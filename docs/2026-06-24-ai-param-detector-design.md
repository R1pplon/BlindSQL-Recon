# AI 参数检测器设计文档

## 概述

在 SQL 盲注重建流水线中，`3_param_extractor.py` 需要手动指定 `-p <参数名>`（如 `-p username`、`-p query`），这是整个管道中唯一需要人工介入的环节。本设计引入 `2_param_detector.py`（AI 参数检测器），通过 LLM 自动识别日志中携带 SQL 注入 payload 的 URL 参数名，实现管道全自动化。

## 架构

```
cat log | 1_web_log_parser.py | 2_param_detector.py | 3_param_extractor.py | ...
                                                              ▲
                                                  优先使用 AI 检测结果
                                                  手动 -p 可覆盖
```

### 模块职责

| 模块 | 变更类型 | 职责 |
|------|----------|------|
| `1_log_parser/2_param_detector.py` | **新增** | 全量读入、随机采样100条、按路径聚合参数、调用 LLM 检测注入参数名、stdout 输出元数据+透传数据 |
| `1_log_parser/3_param_extractor.py` | **修改** | 新增从 stdin 首行读取 AI 检测参数的能力，保留 `-p` 手动覆盖，向后兼容旧用法 |

### 管道传递机制

`2_param_detector.py` 的 stdout 同时承载两类数据：

```
{"__param_detect__": "username"}          ← 元数据行（仅第1行）
{"remote_host": "...", "request_line": "..."}  ← 透传全量 JSON 数据
{"remote_host": "...", "request_line": "..."}
...
```

`3_param_extractor.py` 读取第一行，若为 `__param_detect__` 元数据则提取参数名，后续行正常处理。

### 兼容性矩阵

| 管道首行 | -p 指定 | 行为 |
|----------|---------|------|
| `__param_detect__` | 无 | 使用 AI 检测参数 |
| `__param_detect__` | `-p username` | 使用 `-p`（手动覆盖） |
| 普通数据 | `-p username` | 使用 `-p`（旧用法，向后兼容） |
| 普通数据 | 无 | 报错退出 |

## 数据流

### 2_param_detector.py 内部流程

```
stdin (全量 JSON Lines)
    │
    ▼
┌─────────────────────────────────────┐
│ 1. 全量读入所有行，存入 list         │
│ 2. random.sample(100)               │
│ 3. 逐条提取 request_line            │
│ 4. urlparse → 解析 query string     │
│ 5. 按 path + param_name 聚合分组    │
│ 6. 转为 YAML 格式                   │
│ 7. 拼接 System Prompt + YAML        │
│ 8. POST → DeepSeek API              │
│ 9. 解析响应，提取参数名              │
│ 10. stdout: 元数据行 + 透传全量数据  │
│    stderr: 诊断日志                  │
└─────────────────────────────────────┘
    │
    ▼
stdout: {"__param_detect__": "username"}\n{原始数据行1}\n{原始数据行2}...
stderr: [INFO] 总行数: 5134, 采样: 100, 唯一路径: 3, 检测参数: username
```

### 请求参数解析逻辑

参考 `请求参数解析逻辑参考.md`：

```python
from urllib.parse import urlparse

request_line = entry['request_line']
parts = request_line.split(' ', 2)
uri = parts[1]
parsed = urlparse(uri)

params = {}
if parsed.query:
    for pair in parsed.query.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            params[key] = value
```

### 采样数据聚合（方案 B）

按 URL 路径 + 参数名聚合，降低 token 消耗，增强 LLM 可读性：

```yaml
sampled_entries:
  - path: /sql-test/
    params:
      username:
        - admin%27%20AND%20ORD%28MID%28...
        - admin
        - 1
        - admin%27%20AND%20ORD%28MID%28...
  - path: /.well-known/appspecific/com.chrome.devtools.json
    params: {}
  - path: /search.php
    params:
      query:
        - KSBBTkQgNDcyM...
        - normal_term
        - KSBBTkQg...
```

### 采样策略

- 从全量数据中 `random.sample(n=100)`
- 若总数据量 < 100，全量使用
- 确保采样覆盖不同 URL 路径，以便 LLM 做对比判断
- 同一路径下若参数值种类过多（>10），截断保留前10+省略提示

## LLM 集成

### API 配置

参考 `LLM api请求.md`，使用 OpenAI SDK 兼容格式访问 DeepSeek：

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com"
)

response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=[...],
    stream=False,
    reasoning_effort="high",
    extra_body={"thinking": {"type": "enabled"}}
)
```

### System Prompt

```
你是SQL注入日志分析专家。分析以下100条随机采样的HTTP请求日志（YAML格式，
按URL路径聚合了参数及其采样值）。

任务：
1. 识别哪个 URL 参数携带了 SQL 盲注 payload
2. SQL盲注payload特征：ORD、MID、SLEEP、IF、SELECT、CAST、LIMIT、
   大量URL编码字符（%27、%28、%29、%20等）
3. 忽略无参数的请求（params: {}）
4. 确认一个最有可能的注入点参数名称
5. 仅返回该参数名称，不要返回任何其他内容
6. 如果无法确定，返回 unknown
7. 返回格式：用尖括号包裹参数名，仅返回 <参数名>，不返回任何额外内容
    正确示例：
        <username>
        <query>
        <unknown>
```

### 输出处理

```python
raw_output = response.choices[0].message.content.strip()

# 尖括号格式提取
match = re.search(r'<([\w-]+)>', raw_output)
if match:
    param_name = match.group(1).strip()
    if param_name.lower() == "unknown":
        print("[ERROR] AI未能识别注入参数", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] 检测到注入参数: {param_name}", file=sys.stderr)
else:
    # 格式不匹配，触发重试
    print(f"[WARN] AI返回格式不正确: {raw_output[:100]}...", file=sys.stderr)
```

## 3_param_extractor.py 修改点

```python
# 新增：检测首行是否为 AI 元数据
first_line = sys.stdin.readline()
param_from_ai = None
try:
    meta = json.loads(first_line)
    if "__param_detect__" in meta:
        param_from_ai = meta["__param_detect__"]
except json.JSONDecodeError:
    pass

# 参数优先级：-p 明确指定 > AI 检测 > 报错
if args.param:
    key_param = args.param  # 手动指定，最高优先
elif param_from_ai:
    key_param = param_from_ai  # AI 自动检测
else:
    print("Error: 需要 -p 参数指定提取的参数名称", file=sys.stderr)
    sys.exit(1)

# 如果第一行是元数据行，从下一行开始处理数据
# 如果第一行是普通数据，正常处理
```

## 依赖变更

| 依赖 | 变更 |
|------|------|
| `openai` | **新增**（DeepSeek API 兼容） |
| `pyyaml` | 已存在，继续使用 |
| `urllib.parse` | 标准库，无需额外安装 |

安装命令：`pip install openai pyyaml`

## 使用方式

### 新旧对比

```bash
# 旧用法（手动指定参数名）
cat bool_access.log | 1_web_log_parser.py | 3_param_extractor.py -p username | url_decoder.py | ...

# 新用法（AI 自动检测参数名）
cat bool_access.log | 1_web_log_parser.py | 2_param_detector.py | 3_param_extractor.py | url_decoder.py | ...

# 新用法 + 手动覆盖（AI检测不准时）
cat bool_access.log | 1_web_log_parser.py | 2_param_detector.py | 3_param_extractor.py -p id | ...
```

### 环境变量

```bash
export DEEPSEEK_API_KEY="sk-xxxxxxxxxxxxxxxx"
```

## 错误处理

| 场景 | 行为 |
|------|------|
| DEEPSEEK_API_KEY 未设置 | stderr 提示，exit(1) |
| API 请求超时/网络错误 | stderr 输出错误信息，exit(1) |
| LLM 返回 "unknown" | stderr 提示无法识别，exit(1) |
| 采样数据为空 | stderr 提示无有效日志行，exit(1) |
| API 返回格式异常 | stderr 输出原始响应，exit(1) |
| 总数据量 < 100 | 全量使用，正常采样 |

## 测试验证

### 测试用例

1. **布尔盲注日志** (`bool_access.log`)：预期输出 `username`
2. **时间盲注日志** (`time_access.log`)：预期输出 `query`
3. **无注入日志**：预期输出 `unknown` → exit(1)
4. **空日志**：预期 exit(1)
5. **双参数日志**（正常参数 + 注入参数混合）：预期准确识别注入参数

### 验证管道

```bash
# 布尔盲注完整管道验证
cat log_example/bool_access.log | \
  python 1_log_parser/1_web_log_parser.py | \
  python 1_log_parser/2_param_detector.py | \
  python 1_log_parser/3_param_extractor.py | \
  python 2_payload_decoder/url_decoder.py | \
  python 3_payload_analyzer/sqlmap_analyzer.py --config 3_payload_analyzer/config/test_boolean_config.yaml | \
  python 4_data_reconstructor/default_data_reconstructor.py | \
  python 5_report_generator/default_report_generator.py -o txt
```

预期结果：与手动 `-p username` 一致，完整重建 10 条用户数据。
