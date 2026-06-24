# AI 配置生成器设计文档

## 概述

`sqlmap_analyzer.py` 需要 `--config <yaml>` 手动编写 YAML 配置文件，该文件定义了盲注类型、触发模式、判断函数和5组正则表达式。配置编写依赖对 SQLMap payload 格式的深入理解，门槛高且易出错。

本设计引入 `ai_config_generator.py`（AI 配置生成器），核心思路是**特征提取驱动**：先在本地对 payload 进行统计分析（响应大小聚类、结构去重、关键词频率），将原始数据压缩为结构化特征摘要，再交由 LLM 根据摘要生成 YAML 配置。LLM 不再面对海量原始 payload，而是接收已提炼的决策依据。

**核心洞察**：盲注攻击基于二分查找，正确的配置能使 `default_data_reconstructor.py` 收敛到合法 ASCII 字符（32-126），错误的配置导致乱码。这一确定性特性可用于**闭环校验**——自动验证 AI 生成的配置是否正确。

参考指导文档：`payload_analyzer修改参考指导.md`。

## 三阶段架构

来自参考指导文档的核心理念：**抽象 → 转换 → 验证**。

```
ai_config_generator.py
├── Phase 1: 特征提取 (extract_features) ← 核心差异化
│   ├── 响应大小聚类：统计所有 response_size，识别分布模式（离散双峰/连续双峰）
│   │   └── 直接推断 judge_function 类型和候选阈值 → suggested_judge
│   ├── 注入类型推断：关键词扫描 ORD/MID vs SLEEP/IF → injection_hint
│   ├── 负载结构去重：按 SQL 结构相似度分组，剔除重复结构
│   └── 多样化采样：每类结构保留 1-2 条代表，压缩到 ≤ 30 条送 LLM
├── Phase 2: 语义转换 (generate_config + call_llm)
│   ├── 构造结构化 Prompt（含特征摘要 + 采样数据 + YAML Schema 约束）
│   ├── 调用 DeepSeek API（复用 2_param_detector.py 的 API 模式）
│   └── 支持重试时追加错误反馈到 Prompt
└── Phase 3: 闭环校验 (validate_config)
    ├── Level 1: YAML 语法测试（yaml.safe_load + 结构完整性）
    ├── Level 2: 正则编译测试（re.compile 逐一验证 5 组 pattern）
    ├── Level 3: trigger_pattern 匹配率测试（匹配率需 > 50%）
    ├── Level 4: 提取完备性测试（database/table/column 非空）
    └── Level 5: ASCII 有效性测试（ascii_value 落在 32-126）
```

## 管道位置

```
1_web_log_parser.py  →  2_param_detector.py  →  3_param_extractor.py
→  url_decoder.py  →  [base64_decoder.py]  →  ai_config_generator.py
→  sqlmap_analyzer.py --config auto  →  default_data_reconstructor.py
→  default_report_generator.py
```

**选择理由**：`ai_config_generator.py` 需要看到解码后的 payload 和 `response_size`，因此放在 `url_decoder.py`（和可选的 `base64_decoder.py`）之后、`sqlmap_analyzer.py` 之前。

## 模块职责

| 模块 | 变更类型 | 职责 |
|------|----------|------|
| `3_payload_analyzer/ai_config_generator.py` | **新增** | 特征提取、LLM 生成配置、闭环校验、stdout 输出元数据+透传数据 |
| `3_payload_analyzer/sqlmap_analyzer.py` | **修改** | 新增 `--config auto` 模式，从 stdin 首行读取 AI 配置路径 |

## 管道传递机制

沿用 `2_param_detector.py → 3_param_extractor.py` 的元数据模式：

```
{"__ai_config__": "3_payload_analyzer/config/ai_generated_20260624_143022.yaml"}   ← 元数据行（仅第1行）
{"response_size": 15, "payload": "admin' AND ORD(MID(...))>64 ..."}  ← 透传全量数据
{"response_size": 23, "payload": "admin' AND ORD(MID(...))>96 ..."}
...
```

`sqlmap_analyzer.py` 在 `--config auto` 模式下读取首行获取配置文件路径，后续行正常处理。

### 兼容性矩阵

| 管道首行 | --config 值 | 行为 |
|----------|-------------|------|
| `__ai_config__` | `auto` | 使用 AI 生成配置 |
| 无元数据 | `auto` | 报错退出 |
| 任意 | `<path>` | 使用指定 YAML 文件（原行为，向后兼容） |

## 数据流详解

### 输入（stdin 每行）

从上游 `url_decoder.py` / `base64_decoder.py` 流入的 JSON-per-line：

```json
{"response_size": 15, "payload": "admin' AND ORD(MID((SELECT IFNULL(CAST(schema_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1),1,1))>112 AND 'uOAb'='uOAb"}
```

关键字段：
- **`payload`**（str）：已解码的 SQL 注入 payload
- **`response_size`**（int）：HTTP 响应大小，用于 judge_function 阈值判定

### 特征摘要（内部阶段间传递）

Phase 1 输出的结构化 dict（示例：419 条布尔盲注记录）：

```python
{
    "total_records": 419,                 # stdin 全量行数
    "injection_hint": "boolean",          # ORD/MID → boolean; SLEEP/IF → time
    "size_stats": {
        "unique_values": [15, 23],
        "distribution": {15: 211, 23: 208},
        "suggested_judge": {
            "type": "size_equal",
            "value": 15,
            "reason": "两个离散值，15 是基线 FALSE 页面，23 是 TRUE 结果页面"
        }
    },
    "keyword_top": ["ORD", "MID", "SELECT", "IFNULL", "CAST", "FROM", "LIMIT"],
    "samples": [
        {"payload": "...", "response_size": 15},
        {"payload": "...", "response_size": 23},
        # ... 最多 30 条
    ]
}
```

### 输出（AI 生成的 YAML）

完全符合 `analyzer_config.yaml` 规范：

```yaml
injection_type: boolean
trigger_pattern: ORD(MID(
judge_function:
  type: size_equal
  value: 15
patterns:
  from_pattern: "FROM\\s+([\\w_]+)\\.([\\w_]+)"
  cast_pattern: "CAST\\(([\\w_]+)\\s+AS"
  limit_pattern: "LIMIT\\s+(\\d+),1"
  position_pattern: ",(\\d+),1\\)\\)"
  comparison_pattern: "\\)\\)\\s*([<>!]=?)\\s*(\\d+)"
```

闭环校验通过后，YAML 保存到 `3_payload_analyzer/config/ai_generated_<timestamp>.yaml`，与手写配置文件同目录，便于复用和对比。

## 配置字段检测策略

### 1. `injection_type` — 难度：低

纯字符串匹配判断：

- 样本 payload 中大量出现 `ORD` + `MID` → `boolean`
- 样本 payload 中大量出现 `SLEEP` + `IF` → `time`

在 Phase 1 特征提取阶段即可完成本地推断，`injection_hint` 直接提示给 LLM。

### 2. `trigger_pattern` — 难度：中

`trigger_pattern` 在 `sqlmap_analyzer.py:50` 以 `in` 运算符（纯子串匹配，非正则）作用于 `payload.upper()`：

```python
if payload and self.config.trigger_pattern in payload.upper():
```

要求：
- 必须在**所有**注入 payload 中出现
- 必须是**稳定唯一的特征子串**（不影响正常的非注入请求）
- 通常为 SQL 函数头：`ORD(MID(` 或 `SLEEP(1-(IF(`

LLM 从关键词频率分析和样本 payload 的共同前缀推断。

### 3. `judge_function` — 难度：高（核心挑战）

判断函数类型和阈值的选择依赖于 `response_size` 的统计分布：

**布尔盲注**（双峰离散分布）：
- FALSE 页面：固定的基线响应大小（如 15 bytes）
- TRUE 页面：不同的结果响应大小（如 23 bytes）
- 推荐配置：`{type: size_equal, value: 15}`（跟踪 FALSE/基线页面）

**时间盲注**（双峰连续分布）：
- TRUE（IF 条件满足 → SLEEP(0) → 无延迟）：较小的快速响应
- FALSE（IF 条件不满足 → SLEEP(1) → 1秒延迟）：较大的响应
- 推荐配置：`{type: size_less, value: 1406}`（跟踪 TRUE/快速响应）

**策略**：Phase 1 特征提取已在本地计算 `size_stats.suggested_judge`，直接写入 Prompt 作为强提示。LLM 主要负责确认，而非从头推理。

### 4. `patterns` — 难度：中高

5 组正则表达式，遵循 SQLMap 标准 payload 格式。关键难点是 YAML 双反斜杠转义。

**SQLMap 标准 payload 结构**：
```
admin' AND ORD(MID((SELECT IFNULL(CAST(column_name AS NCHAR),0x20)
                     FROM database_name.table_name
                     LIMIT offset,1), char_position,1))>ascii_value AND '1'='1
```

| pattern | 作用 | Python 正则（无转义） | YAML 写法（双反斜杠） |
|---------|------|----------------------|----------------------|
| `from_pattern` | 提取 database.table | `FROM\s+([\w_]+)\.([\w_]+)` | `FROM\\s+([\\w_]+)\\.([\\w_]+)` |
| `cast_pattern` | 提取 column | `CAST\(([\w_]+)\s+AS` | `CAST\\(([\\w_]+)\\s+AS` |
| `limit_pattern` | 提取 LIMIT offset | `LIMIT\s+(\d+),1` | `LIMIT\\s+(\\d+),1` |
| `position_pattern` | 提取字符位置 | `,(\d+),1\)\)` | `,(\\d+),1\\)\\)` |
| `comparison_pattern` | 提取运算符和ASCII值 | `\)\)\s*([<>!]=?)\s*(\d+)` | `\\)\\)\\s*([<>!]=?)\\s*(\\d+)` |

**策略**：Prompt 中直接给出正确的标准 YAML 写法作为参考模板。LLM 仅需验证：这些正则能否匹配当前样本？若能，直接复制；若 payload 格式有变，微调正则。

## Prompt 设计

### SYSTEM_PROMPT

```
你是 SQL 盲注分析配置专家。分析提供的 HTTP 请求样本（含 payload 和 response_size），
生成一个完整的 YAML 配置文件，用于 BlindSQL-Recon 的 sqlmap_analyzer.py。

必须返回的 YAML 字段：
  injection_type: "boolean" 或 "time"
  trigger_pattern: payload 中唯一稳定的特征子串（纯文本，非正则）
  judge_function: {type: size_equal|size_less|size_greater|size_range, value: <int>}
  patterns:
    from_pattern, cast_pattern, limit_pattern, position_pattern, comparison_pattern

判断规则：
1. injection_type: 含 ORD/MID → "boolean"；含 SLEEP/IF → "time"
2. trigger_pattern: 所有注入 payload 都包含的特征子串，通常为 SQL 函数头
3. judge_function: 参考特征摘要中的 size_stats.suggested_judge
4. patterns: 正则表达式（注意 YAML 双反斜杠转义：每个 \ 写为 \\）

参考模板（标准 SQLMap 格式，直接可用）：
  from_pattern: "FROM\\s+([\\w_]+)\\.([\\w_]+)"
  cast_pattern: "CAST\\(([\\w_]+)\\s+AS"
  limit_pattern: "LIMIT\\s+(\\d+),1"
  position_pattern: ",(\\d+),1\\)\\)"
  comparison_pattern: "\\)\\)\\s*([<>!]=?)\\s*(\\d+)"

仅返回 YAML 内容，不返回任何额外文字或解释。
```

### User Content（YAML 格式）

LLM 收到的数据包含两部分：统计摘要 + 采样 payload。

```yaml
analysis_goal: 为 BlindSQL-Recon 生成盲注分析器 YAML 配置
feature_summary:
  total_records: 419
  injection_type_hint: boolean
  response_size_stats:
    unique_values: [15, 23]
    distribution: {15: 100, 23: 100}
    suggested_judge:
      type: size_equal
      value: 15
      reason: "两个离散值，15=基线FALSE页面，23=TRUE结果页面"
  keyword_top:
    - ORD
    - MID
    - SELECT
    - IFNULL
    - CAST
    - FROM
    - LIMIT
reference_patterns:
  from_pattern: "FROM\\s+([\\w_]+)\\.([\\w_]+)"
  cast_pattern: "CAST\\(([\\w_]+)\\s+AS"
  limit_pattern: "LIMIT\\s+(\\d+),1"
  position_pattern: ",(\\d+),1\\)\\)"
  comparison_pattern: "\\)\\)\\s*([<>!]=?)\\s*(\\d+)"
sample_payloads:
  - payload: "admin' AND ORD(MID((SELECT IFNULL(CAST(schema_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1),1,1))>64 AND '1'='1"
    response_size: 23
  - payload: "admin' AND ORD(MID((SELECT IFNULL(CAST(schema_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1),1,1))>112 AND '1'='1"
    response_size: 15
  # ... 最多 30 条多样化样本
```

### 重试时的错误反馈

若 Phase 3 验证失败，错误信息追加到 User Content：

```yaml
errors_from_previous_attempt:
  - "trigger_pattern 匹配率过低: 15% (<50%)，请选择更通用的特征子串"
  - "正则 'cast_pattern' 编译失败: bad escape (position 12)"
```

## 闭环校验机制

### 校验层级

```
Level 1: YAML 语法
  └─ yaml.safe_load() 不抛异常
  └─ 四大必需字段 (injection_type, trigger_pattern, judge_function, patterns) 全部存在
  └─ 5 个子 patterns (from/cast/limit/position/comparison) 全部存在
  └─ create_judge_function() 不抛异常

Level 2: 正则编译
  └─ re.compile(pattern) 对 5 组 pattern 各执行一次，不抛 re.error

Level 3: trigger_pattern 匹配率
  └─ 在采样 payload 中逐一测试 trigger_pattern in payload.upper()
  └─ 匹配率 ≥ 50%，否则判定 pattern 选择不当

Level 4: 提取完备性
  └─ 至少一条采样 payload 能同时被 from_pattern 和 cast_pattern 匹配
  └─ 确保 database/table/column 非空

Level 5: ASCII 有效性
  └─ comparison_pattern 从采样 payload 中提取 ascii_value
  └─ 一半以上的值落在 [32, 126] 区间
  └─ 若大量越界 → comparison_pattern 捕获了错误位置
```

### 重试流程

```
generate_config(feature_summary)
  ├─ for attempt in 1..3:
  │     ├─ yaml_str = call_llm(system_prompt, user_content + errors)
  │     ├─ valid, errors = validate_config(yaml_str, samples)
  │     ├─ if valid: return yaml_str
  │     └─ else: 错误追加到 user_content，下一轮重试
  └─ 三次均失败 → 输出警告，使用降级策略
```

### 降级策略

三次重试全部失败时，不再中断管道：
1. 输出 `analyzer_config.yaml` 模板（空值占位）作为降级配置
2. 通过 stderr 输出清晰错误信息，提示用户手动修改 `trigger_pattern` 和 `patterns`
3. 管道继续运行，可能产生未知结果（`type: unknown`），但不阻塞后续步骤

## API 复用

完全复用 `2_param_detector.py` 的 API 调用模式：

```python
from openai import OpenAI

def load_dotenv(dotenv_path=None):
    """从 2_param_detector.py 原样复制"""
    ...

def call_llm(system_prompt: str, user_content: str, max_retries: int = 3) -> str:
    load_dotenv()
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model="deepseek-v4-flash",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                stream=False,
                reasoning_effort="high",
                extra_body={"thinking": {"type": "enabled"}}
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            if attempt < max_retries:
                print(f"[WARN] API请求失败 (尝试{attempt}/{max_retries}): {e}", file=sys.stderr)
                continue
            print(f"[ERROR] API请求失败: {e}", file=sys.stderr)
            sys.exit(1)
```

## 命令行接口

```bash
# 基本用法
python ai_config_generator.py

# 在管道中使用
cat decoded_payloads.jsonl | python ai_config_generator.py | python sqlmap_analyzer.py --config auto
```

脚本全量读入 stdin 所有行进行特征提取，无采样参数。LLM 实际收到的样本由结构去重和多样化选择决定，通常 ≤ 30 条。

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| LLM 生成的正则转义错误（`\s` vs `\\s`） | 正则编译失败，analysis 全部为 `unknown` | Prompt 提供正确 YAML 模板；Level 2 正则编译测试捕获 |
| LLM 误判 judge_function 阈值 | 二分重构全部失败，输出乱码 | 本地统计 `size_stats.suggested_judge` 直接提示 LLM |
| 非标准 SQLMap payload 格式 | 现有正则模板不匹配 | 匹配率测试（Level 3）检测；错误反馈推动 LLM 微调正则 |
| API 不可用 / 网络超时 | 生成中断 | 降级策略：输出模板配置，管道继续运行；API 调用支持 3 次重试 |
| 采样不足（总输入 < 50 条） | 统计特征不准确 | Phase 1 检测样本量，通过 stderr 警告；仍尝试生成 |
| 特征提取阶段响应大小分布不明确 | judge_function 推断错误 | 本地 clustering 提供 suggested_judge 作为强提示，LLM 只需确认 |

## 测试计划

### 布尔盲注管道路径测试

```bash
cat log_example/bool_access.log | \
  python 1_log_parser/1_web_log_parser.py | \
  python 1_log_parser/2_param_detector.py | \
  python 1_log_parser/3_param_extractor.py | \
  python 2_payload_decoder/url_decoder.py | \
  python 3_payload_analyzer/ai_config_generator.py | \
  python 3_payload_analyzer/sqlmap_analyzer.py --config auto | \
  python 4_data_reconstructor/default_data_reconstructor.py | \
  python 5_report_generator/default_report_generator.py -o txt
```

预期：AI 生成配置等价于 `test_boolean_config.yaml`，重建 10 条用户记录。

### 时间盲注管道路径测试

```bash
cat log_example/time_access.log | \
  python 1_log_parser/1_web_log_parser.py | \
  python 1_log_parser/2_param_detector.py | \
  python 1_log_parser/3_param_extractor.py | \
  python 2_payload_decoder/url_decoder.py | \
  python 2_payload_decoder/base64_decoder.py | \
  python 3_payload_analyzer/ai_config_generator.py | \
  python 3_payload_analyzer/sqlmap_analyzer.py --config auto | \
  python 4_data_reconstructor/default_data_reconstructor.py | \
  python 5_report_generator/default_report_generator.py -o csv
```

预期：AI 生成配置等价于 `test_time_config.yaml`，重建 20 条司机记录。

### 向后兼容测试

```bash
# 手动指定配置（原用法）必须正常工作
cat log_example/bool_access.log | \
  python 1_log_parser/1_web_log_parser.py | \
  python 1_log_parser/3_param_extractor.py -p username | \
  python 2_payload_decoder/url_decoder.py | \
  python 3_payload_analyzer/sqlmap_analyzer.py --config 3_payload_analyzer/config/test_boolean_config.yaml | \
  python 4_data_reconstructor/default_data_reconstructor.py | \
  python 5_report_generator/default_report_generator.py -o txt
```

预期：与 AI 自动模式结果完全一致。

## 实施清单

- [ ] 新增 `3_payload_analyzer/ai_config_generator.py`
  - [ ] `load_dotenv()` 函数（从 `2_param_detector.py` 复制）
  - [ ] `extract_features()` — **核心**：Phase 1 特征提取（响应聚类、结构去重、关键词统计）
  - [ ] `build_prompt()` — Phase 2 Prompt 构造（特征摘要 → YAML 输入）
  - [ ] `call_llm()` — DeepSeek API 调用
  - [ ] `validate_config()` — Phase 3 闭环校验
  - [ ] `generate_and_validate()` — 带重试的生成循环
  - [ ] `main()` — stdin/stdout 管道集成（校验通过后 YAML 保存到 `3_payload_analyzer/config/ai_generated_<ts>.yaml`）

- [ ] 修改 `3_payload_analyzer/sqlmap_analyzer.py`
  - [ ] 新增 `import os`
  - [ ] `--config auto` 模式：读 stdin 首行 `__ai_config__` 元数据
  - [ ] 保持原 `--config <path>` 行为

- [ ] 更新文档
  - [ ] `AGENTS.md` — ai_config_generator 入口、`--config auto` 用法、闭环校验
  - [ ] `readme.md` — 架构树、快速开始示例
  - [ ] `3_payload_analyzer/readme.md` — AI 配置生成器章节

- [ ] 管道测试
  - [ ] 布尔盲注完整管线（AI 自动配置）
  - [ ] 时间盲注完整管线（AI 自动配置）
  - [ ] 向后兼容测试（手动指定配置）
