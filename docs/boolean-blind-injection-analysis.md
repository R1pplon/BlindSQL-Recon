# 布尔型盲注日志解析经验文档

## 1. 概述

本文档记录了使用 BlindSQL-Recon 工具对 `log_example/bool_access.log` 进行布尔型（Boolean-based）SQL 盲注攻击数据重建的完整过程、遇到的陷阱及解决方案。

## 2. 日志特征分析

### 2.1 日志格式

样例日志采用 Apache Combined Log Format：

```
172.17.0.1 - - [17/Sep/2025:13:37:54 +0800] "GET /sql-test/?username=admin HTTP/1.1" 200 23
```

### 2.2 响应大小与真值判断

攻击者利用响应体大小的差异来判断 SQL 条件是否为真：

| 响应大小 (response_size) | SQL 条件结果 | 含义 |
|-------------------------|------------|------|
| 15 | TRUE | 注入条件成立 |
| 23 | FALSE | 注入条件不成立 |

对应配置文件 `test_boolean_config.json` 中的 `judge_function`：

```json
{
  "judge_function": {
    "type": "size_equal",
    "value": 15
  }
}
```

### 2.3 攻击阶段划分

日志包含 SQLMap 的完整攻击链，约 5134 行：

| 阶段 | 特征 | 示例 payload 关键字 |
|------|------|-------------------|
| 探测 (Detection) | 数据库指纹、函数测试 | `BENCHMARK`, `SLEEP`, `SYSMASTER`, `SYSDUMMY1` |
| 枚举 (Enumeration) | schema/表/列枚举 | `SCHEMATA`, `COUNT(DISTINCT(schema_name))` |
| 提取 (Extraction) | 逐字符二分搜索 | `ORD(MID(...CAST(...LIMIT n,1)...))` |

**重要**：只有"提取"阶段的 payload 包含 `ORD(MID(` 触发模式，才会被分析器捕获。前期探测/枚举的 payload 会被过滤。

## 3. 陷阱与解决方案

### 3.1 陷阱一：参数名错误

**现象**：使用 `-p id` 时 param_extractor 输出为空（`Broken pipe`），分析器无数据可处理。

**原因**：日志中的查询参数是 `username`，而非 `id`。需要根据实际日志确定参数名。

**解决方案**：

```bash
# 先 grep 查看日志中的参数名
grep -oP '\?[^&\s]+' log_example/bool_access.log | sort -u

# 使用正确的参数名
... | 3_param_extractor.py -p username | ...
```

### 3.2 陷阱二：base64_decoder 导致数据丢失（关键！）

**现象**：管道中加入 `base64_decoder` 后分析结果为空，或仅有少量 `admin`/`YWRtaW4=` 的记录通过。

**原因**：`base64_decoder.py` 对非 base64 格式的 payload 会解码失败，返回 `payload: null`，导致后续分析器收到空 payload 而跳过所有注入 payload。布尔型盲注的 payload 是 URL 编码后的原始 SQL 语句，并非 base64 格式。

**解决方案**：布尔型盲注日志解析中**不应包含 base64_decoder**。

```bash
# 错误（base64_decoder 会破坏数据）
... | url_decoder.py | base64_decoder.py | sqlmap_analyzer.py ...

# 正确（仅需 URL 解码）
... | url_decoder.py | sqlmap_analyzer.py ...
```

**适用规则**：

| 日志类型 | 需要 base64_decoder？ | 说明 |
|---------|---------------------|------|
| 布尔型盲注 (bool_access.log) | 不需要 | payload 仅为 URL 编码的 SQL 语句 |
| 时间型盲注 (time_access.log) | 视情况 | 需要检查 payload 是否含 base64 编码层 |

## 4. 正确的完整管道命令

```bash
cat ./log_example/bool_access.log \
  | python3 ./1_log_parser/1_web_log_parser.py \
  | python3 ./1_log_parser/3_param_extractor.py -p username \
  | python3 ./2_payload_decoder/url_decoder.py \
  | python3 ./3_payload_analyzer/sqlmap_analyzer.py \
      --config ./3_payload_analyzer/config/test_boolean_config.json \
  | python3 ./4_data_reconstructor/default_data_reconstructor.py \
  | python3 ./5_report_generator/default_report_generator.py -o txt
```

## 5. 重建结果

### 5.1 数据库结构

攻击者枚举了 INFORMATION_SCHEMA 元数据，导出目标 `test_sql` 数据库的结构：

- **数据库**: INFORMATION_SCHEMA（元数据来源）
- **表**: `test_sql.USERS`（来自 TABLES 枚举，其中 `test_sql` 是目标库）
- **列**: `ID`, `USERNAME`, `PASSWORD`, `EMAIL`

### 5.2 枚举的 Schema 列表

共 11 个 schema：`information_schema`, `blog`, `blog_db`, `blog_test`, `mysql`, `performance_schema`, `qos`, `sky_take_out`, `sys`, `test_sql`, `todolist`

### 5.3 被窃取的用户数据（全部 10 条记录）

| ID | USERNAME | PASSWORD (MD5) | EMAIL |
|----|----------|-----------------|-------|
| 1 | admin | 5d7845ac6ee7cfffafc5fe5f35cf666d | admin@example.com |
| 2 | john_doe | 7c6a180b36896a0a8c02787eeafb0e4c | john@mail.com |
| 3 | jane_smith | 0d107d09f5bbe40cade3de5c71e9e9b7 | jane@work.org |
| 4 | test_user | 179ad45c6ce2cb97cf1029e212046e81 | test@test.test |
| 5 | demo | 6e9bece1914809fb8493146417e722f6 | demo@demo.demo |
| 6 | alice | 4cecaff2b30bbe75ce7322109164cfb5 | alice@wonder.land |
| 7 | bob | 285fbe7245c1d922f146f614ab3864c6 | bob@build.it |
| 8 | charlie | c378985d629e99a4e86213db0cd5e70d | charlie@factory.com |
| 9 | diana | 5300ee96dd08ec22708da7c6fae2bb0d | diana@themyscira.org |
| 10 | peter | 9ff1a119c14898c3fe71ad9d616d6e12 | peter@dailybugle.net |

## 6. 通用调试流程

当解析结果为空时，按以下流程逐步排查：

### 第一阶段：验证日志解析

```bash
# 1. 确认日志格式能被解析
cat access.log | python3 1_web_log_parser.py | head -5

# 2. 确认参数提取正确
cat access.log | python3 1_web_log_parser.py | python3 3_param_extractor.py -p <param> | head -5
```

### 第二阶段：验证解码链路

```bash
# 3. 检查 URL 解码是否正确
... | url_decoder.py | head -5

# 4. 检查 base64 解码是否必要（非必要则跳过）
# 如果输出中出现大量 "payload": null，说明不应使用 base64_decoder
... | url_decoder.py | base64_decoder.py | head -5
```

### 第三阶段：验证分析器

```bash
# 5. 确认 trigger_pattern 与日志中 payload 匹配
grep "ORD(MID" access.log | head -2   # 检查是否有匹配的提取 payload

# 6. 检查分析器输出
... | sqlmap_analyzer.py --config config.json | head -5
```

### 第四阶段：验证重建与报告

```bash
# 7. 检查重建数据
... | default_data_reconstructor.py | python3 -m json.tool | head -50

# 8. 最终报告生成
... | default_report_generator.py -o all
```

## 7. 关键经验总结

1. **参数名必须与日志匹配**：先用 `grep` 确认日志中实际的查询参数名。
2. **base64_decoder 不是通用组件**：仅在 payload 确实经过 Base64 编码时才加入管道，否则会丢失所有非 base64 数据。
3. **trigger_pattern 必须匹配**：分析器通过 `trigger_pattern` 过滤 payload，需确保配置与日志中的提取 payload 格式一致（本例为 `ORD(MID(`）。
4. **judge_function 基于响应大小**：需要通过观察日志中的响应大小分布来确定 TRUE/FALSE 的阈值，配置到 `judge_function` 中。
5. **噪声请求可忽略**：日志中的 `.well-known`、静态资源请求会被 log_parser 正常解析但不会包含注入 payload，通过 param_extractor 和 trigger_pattern 双层过滤即可排除。
6. **重建算法依赖完整对比链**：对于每个字符位置，需要有完整的 `>` `<` `=` 对比操作序列，数据重建器才能通过二分搜索收敛到正确的 ASCII 值。
