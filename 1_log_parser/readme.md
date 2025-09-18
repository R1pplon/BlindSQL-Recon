# Web 日志处理工具集

## 概述

本工具集包含两个独立的 Python 脚本，用于处理和解析 Web 服务器日志。第一个工具解析原始日志文件，第二个工具从解析后的日志中提取特定参数。

## Web 日志解析器 `1_web_log_parser.py`

### 功能

解析通用日志格式(CLF)和组合日志格式的 Web 服务器日志，并将其转换为 JSON 格式的结构化数据。

### 输入格式

- 原始 Web 服务器日志行（CLF 或组合格式）
- 通过标准输入流(stdin)接收数据

### 输出格式

- JSON 行格式的结构化日志数据
- 输出到标准输出流(stdout)

### 支持的日志格式

1. **通用日志格式(CLF)**:

   ```
   remote_host remote_logname remote_user [timestamp] "request_line" status_code response_size
   ```

2. **组合日志格式**:

   ```
   remote_host remote_logname remote_user [timestamp] "request_line" status_code response_size "user_agent"
   ```

### 使用方法

```bash
# 直接解析日志文件
cat access.log | python3 1_web_log_parser.py

# 或使用管道与其他命令结合
cat access.log | grep "GET" | python3 1_web_log_parser.py
```

### 输出示例

```json
{"remote_host": "192.168.1.1", "remote_logname": "-", "remote_user": "-", "timestamp": "18/Sep/2025:10:15:32 +0800", "request_line": "GET /page?param=value HTTP/1.1", "status_code": "200", "response_size": "1234", "user_agent": "Mozilla/5.0..."}
```

### 工作原理

1. 首先尝试匹配组合日志格式的正则表达式
2. 如果失败，则尝试匹配通用日志格式的正则表达式
3. 将匹配的字段映射到结构化 JSON 对象
4. 无法解析的行将被忽略

## 参数提取器 `2_param_extractor.py`

### 功能

从结构化日志数据中提取 URL 查询字符串中的特定参数值。

### 输入格式

- JSON 行格式的日志数据（工具1的输出）
- 通过标准输入流(stdin)接收数据

### 输出格式

- JSON 行格式的提取结果
- 输出到标准输出流(stdout)

### 使用方法

```bash
# 基本用法：提取特定参数
cat parsed_logs.json | python3 2_param_extractor.py -p param_name

# 结合关键词过滤
cat parsed_logs.json | python3 2_param_extractor.py -p user_id -k "GET /user"

# 与工具1串联使用
cat access.log | python3 1_web_log_parser.py | python3 2_param_extractor.py -p session_id
```

### 命令行参数

- `-p/--param`: 必需，指定要提取的参数名
- `-k/--key`: 可选，指定关键词过滤（仅处理包含该关键词的行）
- `-h/--help`: 显示帮助信息

### 输出示例

```json
{"status_code": 200, "response_size": 1234, "timestamp": "18/Sep/2025:10:15:32 +0800", "payload": "extracted_value"}
```

### 工作原理

1. 从输入 JSON 中提取请求行(request_line)
2. 使用正则表达式匹配查询字符串中的指定参数
3. 提取参数值并与其他相关信息（状态码、响应大小、时间戳）一起输出
4. 支持关键词过滤，提高处理效率

## 串联使用示例

```bash
# 完整处理流程：解析日志并提取特定参数
cat access.log | python3 1_web_log_parser.py | python3 2_param_extractor.py -p user_id > extracted_params.json

# 结合过滤条件处理
cat access.log | python3 1_web_log_parser.py | python3 2_param_extractor.py -p search_query -k "GET /search" > search_queries.json
```

## 注意事项

1. 两个工具都使用标准输入输出，便于管道操作和重定向
2. 工具2依赖于工具1的输出格式，不能直接处理原始日志
3. 对于无法解析的日志行，工具1会静默跳过
4. 工具2只会处理包含指定参数且匹配关键词（如果提供）的请求

## 错误处理

- 两个工具都会忽略无法解析的输入行
- 工具2会跳过不包含指定参数或关键词（如果提供）的请求
- 所有有效输出均为标准 JSON 格式，便于后续处理

这两个工具可以独立使用，也可以串联组成完整的数据处理流水线，适用于日志分析、参数提取和监控等场景。
