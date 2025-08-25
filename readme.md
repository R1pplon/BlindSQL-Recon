# SQL 盲注分析管道

## 项目简介

在 SQL 注入攻击中，攻击者通常通过直接查询数据库泄露敏感数据。但在 SQL 盲注（Blind SQL Injection）攻击中，攻击者无法直接从响应中获取数据，而是通过推测数据库内容来逐步泄露信息。盲注通常有两种形式：

* **时间盲注**：通过观察数据库响应的延迟时间推测查询结果。
* **布尔盲注**：通过真假判断的查询，观察不同响应结果来推测数据库内容。

由于盲注攻击无法直接从响应中获得数据，运维人员很难通过流量包直接识别被盗数据。本项目旨在自动化分析和重构盲注攻击泄露的数据。通过解析 Web 服务器日志、解码恶意载荷、分析 SQL 盲注模式，并重构被盗数据，帮助运维人员从间接的盲注攻击中恢复敏感信息。

---

## 特性

**具体问题具体分析**

* **可自定义工作流**：管道由五个阶段组成，每个阶段有一个独立的脚本。用户可以轻松地替换或修改这些阶段以适应不同的需求：

  * **日志解析器**：默认解析 Apache 日志，但可以将其替换为 Nginx 日志解析器等自定义解析器。
  * **载荷解码器**：可以自定义解码逻辑以处理不同的编码格式。
  * **载荷分析器**：修改分析逻辑，检测不同类型的 SQL 注入，例如布尔盲注分析。
  * **数据重构器**：根据分析结果重构被盗数据。
  * **报告生成器**：生成最终报告，并在控制台打印和保存为 JSON 文件。

* **模块化设计**：每个阶段实现为独立的 Python 脚本，允许用户修改或扩展某一部分，而不影响整个工作流。

* **可定制的注入检测**：当前管道支持基于时间的盲注检测，布尔盲注分析功能正在开发中，使工具能够适应更多种类的 SQL 注入攻击。

---

## 工作流概述

1. **日志解析 (1_Apache_log_parser.py)**
   解析 Web 服务器日志（默认 Apache）以识别与 SQL 注入工具（如 SQLMap）相关的请求。提取请求参数，如 URL、响应大小和时间戳。

2. **载荷解码 (2_payload_decoder.py)**
   解码可能的恶意载荷，这些载荷可能是 URL 编码或 Base64 编码。用户可以根据需求自定义解码逻辑以处理其他编码方法。

3. **载荷分析 (3_payload_analyzer.py)**
   分析解码后的载荷，检测 SQL 注入模式（例如基于时间的盲注）。用户可以修改分析逻辑，检测其他类型的 SQL 注入，如布尔盲注。

4. **数据重构 (4_data_reconstructor.py)**
   根据分析结果重构被盗数据，解码通过 SQL 注入攻击提取的数据。

5. **报告生成 (5_report_generator.py)**
   生成最终报告，总结攻击详情，包括目标数据库、表、列和被盗数据。报告会打印到控制台，并保存为 JSON 文件。

---

## 自定义与扩展

### 自定义工作流

要修改或替换某些步骤，只需编辑或替换相应的 Python 脚本。例如：

* 将 `Apache_log_parser.py` 替换为 `Nginx_log_parser.py` 来解析 Nginx 日志。
* 修改 `payload_decoder.py` 中的解码逻辑，以处理不同的编码方法。
* 更新 `payload_analyzer.py`，以实现更多功能，比如布尔盲注。

### 1. 自定义日志解析器

默认的日志解析器用于解析 Apache 日志。如果需要解析 Nginx 等其他 Web 服务器的日志，可以将 `1_Apache_log_parser.py` 替换为自定义的日志解析脚本（例如 `1_Nginx_log_parser.py`）。确保新的解析器输出的数据格式与其他脚本兼容（JSON 格式）。

### 2. 自定义载荷解码逻辑

默认的 `2_payload_decoder.py` 支持 URL 编码和 Base64 编码的解码。如果遇到使用其他编码方法的载荷，用户可以修改 `decode_payload` 函数，添加其他解码步骤（例如 Hex 编码、Unicode 解码等）。

### 3. 自定义载荷分析

当前版本的 `3_payload_analyzer.py` 支持基于时间的盲注分析。未来版本将扩展到布尔盲注分析。用户可以修改正则表达式和检测逻辑，以适应不同的攻击模式。

### 4. 未来更新

* **更多注入参数处理**：该功能正在开发中，未来将支持对 POST 请求和 COOKIE 等其他注入参数的处理。
* **布尔盲注检测**：该功能正在开发中，预计将支持检测布尔盲注 SQL 注入攻击。
* **更多日志解析器**：将支持更多 Web 服务器的日志解析器（例如 Nginx），以实现更广泛的兼容性。
* **扩展解码逻辑**：将提供更多自定义选项，处理更多编码方法。

---

## 安装与使用

### 环境要求

Python 3.x

### 运行管道

1. 克隆或下载包含管道脚本的仓库。
2. 使用以下命令在命令行中运行管道：

```bash
python3 ./1_log_parser/Apache_log_parser.py -f /path/to/logfile -p key_param_value | \
  python3 ./2_payload_decoder/url_decoder.py | \
  python3 ./2_payload_decoder/base64_decoder.py | \
  python3 ./3_payload_analyzer/sqlmap_time_blind_analyzer.py | \
  python3 ./4_data_reconstructor/default_data_reconstructor.py | \
  python3 ./5_report_generator/default_report_generator.py
```

* **参数**：

  * `-f` 或 `--file`：Web 服务器日志文件的路径。
  * `-p` 或 `--param`：日志分析时使用的关键参数（被注入的参数）。
  * 管道会通过标准输入（stdin）将数据从一个脚本传递到下一个脚本。


或者，使用预设的脚本文件 `analyze.sh`（Linux/macOS）或 `analyze.bat`（Windows）来简化运行流程：

```bash
# 对于 Linux/macOS
sh analyze.sh /path/to/logfile key_param

# 对于 Windows
./analyze.bat /path/to/logfile key_param
```

### 示例用例

使用 `log_example/access.log` 运行示例：

```bash
./analyze.bat ./log_example/access.log query
```

---

## 贡献

欢迎贡献！如果您希望添加新功能或修改现有功能，请 fork 仓库并提交 pull 请求。确保任何新脚本或功能与现有工作流保持兼容。
