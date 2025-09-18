# SQL 盲注分析管道

## 项目概述

由于盲注攻击无法直接从响应中获得数据，运维人员很难通过流量包直接识别被盗数据。本项目旨在自动化分析和重构盲注攻击泄露的数据。通过解析 Web 服务器日志、解码恶意载荷、分析 SQL 盲注模式，并重构被盗数据，帮助运维人员从间接的盲注攻击中恢复敏感信息。

### 支持的盲注类型

- **布尔盲注**：通过**真/假响应**推断数据内容
- **时间盲注**：通过**响应延迟**推断数据内容

### 支持的日志格式

- **通用日志格式**

  ```log
  %h %l %u %t \"%r\" %>s %b
  ```

- **组合日志格式**

  ```log
  %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
  ```

## 项目架构

```
├─1_log_parser/          # 日志解析模块
├─2_payload_decoder/     # 载荷解码模块
├─3_payload_analyzer/    # 载荷分析模块
│  └─config/             # 分析配置文件
├─4_data_reconstructor/  # 数据重构模块
├─5_report_generator/    # 报告生成模块
└─log_example/           # 示例日志文件
```

## 安装与依赖

### 环境要求

- Python 3.6+

### 获取项目

```bash
git clone https://github.com/R1pplon/BlindSQL-Recon.git
cd BlindSQL-Recon
```

## 快速开始

### 基本使用流程

```bash
cat .\log_example\time_access.log
 | python .\1_log_parser\1_web_log_parser.py
 | python .\1_log_parser\2_param_extractor.py -p query
 | python .\2_payload_decoder\url_decoder.py
 | python .\2_payload_decoder\base64_decoder.py
 | python .\3_payload_analyzer\sqlmap_analyzer.py --config .\3_payload_analyzer\config\time_config.json
 | python .\4_data_reconstructor\default_data_reconstructor.py
 | python .\5_report_generator\default_report_generator.py -o csv
```

**2_param_extractor.py** 需要 `-p` 参数，指定需要提取的参数名称
**3_payload_analyzer.py** 需要 `--config` 参数，指定分析配置文件
**config.json** 配置文件需要手动分析 payload 提取特点

### 各模块功能说明

#### 1. 日志解析器 (`1_web_log_parser.py`)

解析常见的 Web 服务器日志格式（通用日志格式和组合日志格式），将非结构化日志转换为结构化 JSON 数据。

支持格式：

- **通用日志格式**：`remote_host remote_logname remote_user [timestamp] "request_line" status_code response_size`
- **组合日志格式**：添加了 `Referer` 和 `User-Agent` 字段

#### 2. 参数提取器 (`2_param_extractor.py`)

从结构化日志中提取特定参数，过滤出潜在的恶意请求。

使用方法：

```bash
python 2_param_extractor.py -p <parameter_name>
```

#### 3. 载荷解码器 (`url_decoder.py`, `base64_decoder.py`)

对提取的载荷进行多层解码，还原攻击者的原始输入：

- URL 解码：处理 `%20` 等编码字符
- Base64 解码：处理 Base64 编码的载荷

#### 4. SQLMap 盲注分析器 (`sqlmap_analyzer.py`)

核心分析模块，使用可配置规则识别和解析盲注攻击模式。

配置文件示例 (`time_config.json`):

```json
{
  "injection_type": "boolean",
  "trigger_pattern": "ORD(MID(",
  "judge_function": {
    "type": "size_equal",
    "value": 15
  },
  "patterns": {
    "from_pattern": "FROM\\s+([\\w_]+)\\.([\\w_]+)",
    "cast_pattern": "CAST\\(([\\w_]+)\\s+AS",
    "limit_pattern": "LIMIT\\s+(\\d+),1",
    "position_pattern": ",(\\d+),1\\)\\)",
    "comparison_pattern": "\\)\\)\\s*([<>!]=?)\\s*(\\d+)"
  }
}
```

#### 5. 数据重构器 (`default_data_reconstructor.py`)

将分散在多次请求中的碎片化信息拼凑成完整数据，通过模拟二分查找算法重构原始字符。

#### 6. 报告生成器 (`default_report_generator.py`)

生成多种格式的分析报告，包括：

- 控制台输出
- JSON 格式报告
- CSV 格式报告
- 文本格式报告

使用方法：

```bash
python default_report_generator.py -o [json|csv|txt|all]
```

## 配置说明

### 分析器配置

分析器的行为由 JSON 配置文件定义，主要包含以下部分：

- **injection_type**: 盲注类型（boolean/time）
- **trigger_pattern**: 识别盲注载荷的关键模式
- **judge_function**: 定义如何根据HTTP响应判断查询结果
  - size_equal: 响应大小等于特定值
  - size_less: 响应大小小于特定值
  - size_greater: 响应大小大于特定值
  - size_range: 响应大小在特定范围内
- **patterns**: 用于提取攻击元数据的正则表达式模式

### 自定义配置

根据实际应用场景，可以创建自定义配置文件：

1. 分析应用的正常响应特征
2. 确定盲注判断条件
3. 根据攻击模式调整正则表达式

## 输出示例

### 控制台输出

```
============================================================
SQL盲注攻击分析报告
============================================================

[+] 目标数据库: app_db

[+] 被攻击的表:
    - users
    - products

[+] 发现的列结构:
    app_db.users:
      - username
      - password
      - email

[+] 表 users.username 中被盗数据:
    记录 1: admin
    记录 2: testuser
    记录 3: john_doe
```

### CSV 输出

报告生成器会创建包含以下内容的目录：

```
./result/csv_report_20230918_143022/
├── metadata.csv
├── users.csv
└── products.csv
```

## 应用场景

1. **安全事件响应**：在发生数据泄露事件后，快速确定泄露范围和内容
2. **渗透测试验证**：验证盲注攻击的有效性和效率
3. **安全监控**：集成到SIEM系统中，检测正在进行的盲注攻击
4. **取证分析**：为法律程序提供数据泄露的证据
5. **安全研究**：学习SQL盲注攻击原理和防御措施
