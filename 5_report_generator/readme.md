# 报告生成器 (Report Generator)

## 概述

报告生成器是 SQL 盲注分析管道的最终组件，负责将重构后的数据转换为多种格式的易读报告。该工具提供控制台输出和多种文件格式的报告，帮助安全团队快速理解和分析 SQL 盲注攻击的结果。

## 功能特性

- 支持多种输出格式：控制台、JSON、CSV 和 TXT
- 自动创建时间戳命名的报告文件
- 结构化展示数据库信息、表结构、列信息和被盗数据
- 为每个被攻击的表生成单独的 CSV 文件
- 自动创建输出目录并组织报告文件

## 使用方法

### 基本用法

```bash
# 从标准输入读取重构数据，生成默认格式（JSON）报告
cat reconstructed_data.json | python default_report_generator.py

# 指定输出格式
cat reconstructed_data.json | python default_report_generator.py -o csv
cat reconstructed_data.json | python default_report_generator.py -o txt
cat reconstructed_data.json | python default_report_generator.py -o all
```

### 完整管道示例

```bash
# 完整的 SQL 盲注分析管道，最终生成报告
cat access.log | \
python 1_web_log_parser.py | \
python 2_param_extractor.py -p query | \
python url_decoder.py | \
python base64_decoder.py | \
python sqlmap_analyzer.py --config config.json | \
python default_data_reconstructor.py | \
python default_report_generator.py -o all
```

## 输入格式

### 输入数据结构

输入应为 JSON 格式的重构数据，包含以下字段：

```json
{
  "database": "目标数据库名",
  "tables": ["被攻击的表1", "被攻击的表2"],
  "columns": {
    "database.table": ["列1", "列2", "列3"]
  },
  "data": {
    "database.table": {
      "column_name": ["值1", "值2", "值3"]
    }
  }
}
```

### 必需字段

- `database`: 目标数据库名称
- `tables`: 被攻击的表列表
- `columns`: 数据库表的列结构信息
- `data`: 重构出的实际数据

## 输出格式

### 输出选项

支持以下输出格式：

1. **控制台输出**：直接在终端显示报告内容
2. **JSON 格式**：结构化的 JSON 报告文件
3. **CSV 格式**：为每个表生成单独的 CSV 文件，并包含元数据文件
4. **TXT 格式**：易读的文本报告文件
5. **所有格式**：同时生成以上所有格式的报告

### 输出文件结构

报告文件保存在 `./result/` 目录下，按时间戳组织：

```
./result/
├── sql_injection_report_20230918_143022.json
├── sql_injection_report_20230918_143022.txt
└── csv_report_20230918_143022/
    ├── metadata.csv
    ├── table1.csv
    └── table2.csv
```

### 报告内容

所有格式的报告都包含以下内容：

1. **数据库信息**：被攻击的目标数据库
2. **被攻击的表**：受影响的数据表列表
3. **列结构**：每个表的列信息
4. **被盗数据**：重构出的实际数据值

## 命令行参数

| 参数 | 缩写 | 可选值 | 默认值 | 描述 |
|------|------|--------|--------|------|
| `--output` | `-o` | `json`, `csv`, `txt`, `all` | `json` | 指定输出报告格式 |

## 工作原理

### 1. 数据处理流程

报告生成器的工作流程如下：

1. **读取输入**：从标准输入读取 JSON 格式的重构数据
2. **解析参数**：解析命令行参数，确定输出格式
3. **创建报告结构**：将输入数据转换为标准报告结构
4. **提取被盗数据**：从输入数据中提取被盗数据并重新组织
5. **生成控制台报告**：在终端输出格式化报告
6. **创建输出目录**：确保 `./result/` 目录存在
7. **生成文件报告**：根据指定格式生成报告文件
8. **输出完成信息**：显示生成的文件路径和信息

### 2. 报告结构创建

```python
def create_report_structure(data):
    return {
        'database': data.get('database', ''),
        'compromised_tables': data.get('tables', []),
        'columns_info': data.get('columns', {}),
        'stolen_data': extract_stolen_data(data),
        'analysis_time': datetime.now().isoformat()
    }
```

### 3. 被盗数据提取

```python
def extract_stolen_data(data):
    stolen_data = {}
    
    for table_key, columns in data.get('data', {}).items():
        table_name = table_key.split('.')[-1]
        if table_name not in stolen_data:
            stolen_data[table_name] = {}
        
        for column, values in columns.items():
            if column not in stolen_data[table_name]:
                stolen_data[table_name][column] = []
            
            stolen_data[table_name][column].extend(values)
    
    return stolen_data
```

### 4. 多格式报告生成

报告生成器支持四种输出格式：

1. **控制台报告**：使用格式化文本在终端显示
2. **JSON 报告**：保存结构化的 JSON 数据
3. **CSV 报告**：
   - 为每个表创建单独的 CSV 文件
   - 创建包含数据库和表信息的元数据文件
   - 处理不同列的数据行数不一致的情况
4. **TXT 报告**：生成易读的文本格式报告

## 使用示例

### 示例 1：生成所有格式报告

```bash
cat reconstructed_data.json | python default_report_generator.py -o all
```

### 示例 2：只生成 CSV 报告用于数据分析

```bash
cat reconstructed_data.json | python default_report_generator.py -o csv
```

### 示例 3：在控制台查看报告并保存 JSON 格式

```bash
cat reconstructed_data.json | python default_report_generator.py -o json
```

## 报告示例

### 控制台输出示例

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

### CSV 报告示例

**metadata.csv**:

```csv
Database,app_db
Analysis Time,2023-09-18T14:30:22.123456

Compromised Tables
users
products
```

**users.csv**:

```csv
username,password,email
admin,5f4dcc3b5aa765d61d8327deb882cf99,admin@example.com
testuser,098f6bcd4621d373cade4e832627b4f6,test@example.com
john_doe,,john@example.com
```

## 注意事项

1. **输出目录**：报告文件会自动保存到 `./result/` 目录，如果目录不存在会自动创建
2. **文件命名**：报告文件使用时间戳命名，避免覆盖之前的报告
3. **数据完整性**：报告内容完全基于输入数据的完整性和准确性
4. **错误处理**：如果输入数据格式不正确，会显示错误信息并退出
5. **CSV 处理**：对于不同列数据行数不一致的情况，会用空字符串填充缺失值

## 故障排除

如果报告生成失败，请检查：

1. **输入数据格式**：确保输入是有效的 JSON 格式
2. **必需字段**：确认输入数据包含所有必需字段
3. **文件权限**：确保有权限创建和写入 `./result/` 目录
4. **磁盘空间**：确保有足够的磁盘空间保存报告文件

报告生成器是 SQL 盲注分析管道的最终环节，能够将技术性的数据分析结果转换为易于理解和分享的多种格式报告，帮助安全团队快速响应和处理数据泄露事件。
