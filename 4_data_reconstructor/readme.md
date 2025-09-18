# 数据重构器 (Data Reconstructor)

## 概述

数据重构器是 SQL 盲注分析管道中的关键组件，负责将分散在多次盲注攻击请求中的碎片化信息重新组合成完整的数据记录。该工具通过分析字符级别的比较操作，逆向还原出被攻击者窃取的原始数据。

## 功能特性

- 从盲注攻击的碎片化信息中重构完整数据
- 支持多表、多列、多记录的数据重构
- 实现基于二分查找算法的字符重构
- 输出结构化的 JSON 数据，便于后续分析和报告生成

## 使用方法

### 基本用法

```bash
# 从标准输入读取分析结果，输出重构后的数据
cat analysis_results.jsonl | python default_data_reconstructor.py
```

### 完整管道示例

```bash
# 完整的 SQL 盲注分析管道
cat access.log | \
python 1_web_log_parser.py | \
python 2_param_extractor.py -p query | \
python url_decoder.py | \
python base64_decoder.py | \
python sqlmap_analyzer.py --config config.json | \
python default_data_reconstructor.py > reconstructed_data.json
```

## 输入格式

### 输入数据结构

输入应为 JSON 行格式，每行包含一个分析结果对象：

```json
{
  "request": {
    "payload": "原始载荷",
    "response_size": 1234,
    "status_code": 200,
    "timestamp": "时间戳"
  },
  "analysis": {
    "type": "boolean_injection",
    "database": "database_name",
    "table": "table_name",
    "column": "column_name",
    "position": 1,
    "ascii_value": 97,
    "limit_offset": 0,
    "judge": true,
    "comparison_operator": ">",
    "record_id": 0
  }
}
```

### 必需字段

分析结果必须包含以下字段才能有效重构数据：
- `type`: 注入类型（需包含 "inject" 字符串）
- `database`: 数据库名
- `table`: 表名
- `column`: 列名
- `position`: 字符位置（大于 0）
- `ascii_value`: 比较的 ASCII 值
- `judge`: 比较结果（真/假）
- `comparison_operator`: 比较运算符（如 ">", "<", "!="）
- `record_id`: 记录 ID（通常从 LIMIT 偏移量获取）

## 输出格式

### 输出数据结构

输出为结构化的 JSON 对象，包含以下部分：

```json
{
  "database": "目标数据库名",
  "tables": ["被攻击的表1", "被攻击的表2"],
  "columns": {
    "database.table": ["列1", "列2", "列3"]
  },
  "data": {
    "database.table": {
      "column_name": ["重构的值1", "重构的值2", "重构的值3"]
    }
  }
}
```

### 输出示例

```json
{
  "database": "app_db",
  "tables": ["users", "products"],
  "columns": {
    "app_db.users": ["username", "password", "email"],
    "app_db.products": ["name", "price", "description"]
  },
  "data": {
    "app_db.users": {
      "username": ["admin", "testuser", "john_doe"],
      "password": ["5f4dcc3b5aa765d61d8327deb882cf99", "098f6bcd4621d373cade4e832627b4f6"],
      "email": ["admin@example.com", "test@example.com"]
    },
    "app_db.products": {
      "name": ["Product A", "Product B"],
      "price": ["19.99", "29.99"]
    }
  }
}
```

## 工作原理

### 1. 数据收集与分组

工具首先收集所有分析结果，并按以下层级进行分组：
- 数据库 → 表 → 列 → 记录 ID → 字符位置

### 2. 字符重构算法

对于每个字符位置，工具收集所有相关的比较操作，并使用基于二分查找的算法确定字符的 ASCII 值：

```python
def reconstruct_character(comparisons):
    min_val = 32  # 可打印字符的最小ASCII值（空格）
    max_val = 126  # 可打印字符的最大ASCII值（~）
    
    for comp in sorted_comparisons:
        ascii_val = comp['ascii_value']
        judge = comp['judge']
        operator = comp['comparison_operator']
        
        if operator == '>':
            if judge:  # 条件为真：字符 > ascii_val
                max_val = min(max_val, ascii_val)
            else:      # 条件为假：字符 <= ascii_val
                min_val = max(min_val, ascii_val + 1)
        elif operator == '<':
            if judge:  # 条件为真：字符 < ascii_val
                min_val = max(min_val, ascii_val)
            else:      # 条件为假：字符 >= ascii_val
                max_val = min(max_val, ascii_val - 1)
        # 处理其他运算符...
    
    return min_val if min_val == max_val else None
```

### 3. 字符串拼接

对于每个记录的每个字段，工具：
1. 确定该字段的最大字符位置
2. 按顺序重构每个位置的字符
3. 遇到 ASCII 值为 0 的字符时停止（表示字符串结束）
4. 将所有字符拼接成完整的字符串

### 4. 数据结构化

将重构的数据按数据库、表、列进行组织，便于后续分析和报告生成。

## 处理流程

1. **读取输入**：从标准输入读取 JSON 行格式的分析结果
2. **过滤有效数据**：只处理包含注入标记且具有必要字段的分析结果
3. **数据分组**：按数据库、表、列、记录ID和字符位置对比较操作进行分组
4. **字符重构**：对每个字符位置使用二分查找算法确定字符值
5. **字符串拼接**：将字符按位置顺序拼接成完整字符串
6. **结果组织**：将重构的数据组织成结构化格式
7. **输出结果**：将最终结果以 JSON 格式输出到标准输出

## 注意事项

1. **数据完整性**：重构的数据质量取决于分析结果的完整性和准确性
2. **字符范围**：只处理 ASCII 值在 32-126 之间的可打印字符，遇到值为 0 的字符视为字符串结束
3. **错误处理**：无法解析的输入行会被跳过，错误信息输出到标准错误流
4. **性能考虑**：处理大量数据时可能需要较长时间，建议先过滤无关数据

## 故障排除

如果重构结果不符合预期，请检查：

1. **输入数据格式**：确保输入符合要求的 JSON 行格式
2. **分析结果完整性**：确认分析结果包含所有必要字段
3. **字符编码**：确保所有字符都在可打印 ASCII 范围内
4. **比较操作完整性**：确保有足够的比较操作来唯一确定每个字符

## 示例用例

### 用例 1：重构用户凭据

```bash
# 重构用户表中的用户名和密码
cat sql_injection_analysis.jsonl | \
grep '"table": "users"' | \
python default_data_reconstructor.py > user_credentials.json
```

### 用例 2：分析特定列的数据

```bash
# 只重构密码列的数据
cat sql_injection_analysis.jsonl | \
grep '"column": "password"' | \
python default_data_reconstructor.py > passwords.json
```

数据重构器是 SQL 盲注分析管道中的关键组件，能够将攻击者通过数百次请求获取的碎片化信息重新组合成有意义的完整数据，帮助安全团队快速了解数据泄露的范围和内容。
