# SQLMap盲注分析器 (SQLMap Blind Analyzer)

## 概述

SQLMap盲注分析器是一个专门用于分析SQLMap工具生成的盲注payload的Python工具。它支持布尔盲注和时间盲注两种类型的分析，能够从payload中提取关键信息，如数据库名、表名、列名、字符位置和比较值等。

## 功能特性

- 支持布尔盲注和时间盲注分析
- 可配置的触发模式和判断逻辑
- 从payload中提取结构化信息
- JSON行格式输入输出，易于集成到数据处理管道
- 支持外部配置文件，灵活适配不同场景

## 使用方法

### 基本用法

```bash
# 从标准输入读取数据，处理后将结果输出到标准输出
cat input.jsonl | python sqlmap_analyzer.py --config config.json
```

### 输入格式

输入应为JSON行格式，每行包含一个请求对象，至少包含`payload`和`response_size`字段：

```json
{"payload": "example.com/page?id=1' AND ORD(MID(...))>0 --", "response_size": 15}
```

### 输出格式

输出为JSON行格式，包含原始请求和分析结果：

```json
{
  "request": {"payload": "...", "response_size": 15},
  "analysis": {
    "type": "boolean_injection",
    "database": "test_db",
    "table": "users",
    "column": "password",
    "position": 1,
    "ascii_value": 97,
    "limit_offset": 0,
    "judge": true,
    "comparison_operator": ">",
    "record_id": 0
  }
}
```

## 配置文件详解

配置文件采用JSON格式，用于定义分析器的行为和识别模式。以下是配置文件中各字段的详细说明：

### 1. injection_type
- **类型**: 字符串
- **说明**: 指定注入类型，用于标识分析结果中的类型字段
- **示例**: `"boolean"` 或 `"time"`

### 2. trigger_pattern
- **类型**: 字符串
- **说明**: 用于识别payload是否为特定类型盲注的关键模式（不区分大小写）
- **示例**: 
  - 布尔盲注: `"ORD(MID("`
  - 时间盲注: `"SLEEP(1-(IF("`

### 3. judge_function
- **类型**: 对象
- **说明**: 定义如何根据响应大小判断条件真假
- **子字段**:
  - `type`: 判断类型，可选值:
    - `"size_equal"`: 响应大小等于特定值
    - `"size_less"`: 响应大小小于特定值
    - `"size_greater"`: 响应大小大于特定值
    - `"size_range"`: 响应大小在特定范围内
  - `value`: 用于比较的值（适用于前三种类型）
  - `min`和`max`: 范围的最小值和最大值（仅适用于`size_range`类型）

#### judge_function 示例

```json
// 布尔盲注：响应大小等于15表示条件为真
"judge_function": {
  "type": "size_equal",
  "value": 15
}

// 时间盲注：响应大小小于1406表示条件为真（因为睡眠函数执行导致响应较小）
"judge_function": {
  "type": "size_less",
  "value": 1406
}

// 范围判断：响应大小在1000到2000之间表示条件为真
"judge_function": {
  "type": "size_range",
  "min": 1000,
  "max": 2000
}
```

### 4. patterns
- **类型**: 对象
- **说明**: 包含多个正则表达式模式，用于从payload中提取特定信息
- **子字段**:
  - `from_pattern`: 提取数据库名和表名
  - `cast_pattern`: 提取列名
  - `limit_pattern`: 提取LIMIT子句中的偏移量
  - `position_pattern`: 提取字符位置
  - `comparison_pattern`: 提取比较运算符和比较值

#### patterns 详解

1. **from_pattern**
   - **用途**: 提取数据库名和表名
   - **格式**: `FROM\s+([\w_]+)\.([\w_]+)`
   - **捕获组**: 
     - 第1组: 数据库名
     - 第2组: 表名
   - **示例**: 从`FROM information_schema.tables`中提取:
     - 数据库名: `information_schema`
     - 表名: `tables`

2. **cast_pattern**
   - **用途**: 提取列名
   - **格式**: `CAST\(([\w_]+)\s+AS`
   - **捕获组**: 
     - 第1组: 列名
   - **示例**: 从`CAST(password AS`中提取列名`password`

3. **limit_pattern**
   - **用途**: 提取LIMIT子句中的偏移量（记录索引）
   - **格式**: `LIMIT\s+(\d+),1`
   - **捕获组**: 
     - 第1组: 偏移量（整数）
   - **示例**: 从`LIMIT 5,1`中提取偏移量`5`

4. **position_pattern**
   - **用途**: 提取字符位置（第几个字符）
   - **格式**: `,(\d+),1\)\)`
   - **捕获组**: 
     - 第1组: 字符位置（整数）
   - **示例**: 从`,3,1))`中提取位置`3`

5. **comparison_pattern**
   - **用途**: 提取比较运算符和比较的ASCII值
   - **格式**: `\)\)\s*([<>!]=?)\s*(\d+)`
   - **捕获组**: 
     - 第1组: 比较运算符（如`>`, `<`, `>=`, `!=`等）
     - 第2组: 比较的ASCII值（整数）
   - **示例**: 从`))>97`中提取:
     - 运算符: `>`
     - ASCII值: `97`

## 编写自定义配置文件

### 步骤1: 确定注入类型

根据要分析的盲注类型设置`injection_type`:
- 布尔盲注: `"boolean"`
- 时间盲注: `"time"`

### 步骤2: 设置触发模式

分析payload样本，找出能够唯一标识该类型注入的模式:
```json
"trigger_pattern": "ORD(MID("  // 布尔盲注
"trigger_pattern": "SLEEP(1-(IF("  // 时间盲注
```

### 步骤3: 配置判断函数

根据响应特征设置判断条件:
```json
// 布尔盲注：条件为真时响应大小固定
"judge_function": {
  "type": "size_equal",
  "value": 15
}

// 时间盲注：条件为真时响应较小（因为执行了睡眠函数）
"judge_function": {
  "type": "size_less",
  "value": 1406
}
```

### 步骤4: 定义提取模式

根据payload结构编写正则表达式模式:
```json
"patterns": {
  "from_pattern": "FROM\\s+([\\w_]+)\\.([\\w_]+)",
  "cast_pattern": "CAST\\(([\\w_]+)\\s+AS",
  "limit_pattern": "LIMIT\\s+(\\d+),1",
  "position_pattern": ",(\\d+),1\\)\\)",
  "comparison_pattern": "\\)\\)\\s*([<>!]=?)\\s*(\\d+)"
}
```

### 完整配置示例

#### 布尔盲注配置
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

#### 时间盲注配置
```json
{
  "injection_type": "time",
  "trigger_pattern": "SLEEP(1-(IF(",
  "judge_function": {
    "type": "size_less",
    "value": 1406
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

## 高级用法

### 处理多种注入类型

要同时处理多种注入类型，可以创建多个配置并分别运行分析器，或者修改代码以支持多配置同时分析。

### 自定义正则表达式

如果payload结构发生变化，可能需要调整正则表达式模式。确保模式能够正确捕获所需信息，并使用在线正则表达式测试工具进行验证。

### 错误处理

分析器会捕获并输出处理过程中遇到的错误，便于调试配置问题或数据格式问题。

## 注意事项

1. 配置文件中的正则表达式使用双反斜杠转义特殊字符
2. 触发模式应尽可能唯一，避免误匹配
3. 判断函数的值应根据实际测试数据调整
4. 分析器只对包含触发模式的payload进行深度分析

## 故障排除

如果分析结果不符合预期，请检查:
1. 触发模式是否匹配payload
2. 正则表达式是否能正确提取信息
3. 判断函数的类型和值是否设置正确
4. 输入数据格式是否符合要求

通过合理配置，SQLMap盲注分析器可以有效地从SQLMap生成的盲注payload中提取结构化信息，帮助安全研究人员更好地理解和分析SQL注入攻击。