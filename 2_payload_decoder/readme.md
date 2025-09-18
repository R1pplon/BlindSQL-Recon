# Payload 解码器工具集

## 概述

本目录包含两个用于处理编码 payload 的解码器工具，能够处理 JSON 行格式的请求数据并解码其中的 payload 字段。

## 工具列表

### 1. Base64 解码器 (base64_decoder.py)

**功能**：

- 对请求中的 payload 字段执行 Base64 解码
- 尝试将解码结果转换为 UTF-8 字符串
- 处理失败时保留原始 payload 值

**使用方法**：

```bash
cat input.json | python3 base64_decoder.py
```

### 2. URL 解码器 (url_decoder.py)

**功能**：

- 对请求中的 payload 字段执行 URL 解码（使用 urllib.parse.unquote）
- 处理失败时保留原始 payload 值

**使用方法**：

```bash
cat input.json | python3 url_decoder.py
```

## 输入输出格式

**输入**：JSON 行格式，每行包含至少一个 `payload` 字段

```json
{"payload": "编码的内容", "other_field": "值"}
```

**输出**：JSON 行格式，包含解码后的 payload

```json
{"payload": "解码后的内容", "other_field": "值"}
```

## 注意事项

1. 两个工具都从标准输入读取数据，处理结果输出到标准输出
2. 错误信息会输出到标准错误流(stderr)
3. 解码失败时会保留原始 payload 值不变
4. 两个工具可单独使用，也可通过管道组合使用

## 组合使用示例

```bash
# 先进行URL解码，再进行Base64解码
cat input.json | python3 url_decoder.py | python3 base64_decoder.py > output.json
```
