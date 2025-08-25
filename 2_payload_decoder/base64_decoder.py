#!/usr/bin/env python3
"""
file: base64_decoder.py
Payload解码器 - 处理URL和Base64编码
输入: JSON行格式的请求数据
输出: JSON行格式的请求数据（含解码后的payload）
"""
import sys
import json
import base64


def decode(encoded_str):
    """执行Base64解码并尝试转为UTF-8字符串"""
    try:
        return base64.b64decode(encoded_str).decode('utf-8')
    except Exception:
        return None

def main():
    for line in sys.stdin:
        try:
            req = json.loads(line.strip())
            req['payload'] = decode(req['payload'])
            print(json.dumps(req))

        except Exception as e:
            print(f"Error processing line: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()