#!/usr/bin/env python3
"""
file: url_decoder.py
Payload解码器 - 处理URL编码
输入: JSON行格式的请求数据
输出: JSON行格式的请求数据（含解码后的payload）
"""
import sys
import json
import urllib.parse

def decode(encoded_str):
    """执行URL解码"""
    try:
        return urllib.parse.unquote(encoded_str)
    except Exception:
        return encoded_str


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