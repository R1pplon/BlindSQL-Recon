#!/usr/bin/env python3
"""
file: 2_param_extractor.py
参数提取器 - 从结构化日志中提取特定参数
输入: JSON行格式的日志数据
输出: JSON行格式的提取结果
"""
import re
import json
import sys
import argparse

def extract_parameter(log_data, key_param):
    """
    从日志数据中提取特定参数
    """
    # 编译参数提取正则表达式
    param_pattern = re.compile(rf'{re.escape(key_param)}=([^&\s]+)')
    
    # 从请求行中提取查询字符串
    request_line = log_data.get('request_line', '')
    query_match = re.search(r'GET\s+[^\s]*\?([^\s]*)\s+HTTP', request_line)
    if not query_match:
        return None
    
    query_string = query_match.group(1)
    
    # 提取关键参数值
    param_match = param_pattern.search(query_string)
    if not param_match:
        return None
    
    # 构建请求数据
    return {
        'status_code': int(log_data.get('status_code', 200)),
        'response_size': int(log_data.get('response_size', 0)) if log_data.get('response_size', '-') != '-' else 0,
        'timestamp': log_data.get('timestamp', ''),
        'payload': param_match.group(1)
    }

def main():
    parser = argparse.ArgumentParser(description='参数提取器', add_help=False)
    parser.add_argument('-p', '--param', required=True, help='关键参数名')
    parser.add_argument('-h', '--help', action='help', help='显示帮助信息')
    
    args = parser.parse_args()
    
    for line in sys.stdin:
        try:
            log_data = json.loads(line)
            result = extract_parameter(log_data, args.param)
            if result:
                print(json.dumps(result))
        except json.JSONDecodeError:
            continue

if __name__ == '__main__':
    main()