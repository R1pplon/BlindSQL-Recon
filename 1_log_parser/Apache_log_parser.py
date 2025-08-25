#!/usr/bin/env python3
"""
file: Apache_log_parser.py
Apache日志解析器 - 提取SQLMap相关请求
输入: Apache日志文件
输出: JSON行格式的请求数据
"""
import re
import json
import argparse

def parse_apache_log(log_file, keyword, key_param):
    # 预编译正则表达式提高效率
    log_pattern = re.compile(r'^.*?\[(.*?)\].*?"GET\s+.*?\?(.*?)\s+HTTP.*?"\s+(\d+)\s+(\d+)')
    param_pattern = re.compile(rf'{re.escape(key_param)}=([^&\s]+)')
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or keyword not in line:
                continue

            # 单次正则匹配提取所有字段
            match = log_pattern.search(line)
            if not match:
                continue
                
            timestamp, query_string, status_code, response_size = match.groups()
            
            # 提取关键参数值
            param_match = param_pattern.search(query_string)
            if not param_match:
                continue
                
            request_data = {
                'status_code': int(status_code),
                'response_size': int(response_size),
                'timestamp': timestamp,
                'payload': param_match.group(1)
            }
            print(json.dumps(request_data))

def main():
    parser = argparse.ArgumentParser(description='Log Parser Tool', add_help=False)
    parser.add_argument('-f', '--file', required=True, help='Log file path')
    parser.add_argument('-p', '--param', required=True, help='Key parameter name')
    parser.add_argument('-k', '--keyword', default='sqlmap', help='Filter keyword')
    parser.add_argument('-h', '--help', action='help', help='Show help')
    
    args = parser.parse_args()
    parse_apache_log(args.file, args.keyword, args.param)

if __name__ == '__main__':
    main()