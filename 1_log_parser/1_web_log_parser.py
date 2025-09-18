#!/usr/bin/env python3
"""
file: 1_web_log_parser.py
Web日志解析器 - 解析通用日志格式(CLF)和组合日志格式
输入: 日志文件
输出: JSON行格式的结构化日志数据
"""
import re
import json
import sys

def parse_log_line(line):
    """
    自动识别并解析日志行
    支持通用日志格式和组合日志格式
    """
    # 尝试匹配组合日志格式
    combined_pattern = re.compile(r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+|-) "([^"]*)"')
    match = combined_pattern.match(line)
    if match:
        return {
            'remote_host': match.group(1),
            'remote_logname': match.group(2),
            'remote_user': match.group(3),
            'timestamp': match.group(4),
            'request_line': match.group(5),
            'status_code': match.group(6),
            'response_size': match.group(7),
            'user_agent': match.group(8)
        }
    
    # 尝试匹配通用日志格式
    common_pattern = re.compile(r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+|-)')
    match = common_pattern.match(line)
    if match:
        return {
            'remote_host': match.group(1),
            'remote_logname': match.group(2),
            'remote_user': match.group(3),
            'timestamp': match.group(4),
            'request_line': match.group(5),
            'status_code': match.group(6),
            'response_size': match.group(7)
        }
    
    return None

def main():
    """
    主函数：从标准输入读取日志，解析后输出JSON
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        # 解析日志行
        log_data = parse_log_line(line)
        if log_data:
            print(json.dumps(log_data))

if __name__ == '__main__':
    main()