#!/usr/bin/env python3
"""
file: 3_param_extractor.py
参数提取器 - 从结构化日志中提取特定参数
输入: JSON行格式的日志数据（支持2_param_detector.py的AI元数据）
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
        # 'status_code': int(log_data.get('status_code', 200)),
        'response_size': int(log_data.get('response_size', 0)) if log_data.get('response_size', '-') != '-' else 0,
        # 'timestamp': log_data.get('timestamp', ''),
        'payload': param_match.group(1)
    }

def main():
    parser = argparse.ArgumentParser(description='参数提取器', add_help=False)
    parser.add_argument('-p', '--param', default=None, help='关键参数名（AI模式下自动检测）')
    parser.add_argument('-k', '--key', help='关键词过滤（可选）')
    parser.add_argument('-h', '--help', action='help', help='显示帮助信息')
    
    args = parser.parse_args()
    
    # 读取第一行，检测是否为AI元数据
    first_line = sys.stdin.readline()
    if not first_line:
        print("Error: 输入数据为空", file=sys.stderr)
        sys.exit(1)
    
    first_line = first_line.strip()
    param_from_ai = None

    if first_line:
        try:
            meta = json.loads(first_line)
            if "__param_detect__" in meta:
                param_from_ai = meta["__param_detect__"]
        except json.JSONDecodeError:
            pass

    # 参数优先级: -p 明确指定 > AI检测 > 报错
    if args.param:
        key_param = args.param
        print(f"[INFO] 使用手动指定参数: {key_param}", file=sys.stderr)
    elif param_from_ai:
        key_param = param_from_ai
        print(f"[INFO] 使用AI检测参数: {key_param}", file=sys.stderr)
    else:
        print("Error: 需要指定 -p 参数，或从AI检测器输入", file=sys.stderr)
        sys.exit(1)

    # 处理数据行
    def all_lines():
        if not param_from_ai:
            yield first_line
        for line in sys.stdin:
            yield line

    for line in all_lines():
        # 关键词过滤：如果提供了-k参数且关键词不在行中，则跳过
        if args.key and args.key not in line:
            continue

        try:
            log_data = json.loads(line)
            result = extract_parameter(log_data, key_param)
            if result:
                print(json.dumps(result))
        except json.JSONDecodeError:
            continue

if __name__ == '__main__':
    main()
