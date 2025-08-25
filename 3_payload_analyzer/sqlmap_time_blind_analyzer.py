#!/usr/bin/env python3
"""
file: sqlmap_time_blind_analyzer.py
Payload分析器 - 识别SQLMap时间盲注特征
输入: JSON行格式的请求数据
输出: JSON行格式的分析结果
"""
import sys
import json
import re

def analyze_payload(payload, response_size):
    analysis = {
        'type': 'unknown',
        'database': '',
        'table': '',
        'column': '',
        'position': 0,
        'ascii_value': 0,
        'limit_offset': 0,
        'sleep_triggered': False,
        'comparison_operator': '>',
        'record_id': 0
    }

    # 检测睡眠触发
    analysis['sleep_triggered'] = response_size < 1406

    # SQLMap特有的时间盲注模式
    if payload and 'SLEEP(1-(IF(' in payload.upper():
        analysis['type'] = 'time_blind_injection'
        payload = payload.upper()

        # 提取数据库、表、列等信息
        ord_mid_pattern = r'ORD\(MID\(\(SELECT\s+.*?FROM\s+(\w+)\.(\w+).*?LIMIT\s+(\d+),1\),(\d+),1\)\)([><!]=?)(\d+)'
        match = re.search(ord_mid_pattern, payload, re.IGNORECASE)

        if match:
            analysis['database'] = match.group(1)
            analysis['table'] = match.group(2)
            analysis['limit_offset'] = int(match.group(3))
            analysis['position'] = int(match.group(4))
            analysis['comparison_operator'] = match.group(5)
            analysis['ascii_value'] = int(match.group(6))
            analysis['record_id'] = analysis['limit_offset']

            # 提取字段名
            field_pattern = r'CAST\((\w+)\s+AS'
            field_match = re.search(field_pattern, payload, re.IGNORECASE)
            if field_match:
                analysis['column'] = field_match.group(1)

    return analysis

def main():
    for line in sys.stdin:
        try:
            req = json.loads(line.strip())
            if 'payload' in req:
                analysis = analyze_payload(
                    req['payload'], 
                    req['response_size']
                )
                
                result = {
                    'request': req,
                    'analysis': analysis
                }
                print(json.dumps(result))
                
        except Exception as e:
            print(f"Error analyzing payload: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()