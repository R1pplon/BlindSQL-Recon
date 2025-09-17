#!/usr/bin/env python3
"""
file: sqlmap_boolean_blind_analyzer.py
Payload分析器 - 识别SQLMap布尔盲注特征
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
        'judge': False,
        'comparison_operator': '>',
        'record_id': 0
    }

    # 布尔盲注判断：响应大小差异
    # 样例中15表示条件为真，23表示条件为假
    analysis['judge'] = response_size == 15  # 15表示条件成立

    # SQLMap布尔盲注模式检测
    if payload and 'ORD(MID(' in payload and 'FROM' in payload.upper():
        analysis['type'] = 'blind_injection'
        payload = payload.upper()
        
        # 提取数据库和表名
        from_pattern = r'FROM\s+([\w_]+)\.([\w_]+)'
        from_match = re.search(from_pattern, payload, re.IGNORECASE)
        if from_match:
            analysis['database'] = from_match.group(1)
            analysis['table'] = from_match.group(2)
        
        # 提取列名
        cast_pattern = r'CAST\(([\w_]+)\s+AS'
        cast_match = re.search(cast_pattern, payload, re.IGNORECASE)
        if cast_match:
            analysis['column'] = cast_match.group(1)
        
        # 提取LIMIT偏移量
        limit_pattern = r'LIMIT\s+(\d+),1'
        limit_match = re.search(limit_pattern, payload, re.IGNORECASE)
        if limit_match:
            analysis['limit_offset'] = int(limit_match.group(1))
            analysis['record_id'] = analysis['limit_offset']
        
        # 提取字符位置
        position_pattern = r',(\d+),1\)\)'
        position_match = re.search(position_pattern, payload, re.IGNORECASE)
        if position_match:
            analysis['position'] = int(position_match.group(1))
        
        # 提取比较运算符和值
        comparison_pattern = r'\)\)\s*([<>!]=?)\s*(\d+)'
        comparison_match = re.search(comparison_pattern, payload, re.IGNORECASE)
        if comparison_match:
            analysis['comparison_operator'] = comparison_match.group(1)
            analysis['ascii_value'] = int(comparison_match.group(2))

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