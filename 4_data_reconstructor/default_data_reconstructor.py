#!/usr/bin/env python3
"""
file: default_data_reconstructor.py
数据重构器 - 组合分析结果重构被盗数据
输入: JSON行格式的分析结果
输出: 结构化JSON数据
"""
import sys
import json
from collections import defaultdict

def reconstruct_character(comparisons):
    if not comparisons:
        return None

    min_val = 32
    max_val = 126

    for comp in sorted(comparisons, key=lambda x: x['ascii_value']):
        ascii_val = comp['ascii_value']
        judge = comp['judge']
        operator = comp.get('comparison_operator', '>')

        if operator == '!=':
            if judge:
                return ascii_val
            continue
            
        if operator == '>':
            if judge:
                max_val = min(max_val, ascii_val)
            else:
                min_val = max(min_val, ascii_val + 1)
        elif operator == '<':
            if judge:
                min_val = max(min_val, ascii_val)
            else:
                max_val = min(max_val, ascii_val - 1)

    return min_val if min_val == max_val else None

def main():
    payload_analyses = []
    for line in sys.stdin:
        try:
            data = json.loads(line.strip())
            payload_analyses.append(data['analysis'])
        except Exception as e:
            print(f"Error loading analysis: {e}", file=sys.stderr)
            continue

    results = {
        'database': '',
        'tables': [],
        'columns': {},
        'data': {}
    }

    # 收集数据提取信息
    data_extractions = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))

    for analysis in payload_analyses:
        if "inject" in analysis['type'] and analysis['table'] and analysis['column']:
            if not results['database'] and analysis['database']:
                results['database'] = analysis['database']

            table_name = analysis['table']
            if table_name and table_name not in results['tables']:
                results['tables'].append(table_name)

            table_key = f"{analysis['database']}.{analysis['table']}"
            column = analysis['column']

            if table_key not in results['columns']:
                results['columns'][table_key] = []
            if column and column not in results['columns'][table_key]:
                results['columns'][table_key].append(column)

            # 收集字符比较数据
            if analysis['position'] > 0:
                record_id = analysis['record_id']
                position = analysis['position']

                data_extractions[table_key][column][record_id][position].append({
                    'ascii_value': analysis['ascii_value'],
                    'judge': analysis['judge'],
                    'comparison_operator': analysis['comparison_operator']
                })

    # 重构字符串数据
    for table_key, columns in data_extractions.items():
        results['data'][table_key] = {}

        for column, records in columns.items():
            reconstructed_records = []

            for record_id in sorted(records.keys()):
                positions = records[record_id]
                max_pos = max(positions.keys()) if positions else 0
                chars = []

                for pos in range(1, max_pos + 1):
                    if pos in positions:
                        char_code = reconstruct_character(positions[pos])
                        if char_code and 32 <= char_code <= 126:
                            chars.append(chr(char_code))
                        elif char_code == 0:
                            break
                    else:
                        break

                reconstructed_value = ''.join(chars)
                if reconstructed_value:
                    reconstructed_records.append({
                        'record_id': record_id,
                        'value': reconstructed_value
                    })

            if reconstructed_records:
                reconstructed_records.sort(key=lambda x: x['record_id'])
                results['data'][table_key][column] = [r['value'] for r in reconstructed_records]

    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()