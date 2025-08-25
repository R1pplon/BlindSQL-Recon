#!/usr/bin/env python3
"""
file: default_report_generator.py
报告生成器 - 创建最终报告
输入: 结构化JSON数据
输出: 控制台报告和JSON文件
"""
import os
import sys
import json
from datetime import datetime

def generate_report(data):
    report = {
        'database': data.get('database', ''),
        'compromised_tables': data.get('tables', []),
        'stolen_data': {},
        'analysis_time': datetime.now().isoformat()
    }

    # 控制台报告
    print("\n" + "="*60)
    print("SQL盲注攻击分析报告")
    print("="*60)

    if report['database']:
        print(f"\n[+] 目标数据库: {report['database']}")

    if report['compromised_tables']:
        print(f"\n[+] 被攻击的表:")
        for table in report['compromised_tables']:
            print(f"    - {table}")

    if data.get('columns'):
        print(f"\n[+] 发现的列结构:")
        for table_key, columns in data['columns'].items():
            print(f"    {table_key}:")
            for column in columns:
                print(f"      - {column}")

    # 提取被盗数据
    for table_key, columns in data.get('data', {}).items():
        table_name = table_key.split('.')[-1]
        if table_name not in report['stolen_data']:
            report['stolen_data'][table_name] = {}
        
        for column, values in columns.items():
            if column not in report['stolen_data'][table_name]:
                report['stolen_data'][table_name][column] = []
                
            report['stolen_data'][table_name][column].extend(values)
            
            # 在控制台显示
            print(f"\n[+] 表 {table_name}.{column} 中被盗数据:")
            for i, value in enumerate(values):
                print(f"    记录 {i+1}: {value}")

    # 保存JSON报告
    os.makedirs("./result", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"./result/sql_injection_report_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] 详细报告已保存到 {filename}")
    return filename

def main():
    try:
        data = json.load(sys.stdin)
        generate_report(data)
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()