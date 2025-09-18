#!/usr/bin/env python3
"""
file: default_report_generator.py
报告生成器 - 创建最终报告
输入: 结构化JSON数据
输出: 控制台报告和多种格式文件
"""
import os
import sys
import json
import csv
import argparse
from datetime import datetime

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='SQL注入攻击报告生成器')
    parser.add_argument('-o', '--output', choices=['json', 'csv', 'txt', 'all'], 
                        default='json', help='输出格式 (默认: json)')
    return parser.parse_args()

def create_report_structure(data):
    """创建报告基本结构"""
    return {
        'database': data.get('database', ''),
        'compromised_tables': data.get('tables', []),
        'columns_info': data.get('columns', {}),
        'stolen_data': extract_stolen_data(data),
        'analysis_time': datetime.now().isoformat()
    }

def extract_stolen_data(data):
    """从输入数据中提取被盗数据"""
    stolen_data = {}
    
    for table_key, columns in data.get('data', {}).items():
        table_name = table_key.split('.')[-1]
        if table_name not in stolen_data:
            stolen_data[table_name] = {}
        
        for column, values in columns.items():
            if column not in stolen_data[table_name]:
                stolen_data[table_name][column] = []
            
            stolen_data[table_name][column].extend(values)
    
    return stolen_data

def print_console_report(report):
    """在控制台输出报告"""
    print("\n" + "="*60)
    print("SQL盲注攻击分析报告")
    print("="*60)

    if report['database']:
        print(f"\n[+] 目标数据库: {report['database']}")

    if report['compromised_tables']:
        print(f"\n[+] 被攻击的表:")
        for table in report['compromised_tables']:
            print(f"    - {table}")

    if report['columns_info']:
        print(f"\n[+] 发现的列结构:")
        for table_key, columns in report['columns_info'].items():
            print(f"    {table_key}:")
            for column in columns:
                print(f"      - {column}")

    # 输出被盗数据
    for table_name, columns in report['stolen_data'].items():
        for column, values in columns.items():
            print(f"\n[+] 表 {table_name}.{column} 中被盗数据:")
            for i, value in enumerate(values):
                print(f"    记录 {i+1}: {value}")

def ensure_output_directory():
    """确保输出目录存在"""
    os.makedirs("./result", exist_ok=True)
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def save_json_report(report, timestamp):
    """保存JSON格式报告"""
    filename = f"./result/sql_injection_report_{timestamp}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] JSON报告已保存到 {filename}")
    return filename

def save_csv_report(report, timestamp):
    """保存CSV格式报告"""
    csv_dir = f"./result/csv_report_{timestamp}"
    os.makedirs(csv_dir, exist_ok=True)
    
    # 创建元数据文件
    metadata_file = f"{csv_dir}/metadata.csv"
    with open(metadata_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Database', report['database']])
        writer.writerow(['Analysis Time', report['analysis_time']])
        writer.writerow([])
        writer.writerow(['Compromised Tables'])
        for table in report['compromised_tables']:
            writer.writerow([table])
    
    # 为每个表创建CSV文件
    for table_name, columns in report['stolen_data'].items():
        csv_file = f"{csv_dir}/{table_name}.csv"
        
        # 获取所有列名
        all_columns = list(columns.keys())
        
        # 确定最大行数
        max_rows = max(len(values) for values in columns.values())
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_columns)
            writer.writeheader()
            
            # 逐行写入数据
            for i in range(max_rows):
                row = {}
                for col in all_columns:
                    values = columns[col]
                    row[col] = values[i] if i < len(values) else ""
                writer.writerow(row)
    
    print(f"\n[+] CSV报告已保存到目录 {csv_dir}")
    return csv_dir

def save_txt_report(report, timestamp):
    """保存文本格式报告"""
    filename = f"./result/sql_injection_report_{timestamp}.txt"
    with open(filename, 'w') as f:
        f.write("="*60 + "\n")
        f.write("SQL盲注攻击分析报告\n")
        f.write("="*60 + "\n\n")
        
        f.write(f"[+] 目标数据库: {report['database']}\n\n")
        
        f.write("[+] 被攻击的表:\n")
        for table in report['compromised_tables']:
            f.write(f"    - {table}\n")
        
        f.write("\n[+] 发现的列结构:\n")
        for table_key, columns in report['columns_info'].items():
            f.write(f"    {table_key}:\n")
            for column in columns:
                f.write(f"      - {column}\n")
        
        f.write("\n[+] 被盗数据:\n")
        for table_name, columns in report['stolen_data'].items():
            for column, values in columns.items():
                f.write(f"\n表 {table_name}.{column}:\n")
                for i, value in enumerate(values):
                    f.write(f"  记录 {i+1}: {value}\n")
    
    print(f"\n[+] TXT报告已保存到 {filename}")
    return filename

def generate_report(data, output_format='json'):
    """生成报告主函数"""
    # 创建报告结构
    report = create_report_structure(data)
    
    # 输出控制台报告
    print_console_report(report)
    
    # 确保输出目录存在并获取时间戳
    timestamp = ensure_output_directory()
    
    # 根据输出格式保存报告
    output_files = []
    
    if output_format in ['json', 'all']:
        output_files.append(save_json_report(report, timestamp))
    
    if output_format in ['csv', 'all']:
        output_files.append(save_csv_report(report, timestamp))
    
    if output_format in ['txt', 'all']:
        output_files.append(save_txt_report(report, timestamp))
    
    return output_files

def main():
    """主函数"""
    args = parse_arguments()
    
    try:
        # 从标准输入读取JSON数据
        data = json.load(sys.stdin)
        # 生成报告
        generate_report(data, args.output)
    except json.JSONDecodeError as e:
        print(f"JSON解析错误: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"生成报告时出错: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()