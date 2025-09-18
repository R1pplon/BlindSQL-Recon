#!/usr/bin/env python3
"""
file: sqlmap_analyzer.py
SQLMap盲注分析器 - 统一版本
支持布尔盲注和时间盲注分析
输入: JSON行格式的请求数据
输出: JSON行格式的分析结果
"""
import sys
import json
import re
import argparse
from typing import Dict, Any, Callable, Optional

# 配置类 - 存储分析器的配置
class BlindAnalysisConfig:
    def __init__(self, 
                 injection_type: str,
                 trigger_pattern: str,
                 judge_function: Callable[[int], bool],
                 patterns: Dict[str, str]):
        self.injection_type = injection_type
        self.trigger_pattern = trigger_pattern
        self.judge_function = judge_function
        self.patterns = patterns

# 分析器核心类
class SQLMapBlindAnalyzer:
    def __init__(self, config: BlindAnalysisConfig):
        self.config = config
        self.compiled_patterns = {name: re.compile(pattern, re.IGNORECASE) 
                                 for name, pattern in config.patterns.items()}
    
    def analyze_payload(self, payload: str, response_size: int) -> Dict[str, Any]:
        analysis = {
            'type': 'unknown',
            'database': '',
            'table': '',
            'column': '',
            'position': 0,
            'ascii_value': 0,
            'limit_offset': 0,
            'judge': self.config.judge_function(response_size),
            'comparison_operator': '>',
            'record_id': 0
        }

        # 检测特定的盲注模式
        if payload and self.config.trigger_pattern in payload.upper():
            analysis['type'] = f'{self.config.injection_type}_injection'
            payload_upper = payload.upper()
            
            # 统一处理逻辑：布尔盲注和时间盲注都使用相同的模式提取方法
            # 提取数据库和表名
            from_match = self.compiled_patterns.get('from_pattern', re.compile('')).search(payload_upper)
            if from_match:
                analysis['database'] = from_match.group(1)
                analysis['table'] = from_match.group(2)
            
            # 提取列名
            cast_match = self.compiled_patterns.get('cast_pattern', re.compile('')).search(payload_upper)
            if cast_match:
                analysis['column'] = cast_match.group(1)
            
            # 提取LIMIT偏移量
            limit_match = self.compiled_patterns.get('limit_pattern', re.compile('')).search(payload_upper)
            if limit_match:
                analysis['limit_offset'] = int(limit_match.group(1))
                analysis['record_id'] = analysis['limit_offset']
            
            # 提取字符位置
            position_match = self.compiled_patterns.get('position_pattern', re.compile('')).search(payload_upper)
            if position_match:
                analysis['position'] = int(position_match.group(1))
            
            # 提取比较运算符和值
            comparison_match = self.compiled_patterns.get('comparison_pattern', re.compile('')).search(payload_upper)
            if comparison_match:
                analysis['comparison_operator'] = comparison_match.group(1)
                analysis['ascii_value'] = int(comparison_match.group(2))

        return analysis

    def process_line(self, line: str) -> str:
        """处理单行输入并返回分析结果"""
        try:
            req = json.loads(line.strip())
            if 'payload' in req:
                analysis = self.analyze_payload(
                    req['payload'], 
                    req['response_size']
                )
                
                result = {
                    'request': req,
                    'analysis': analysis
                }
                return json.dumps(result)
            return line  # 如果没有payload，原样返回
        except Exception as e:
            return f"Error analyzing payload: {e}"

def create_judge_function(judge_config: Dict[str, Any]) -> Callable[[int], bool]:
    """根据配置创建判断函数"""
    judge_type = judge_config.get('type', 'size_equal')
    value = judge_config.get('value', 0)
    
    if judge_type == 'size_equal':
        return lambda size: size == value
    elif judge_type == 'size_less':
        return lambda size: size < value
    elif judge_type == 'size_greater':
        return lambda size: size > value
    elif judge_type == 'size_range':
        min_val = judge_config.get('min', -1)
        max_val = judge_config.get('max', -1)
        # 确保配置中确实提供了min和max值
        if min_val == -1 or max_val == -1:
            raise ValueError("size_range类型需要提供min和max参数")
        return lambda size: min_val <= size <= max_val
    else:
        # 默认返回False
        return lambda size: False

def load_config(config_path: str) -> BlindAnalysisConfig:
    """从外部配置文件加载配置"""
    try:
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        # 创建判断函数
        judge_function = create_judge_function(config_data.get('judge_function', {}))
        
        # 创建配置对象
        config = BlindAnalysisConfig(
            injection_type=config_data.get('injection_type', 'boolean'),
            trigger_pattern=config_data.get('trigger_pattern', ''),
            judge_function=judge_function,
            patterns=config_data.get('patterns', {})
        )
        
        return config
        
    except Exception as e:
        print(f"Error loading config from {config_path}: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='SQLMap盲注分析器')
    parser.add_argument('--config', required=True, type=str, 
                       help='外部配置文件路径(JSON格式)')
    args = parser.parse_args()
    
    # 从外部配置文件加载配置
    config = load_config(args.config)
    
    # 创建分析器实例
    analyzer = SQLMapBlindAnalyzer(config)
    
    # 处理输入
    for line in sys.stdin:
        result = analyzer.process_line(line)
        print(result)

if __name__ == '__main__':
    main()