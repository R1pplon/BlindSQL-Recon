#!/usr/bin/env python3
"""
file: 2_param_detector.py
AI参数检测器 - 通过LLM自动识别日志中携带SQL注入payload的参数名
输入: JSON行格式的日志数据 (1_web_log_parser.py 的输出)
输出: 元数据行 + 全量透传的原始数据
依赖: openai, pyyaml (DeepSeek API)
环境变量: DEEPSEEK_API_KEY
"""
import sys
import json
import os
import re
import random
import argparse
from urllib.parse import urlparse
from collections import defaultdict

import yaml
from openai import OpenAI


def load_dotenv(dotenv_path=None):
    """加载 .env 文件中的环境变量"""
    if dotenv_path is None:
        dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env')
    if not os.path.exists(dotenv_path):
        dotenv_path = os.path.join(os.getcwd(), '.env')
    if not os.path.exists(dotenv_path):
        return
    with open(dotenv_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value

SYSTEM_PROMPT = """你是SQL注入日志分析专家。分析以下随机采样的HTTP请求日志（YAML格式，
按URL路径聚合了参数及其采样值）。

任务：
1. 识别哪个 URL 参数携带了 SQL 盲注 payload
2. SQL盲注payload特征：ORD、MID、SLEEP、IF、SELECT、CAST、LIMIT、
   大量URL编码字符（%27、%28、%29、%20等）
3. 忽略无参数的请求（params: {}）
4. 确认一个最有可能的注入点参数名称
5. 如果无法确定，返回 <unknown>
6. 返回格式：用尖括号包裹参数名，仅返回 <参数名> ，不返回任何其他内容
    - 正确示例：
        <username>
        <query>
        <unknown>
"""


def parse_params_from_request_line(request_line):
    """从request_line中提取URL参数，返回 {param_name: [value1, value2, ...]}"""
    parts = request_line.split(' ', 2)
    if len(parts) < 2:
        return {}
    uri = parts[1]
    parsed = urlparse(uri)

    params = {}
    if parsed.query:
        for pair in parsed.query.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
    return params


def aggregate_samples(sample_lines):
    """将采样数据按 URL path + param name 聚合"""
    path_groups = defaultdict(lambda: defaultdict(list))

    for line in sample_lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        request_line = entry.get('request_line', '')
        parts = request_line.split(' ', 2)
        if len(parts) < 2:
            continue
        uri = parts[1]
        parsed = urlparse(uri)
        path = parsed.path

        params = parse_params_from_request_line(request_line)
        for key, value in params.items():
            if len(path_groups[path][key]) < 10:
                path_groups[path][key].append(value)

    result = []
    for path, param_map in sorted(path_groups.items()):
        entry = {"path": path}
        if param_map:
            entry["params"] = {k: v for k, v in param_map.items()}
        else:
            entry["params"] = {}
        result.append(entry)

    return result


def call_llm(sampled_yaml, max_retries=3):
    """调用DeepSeek API检测注入参数名 (尖括号格式提取+自动重试)"""
    load_dotenv()
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        print("[ERROR] 未设置 DEEPSEEK_API_KEY 环境变量", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com"
    )

    user_content = yaml.dump(
        {"sampled_entries": sampled_yaml},
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=200
    )

    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model="deepseek-v4-flash",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                stream=False,
                reasoning_effort="high",
                extra_body={"thinking": {"type": "enabled"}}
            )
        except Exception as e:
            if attempt < max_retries:
                print(f"[WARN] API请求失败 (尝试{attempt}/{max_retries}): {e}", file=sys.stderr)
                continue
            print(f"[ERROR] API请求失败 (已重试{max_retries}次): {e}", file=sys.stderr)
            sys.exit(1)

        raw_output = response.choices[0].message.content.strip()

        match = re.search(r'<([\w-]+)>', raw_output)
        if match:
            param_name = match.group(1).strip()
            if param_name.lower() == "unknown":
                print("[ERROR] AI未能识别注入参数", file=sys.stderr)
                sys.exit(1)
            return param_name

        if attempt < max_retries:
            print(f"[WARN] AI返回格式不正确 (尝试{attempt}/{max_retries}): "
                  f"{raw_output[:100]}...", file=sys.stderr)
        else:
            print(f"[ERROR] AI连续{max_retries}次返回格式不正确", file=sys.stderr)
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='AI参数检测器')
    parser.add_argument('-n', '--max-samples', type=int, default=100,
                        help='采样数量 (默认: 100)')
    args = parser.parse_args()

    all_lines = []
    for line in sys.stdin:
        line = line.strip()
        if line:
            all_lines.append(line)

    if not all_lines:
        print("[ERROR] 输入日志为空", file=sys.stderr)
        sys.exit(1)

    sample_count = min(args.max_samples, len(all_lines))
    sampled = random.sample(all_lines, sample_count) if sample_count > 0 else []

    print(f"[INFO] 总行数: {len(all_lines)}, 采样: {sample_count}", file=sys.stderr)

    sampled_data = aggregate_samples(sampled)
    path_count = len(sampled_data)
    param_count = sum(
        len(entry.get("params", {})) for entry in sampled_data
    )
    print(f"[INFO] 唯一路径: {path_count}, 唯一参数: {param_count}", file=sys.stderr)

    param_name = call_llm(sampled_data)

    print(f"[INFO] 检测到注入参数: {param_name}", file=sys.stderr)

    # 输出元数据行
    sys.stdout.write(json.dumps({"__param_detect__": param_name}) + "\n")
    # 透传全量原始数据
    for line in all_lines:
        sys.stdout.write(line + "\n")
    sys.stdout.flush()


if __name__ == '__main__':
    main()
