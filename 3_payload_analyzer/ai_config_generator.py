#!/usr/bin/env python3
"""
file: ai_config_generator.py
AI 配置生成器 — 三阶段架构：特征提取 → 语义转换 → 闭环校验
输入: JSON行格式的解码后 payload 数据 (url_decoder.py / base64_decoder.py 的输出)
输出: 元数据行 {"__ai_config__": "<path>"} + 透传全量数据
依赖: openai, pyyaml
环境变量: DEEPSEEK_API_KEY
"""
import sys
import json
import re
import os
import yaml
from datetime import datetime
from collections import Counter, defaultdict
from openai import OpenAI


# ── .env 加载（复用 2_param_detector.py 模式）──────────────────────────

def load_dotenv(dotenv_path=None):
    if dotenv_path is None:
        dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '.env')
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


# ── Phase 1: 特征提取 ──────────────────────────────────────────────────

def _extract_structure_key(payload):
    """从 payload 提取语义结构键：db.table|column|operator|flags"""
    p_upper = payload.upper()

    from_match = re.search(r'FROM\s+(\w+)\.(\w+)', p_upper)
    db_table = f"{from_match.group(1)}.{from_match.group(2)}" if from_match else "?"

    cast_match = re.search(r'CAST\s*\(\s*(\w+)', p_upper)
    column = cast_match.group(1) if cast_match else "?"

    comp_match = re.search(r'\)\)\s*([<>!]=?)\s*\d+', p_upper)
    operator = comp_match.group(1) if comp_match else "?"

    flags = []
    if 'ORDER BY' in p_upper:
        flags.append('OB')
    if 'DISTINCT' in p_upper:
        flags.append('D')
    if 'COUNT' in p_upper:
        flags.append('C')

    return f"{db_table}|{column}|{operator}|{'|'.join(flags)}"


def _infer_judge_function(size_counter, total, injection_hint):
    """推断 judge_function 类型和候选阈值"""
    dominant = {s: c for s, c in size_counter.items() if c >= total * 0.05}
    dominant_sorted = sorted(dominant.keys())

    if len(dominant_sorted) == 2 and injection_hint == 'boolean':
        smaller = dominant_sorted[0]
        larger = dominant_sorted[1]
        return {
            'type': 'size_equal',
            'value': smaller,
            'reason': (
                f'离散双峰分布: {smaller}({dominant[smaller]}次) 和 '
                f'{larger}({dominant[larger]}次)，'
                f'{smaller} 为基线 FALSE 页面'
            )
        }

    all_sizes = sorted(size_counter.keys())
    if len(all_sizes) >= 3:
        trim_start = max(1, len(all_sizes) // 20)
        trim_end = max(1, len(all_sizes) // 20)
        mid_sizes = all_sizes[trim_start:-trim_end] if len(all_sizes) > trim_start + trim_end else all_sizes

        max_gap = 0
        gap_mid = 0
        gap_lo = gap_hi = 0
        for i in range(len(mid_sizes) - 1):
            gap = mid_sizes[i + 1] - mid_sizes[i]
            if gap > max_gap:
                max_gap = gap
                gap_lo, gap_hi = mid_sizes[i], mid_sizes[i + 1]
                gap_mid = (gap_lo + gap_hi) // 2

        if max_gap >= 3:
            lower_cluster = [s for s in all_sizes if s <= gap_mid]
            upper_cluster = [s for s in all_sizes if s > gap_mid]
            lower_total = sum(size_counter[s] for s in lower_cluster)
            upper_total = sum(size_counter[s] for s in upper_cluster)
            return {
                'type': 'size_less',
                'value': gap_mid,
                'reason': (
                    f'双簇分界于 {gap_lo}→{gap_hi} (间隔{max_gap}bytes)，'
                    f'低值簇 {lower_total}条 (TRUE/无延迟)，'
                    f'高值簇 {upper_total}条 (FALSE/有延迟)'
                )
            }

        cumulative = 0
        half = total // 2
        for s in all_sizes:
            cumulative += size_counter[s]
            if cumulative >= half:
                return {
                    'type': 'size_less',
                    'value': s,
                    'reason': f'连续分布，阈值取中位数 {s}'
                }

    if len(dominant_sorted) == 1:
        return {
            'type': 'size_equal',
            'value': dominant_sorted[0],
            'reason': f'单一主值: {dominant_sorted[0]}({dominant[dominant_sorted[0]]}次)'
        }

    return {'type': 'size_equal', 'value': 0, 'reason': '无法推断分布模式'}


def _structural_dedup(records):
    """按语义结构键分组，每类保留 1-2 条代表，压缩到 ≤ 30 条"""
    groups = defaultdict(list)

    for rec in records:
        payload = rec.get('payload')
        if not isinstance(payload, str):
            continue
        key = _extract_structure_key(payload)
        groups[key].append(rec)

    samples = []
    for key, recs in sorted(groups.items(), key=lambda x: -len(x[1])):
        if len(samples) >= 30:
            break
        take = min(len(recs), 2)
        samples.extend(recs[:take])

    return samples


def _extract_keywords(payloads, top_n=20):
    """从 payload 中提取高频 SQL 关键词"""
    word_counter = Counter()
    for p in payloads:
        tokens = re.findall(r'[A-Za-z_]{3,}', p.upper())
        word_counter.update(tokens)

    sql_keywords = {
        'ORD', 'MID', 'SLEEP', 'IF', 'SELECT', 'IFNULL', 'CAST',
        'FROM', 'WHERE', 'AND', 'OR', 'LIMIT', 'AS', 'NCHAR',
        'INFORMATION_SCHEMA', 'SCHEMATA', 'TABLES', 'COLUMNS',
        'DISTINCT', 'COUNT', 'SCHEMA_NAME', 'TABLE_NAME',
        'COLUMN_NAME', 'COLUMN_TYPE', 'OFFSET', 'NOT', 'NULL',
        'CHAR', 'ASCII', 'SUBSTR', 'SUBSTRING', 'BENCHMARK',
    }
    keywords = [(w, c) for w, c in word_counter.most_common(top_n * 3)
                if w in sql_keywords]
    return [w for w, _ in keywords[:top_n]]


def extract_features(records):
    """Phase 1: 从记录列表中提取结构化特征摘要"""
    total = len(records)
    if total == 0:
        print("[ERROR] 输入数据为空", file=sys.stderr)
        sys.exit(1)

    size_counter = Counter(r['response_size'] for r in records)
    print(f"[INFO] 总记录数: {total}", file=sys.stderr)
    print(f"[INFO] 唯一响应大小数: {len(size_counter)}", file=sys.stderr)

    payloads = [r['payload'] for r in records if isinstance(r.get('payload'), str)]
    ord_mid_count = sum(1 for p in payloads if 'ORD' in p.upper() and 'MID' in p.upper())
    sleep_if_count = sum(1 for p in payloads if 'SLEEP' in p.upper() and 'IF' in p.upper())

    if ord_mid_count > sleep_if_count:
        injection_hint = 'boolean'
    elif sleep_if_count > ord_mid_count:
        injection_hint = 'time'
    else:
        injection_hint = 'unknown'

    print(f"[INFO] 注入类型推断: {injection_hint} "
          f"(ORD/MID:{ord_mid_count}, SLEEP/IF:{sleep_if_count})", file=sys.stderr)

    suggested_judge = _infer_judge_function(size_counter, total, injection_hint)
    print(f"[INFO] 推断 judge_function: {suggested_judge['type']} "
          f"value={suggested_judge['value']}", file=sys.stderr)

    samples = _structural_dedup(records)
    print(f"[INFO] 结构去重: {total}条 → 结构分组 → {len(samples)}条样本送LLM",
          file=sys.stderr)

    keywords = _extract_keywords(payloads)
    print(f"[INFO] 高频SQL关键词: {keywords[:10]}", file=sys.stderr)

    dist = {str(k): v for k, v in size_counter.most_common(20)}

    return {
        'total_records': total,
        'injection_hint': injection_hint,
        'size_stats': {
            'unique_count': len(size_counter),
            'distribution_top20': dist,
            'suggested_judge': suggested_judge
        },
        'keyword_top': keywords,
        'samples': [
            {'payload': r['payload'], 'response_size': r['response_size']}
            for r in samples
        ]
    }


# ── Phase 2: 语义转换 (LLM) ─────────────────────────────────────────────

SYSTEM_PROMPT = """你是 SQL 盲注分析配置专家。根据提供的特征摘要（含响应大小分布和采样 payload），
生成一个完整的 YAML 配置文件，用于 BlindSQL-Recon 的 sqlmap_analyzer.py。

必须返回的 YAML 字段：
  injection_type: "boolean" 或 "time"
  trigger_pattern: payload 中唯一稳定的特征子串（纯文本，非正则，用于 case-insensitive 匹配）
  judge_function: {type: size_equal|size_less|size_greater|size_range, value: <int>}
  patterns:
    from_pattern:       提取 database.table   例 "FROM\\\\s+([\\\\w_]+)\\\\.([\\\\w_]+)"
    cast_pattern:       提取 column           例 "CAST\\\\(([\\\\w_]+)\\\\s+AS"
    limit_pattern:      提取 LIMIT offset     例 "LIMIT\\\\s+(\\\\d+),1"
    position_pattern:   提取字符位置          例 ",(\\\\d+),1\\\\)\\\\)"
    comparison_pattern: 提取运算符和ASCII值   例 "\\\\)\\\\)\\\\s*([<>!]=?)\\\\s*(\\\\d+)"

判断规则：
1. injection_type: 参考 injection_hint（含 ORD/MID → "boolean"；含 SLEEP/IF → "time"）
2. trigger_pattern: 选择所有注入 payload 都出现且稳定的 SQL 函数头：
   - 布尔盲注通常为 "ORD(MID("
   - 时间盲注通常为 "SLEEP(1-(IF("
   - 也可以是 "ORD"、"MID"、"SLEEP" 等，但必须足够唯一
3. judge_function: **直接参考** suggested_judge 的类型和 value
4. patterns: 使用上文示例中的正则（注意 YAML 双反斜杠：每个反斜杠 \\ 写成 \\\\）
   如果 sample payload 的结构与标准 SQLMap 格式不同，可调整正则但保持捕获组个数不变

重要：仅返回 YAML 文本，不包含 markdown 代码块标记（```）、不包含任何解释文字。"""


def build_user_content(feature_summary, errors=None):
    """将特征摘要转换为 LLM 可读的 YAML 输入，可选追加校验错误反馈"""
    user_data = {
        'analysis_goal': '为 BlindSQL-Recon 生成盲注分析器 YAML 配置',
        'feature_summary': {
            'total_records': feature_summary['total_records'],
            'injection_hint': feature_summary['injection_hint'],
            'response_size_stats': feature_summary['size_stats'],
            'keyword_top': feature_summary['keyword_top'],
        },
        'reference_patterns': {
            'from_pattern':      r"FROM\\s+([\\w_]+)\\.([\\w_]+)",
            'cast_pattern':      r"CAST\\(([\\w_]+)\\s+AS",
            'limit_pattern':     r"LIMIT\\s+(\\d+),1",
            'position_pattern':  r",(\\d+),1\\)\\)",
            'comparison_pattern': r"\\)\\)\\s*([<>!]=?)\\s*(\\d+)",
        },
        'sample_payloads': feature_summary['samples'],
    }

    if errors:
        user_data['errors_from_previous_attempt'] = errors

    return yaml.dump(user_data, allow_unicode=True, default_flow_style=False,
                     sort_keys=False, width=200)


def _clean_yaml_response(raw: str) -> str:
    """从 LLM 原始响应中提取纯 YAML：去除 markdown 代码块和前后空白"""
    text = raw.strip()
    fence_patterns = [
        (r'^```ya?ml\s*\n', r'\n```\s*$'),
        (r'^```\s*\n', r'\n```\s*$'),
    ]
    for start_pat, end_pat in fence_patterns:
        if re.match(start_pat, text):
            text = re.sub(start_pat, '', text)
            text = re.sub(end_pat, '', text)
            text = text.strip()
            break
    return text


def call_llm(system_prompt, user_content, max_retries=3):
    """调用 DeepSeek API，返回 LLM 原始响应文本"""
    load_dotenv()
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        print("[ERROR] 未设置 DEEPSEEK_API_KEY 环境变量", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model="deepseek-v4-flash",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                stream=False,
                reasoning_effort="high",
                extra_body={"thinking": {"type": "enabled"}}
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            if attempt < max_retries:
                print(f"[WARN] API请求失败 (尝试{attempt}/{max_retries}): {e}", file=sys.stderr)
                continue
            print(f"[ERROR] API请求失败: {e}", file=sys.stderr)
            sys.exit(1)


# ── Phase 3: 闭环校验 ──────────────────────────────────────────────────

def validate_config(yaml_str, sample_payloads):
    """五级校验链，返回 (通过: bool, 错误列表: [str])"""
    errors = []

    # Level 1: YAML 语法 + 结构完整性
    try:
        config = yaml.safe_load(yaml_str)
    except yaml.YAMLError as e:
        return False, [f"YAML语法错误: {e}"]

    if not isinstance(config, dict):
        return False, ["YAML 解析结果不是字典"]

    required = ['injection_type', 'trigger_pattern', 'judge_function', 'patterns']
    for k in required:
        if k not in config:
            errors.append(f"缺少必需字段: {k}")

    if 'patterns' in config:
        for p in ['from_pattern', 'cast_pattern', 'limit_pattern',
                   'position_pattern', 'comparison_pattern']:
            if p not in config['patterns']:
                errors.append(f"缺少 pattern: {p}")

    # judge_function 有效性（内联校验，避免跨文件 import）
    jf = config.get('judge_function', {})
    jf_type = jf.get('type', '')
    if jf_type not in ('size_equal', 'size_less', 'size_greater', 'size_range'):
        errors.append(f"无效的 judge_function.type: '{jf_type}'")
    elif jf_type == 'size_range':
        if 'min' not in jf or 'max' not in jf:
            errors.append("size_range 类型需要 min 和 max 参数")
    else:
        if 'value' not in jf or not isinstance(jf.get('value'), (int, float)):
            errors.append("judge_function 缺少有效 value")

    if config.get('injection_type') not in ('boolean', 'time'):
        errors.append(f"injection_type 应为 'boolean' 或 'time'，当前为 '{config.get('injection_type')}'")

    if errors:
        return False, errors

    # Level 2: 正则编译测试
    for pname in ['from_pattern', 'cast_pattern', 'limit_pattern',
                   'position_pattern', 'comparison_pattern']:
        pattern = config['patterns'].get(pname, '')
        try:
            re.compile(pattern)
        except re.error as e:
            errors.append(f"正则 '{pname}' 编译失败: {e}")

    if errors:
        return False, errors

    # Level 3: trigger_pattern 匹配率
    trigger = config['trigger_pattern']
    if not trigger:
        errors.append("trigger_pattern 为空")
    else:
        matches = sum(1 for s in sample_payloads
                      if trigger.upper() in s.get('payload', '').upper())
        rate = matches / len(sample_payloads) if sample_payloads else 0
        if rate < 0.5:
            errors.append(
                f"trigger_pattern '{trigger}' 匹配率过低: {rate:.0%} (<50%)，"
                f"请选择更通用的特征子串"
            )

    # Level 4: 提取完备性
    from_re = re.compile(config['patterns']['from_pattern'], re.I)
    cast_re = re.compile(config['patterns']['cast_pattern'], re.I)
    if not any(from_re.search(s.get('payload', '')) and cast_re.search(s.get('payload', ''))
               for s in sample_payloads[:10]):
        errors.append("from_pattern 或 cast_pattern 未能从样本中提取 database/table/column")

    # Level 5: ASCII 有效性
    comp_re = re.compile(config['patterns']['comparison_pattern'], re.I)
    ascii_vals = []
    for s in sample_payloads[:20]:
        m = comp_re.search(s.get('payload', ''))
        if m:
            try:
                ascii_vals.append(int(m.group(2)))
            except (ValueError, IndexError):
                pass
    if ascii_vals:
        out_of_range = sum(1 for v in ascii_vals if v < 32 or v > 126)
        if len(ascii_vals) >= 3 and out_of_range > len(ascii_vals) * 0.5:
            errors.append(
                f"过半 ascii_value 超出 32-126: "
                f"{[v for v in ascii_vals if v < 32 or v > 126][:5]}..."
            )

    return (len(errors) == 0, errors)


def _get_fallback_config():
    """降级策略：返回 analyzer_config.yaml 模板"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'config', 'analyzer_config.yaml')
    try:
        with open(config_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return (
            "injection_type: \"\"\n"
            "trigger_pattern: \"\"\n"
            "judge_function:\n"
            "  type: \"\"\n"
            "  value: 15\n"
            "patterns:\n"
            "  from_pattern: \"\"\n"
            "  cast_pattern: \"\"\n"
            "  limit_pattern: \"\"\n"
            "  position_pattern: \"\"\n"
            "  comparison_pattern: \"\"\n"
        )


def _save_config(yaml_str):
    """保存生成的 YAML 到 config 目录，返回绝对路径"""
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config')
    os.makedirs(config_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    config_path = os.path.join(config_dir, f'ai_generated_{timestamp}.yaml')
    with open(config_path, 'w') as f:
        f.write(yaml_str)
    return os.path.abspath(config_path)


def generate_and_validate(feature_summary):
    """Phase 2+3: LLM 生成 + 闭环校验 + 重试循环，返回配置文件路径"""
    system_prompt = SYSTEM_PROMPT
    user_content_base = build_user_content(feature_summary)
    samples = feature_summary['samples']

    errors = []
    for attempt in range(1, 4):
        if errors:
            error_feedback = build_user_content(feature_summary, errors=errors)
            user_content = error_feedback
        else:
            user_content = user_content_base

        print(f"[INFO] 调用 LLM 生成配置 (尝试 {attempt}/3)...", file=sys.stderr)
        raw = call_llm(system_prompt, user_content)
        yaml_str = _clean_yaml_response(raw)

        print(f"[INFO] 校验生成的配置...", file=sys.stderr)
        valid, errors = validate_config(yaml_str, samples)

        if valid:
            print(f"[INFO] 配置校验通过 ✓", file=sys.stderr)
            config_path = _save_config(yaml_str)
            print(f"[INFO] 配置已保存到: {config_path}", file=sys.stderr)
            return config_path

        print(f"[WARN] 配置校验失败 (尝试 {attempt}/3):", file=sys.stderr)
        for e in errors:
            print(f"[WARN]   - {e}", file=sys.stderr)

    # 降级
    print("[WARN] 全部重试失败，使用降级模板配置", file=sys.stderr)
    fallback = _get_fallback_config()
    config_path = _save_config(fallback)
    print(f"[WARN] 降级模板已保存到: {config_path}", file=sys.stderr)
    return config_path


# ── 主入口 ─────────────────────────────────────────────────────────────

def main():
    all_lines = []
    records = []
    for line in sys.stdin:
        line_stripped = line.rstrip('\n')
        if not line_stripped:
            continue
        all_lines.append(line_stripped)
        try:
            rec = json.loads(line_stripped)
            if isinstance(rec.get('payload'), str) and 'response_size' in rec:
                records.append(rec)
        except json.JSONDecodeError:
            continue

    if not records:
        print("[ERROR] 输入数据无有效记录", file=sys.stderr)
        sys.exit(1)

    features = extract_features(records)
    config_path = generate_and_validate(features)

    sys.stdout.write(json.dumps({"__ai_config__": config_path}) + "\n")
    for line in all_lines:
        sys.stdout.write(line + "\n")
    sys.stdout.flush()


if __name__ == '__main__':
    main()
