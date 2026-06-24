#!/usr/bin/env python3
"""BlindSQL-Recon: SQL盲注重建全自动管道入口"""

import sys
import os
import subprocess
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve(relpath):
    return os.path.join(SCRIPT_DIR, relpath)


def main():
    parser = argparse.ArgumentParser(
        description="BlindSQL-Recon — SQL 盲注重建全自动管道",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python main.py log_example/bool_access.log
  python main.py log_example/time_access.log --decode url base64
  python main.py access.log --decode url base64 -o csv
  python main.py access.log -k "GET /search" -n 50 -o all""",
    )
    parser.add_argument("log_file", help="原始日志文件路径")
    parser.add_argument(
        "--decode",
        nargs="+",
        default=["url"],
        metavar="NAME",
        help="解码器名称序列，匹配 2_payload_decoder/<name>_decoder.py (默认: url)",
    )
    parser.add_argument(
        "-k",
        "--keyword",
        default=None,
        help="关键词过滤，仅提取包含该关键词的行",
    )
    parser.add_argument(
        "-n",
        "--samples",
        type=int,
        default=100,
        help="AI 参数检测采样数量 (默认: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "csv", "txt", "all"],
        default="txt",
        help="报告输出格式 (默认: txt)",
    )

    args = parser.parse_args()

    python = sys.executable

    def script(relpath):
        abspath = resolve(relpath)
        return f"'{python}' '{abspath}'"

    stages = []

    stages.append(f"cat '{args.log_file}'")
    stages.append(script("1_log_parser/1_web_log_parser.py"))
    stages.append(script("1_log_parser/2_param_detector.py") + f" -n {args.samples}")

    extractor_cmd = script("1_log_parser/3_param_extractor.py")
    if args.keyword:
        extractor_cmd += f" -k '{args.keyword}'"
    stages.append(extractor_cmd)

    for name in args.decode:
        decoder_path = f"2_payload_decoder/{name}_decoder.py"
        if not os.path.exists(resolve(decoder_path)):
            print(
                f"[ERROR] 解码器不存在: {decoder_path}",
                file=sys.stderr,
            )
            sys.exit(1)
        stages.append(script(decoder_path))

    stages.append(script("3_payload_analyzer/ai_config_generator.py"))
    stages.append(script("3_payload_analyzer/sqlmap_analyzer.py") + " --config auto")
    stages.append(script("4_data_reconstructor/default_data_reconstructor.py"))
    stages.append(
        script("5_report_generator/default_report_generator.py") + f" -o {args.output}"
    )

    pipeline = " | ".join(stages)
    # print(f"[INFO] 管道: {pipeline}", file=sys.stderr)

    proc = subprocess.run(pipeline, shell=True)
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
