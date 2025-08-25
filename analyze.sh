#!/bin/bash
# Usage: ./analyze.sh <log_file_path> <query_param>

if [ $# -lt 2 ]; then
    echo "Error: Both log file path and query parameter must be specified"
    exit 1
fi

LOG_FILE="$1"
QUERY_PARAM="$2"

python ./1_log_parser/Apache_log_parser.py -f "$LOG_FILE" -p "$QUERY_PARAM" \
    | python ./2_payload_decoder/url_decoder.py \
    | python ./2_payload_decoder/base64_decoder.py \
    | python ./3_payload_analyzer/sqlmap_time_blind_analyzer.py \
    | python ./4_data_reconstructor/default_data_reconstructor.py \
    | python ./5_report_generator/default_report_generator.py