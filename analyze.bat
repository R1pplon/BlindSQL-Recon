@echo off
REM Usage: analyze.bat <log_file_path> <query_param>
set LOG_FILE=%1
set QUERY_PARAM=%2
if "%2"=="" (
    echo Error: Query parameter must be specified
    exit /b 1
)
python .\1_log_parser\Apache_log_parser.py -f "%LOG_FILE%" -p "%QUERY_PARAM%" ^
 | python .\2_payload_decoder\url_decoder.py ^
 | python .\2_payload_decoder\base64_decoder.py ^
 | python .\3_payload_analyzer\sqlmap_time_blind_analyzer.py ^
 | python .\4_data_reconstructor\default_data_reconstructor.py ^
 | python .\5_report_generator\default_report_generator.py