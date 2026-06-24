# AGENTS.md — BlindSQL-Recon

## Architecture

9-script linear pipeline. Directory numeric prefixes match pipe order:

```
1_web_log_parser.py  →  2_param_detector.py  →  3_param_extractor.py
  (parse access.log)     (AI detect param name)    (extract payload by param)
→  url_decoder.py  →  [base64_decoder.py]  →  ai_config_generator.py
   (URL-decode)         (Base64-decode, optional)   (AI generate analyzer config)
→  sqlmap_analyzer.py  →  default_data_reconstructor.py  →  default_report_generator.py
   (pattern-match blind payloads)  (reconstruct chars)    (console + file reports)
```

## Pipeline metadata passing (critical)

Two metadata handoffs in the pipeline:

`2_param_detector.py` → `3_param_extractor.py`:

```json
{"__param_detect__": "username"}
```

`3_param_extractor.py` reads **only the first stdin line** to check for this key. If you insert any pipeline stage between them that modifies stdout, AI detection silently breaks.

`ai_config_generator.py` → `sqlmap_analyzer.py --config auto`:

```json
{"__ai_config__": "3_payload_analyzer/config/ai_generated_<ts>.yaml"}
```

`sqlmap_analyzer.py` with `--config auto` reads the first stdin line for this key and loads config from the referenced file. Generated configs are saved to `3_payload_analyzer/config/`.

## Script concrete names

The file is `sqlmap_analyzer.py`, **not** `3_payload_analyzer.py`. CLI: `python sqlmap_analyzer.py --config <yaml|auto>`.

## Required args

- `sqlmap_analyzer.py`: `--config` is **required** (no default). Options: `<path>` (manual YAML) or `auto` (read from AI generator). Pre-built configs at `3_payload_analyzer/config/test_boolean_config.yaml` and `test_time_config.yaml`.
- `default_report_generator.py`: `-o` defaults to `json`. Options: `json`, `csv`, `txt`, `all`.
- `2_param_detector.py`: `-n` sampling count (default 100).
- `3_param_extractor.py`: `-p` is **optional** with AI mode, **required** without. `-k` keyword filter.

## YAML config regex syntax

Patterns in YAML config use Python regex with YAML double-escaping: `"FROM\\s+([\\w_]+)\\.([\\w_]+)"`. YAML reads `\\` → `\`, so Python regex sees `FROM\s+([\w_]+)\.([\w_]+)`.

## judge_function types

`size_equal` | `size_less` | `size_greater` | `size_range`. For `size_range`, `min` and `max` keys are **both required** or a ValueError is raised.

## Input/output format transitions

| Stage | Input | Output |
|-------|-------|--------|
| 1_web_log_parser | raw log lines | JSON-per-line |
| 2_param_detector | JSON-per-line | metadata + JSON-per-line |
| 3_param_extractor | JSON-per-line | JSON-per-line |
| url_decoder / base64_decoder | JSON-per-line | JSON-per-line |
| ai_config_generator | JSON-per-line | metadata + JSON-per-line |
| sqlmap_analyzer | JSON-per-line | JSON-per-line |
| default_data_reconstructor | JSON-per-line | **single JSON object** |
| default_report_generator | single JSON object | console + files |

`ai_config_generator.py` reads all lines for feature extraction, then outputs `__ai_config__` metadata + pass-through. `sqlmap_analyzer.py --config auto` reads the first line for the metadata key.

The reconstructor is the transition point: it **accumulates all lines** then outputs one JSON document. The report generator reads **all stdin at once** (`json.load(sys.stdin)`).

## stderr convention

**All** scripts write diagnostics/progress/errors to stderr. Only pipeline data goes to stdout. Never mix them.

## AI detector setup

- `2_param_detector.py` and `ai_config_generator.py` both load `DEEPSEEK_API_KEY` from project-root `.env` or CWD `.env`.
- Uses `openai` SDK → DeepSeek API (`deepseek-v4-flash`). Sends `reasoning_effort="high"` and `extra_body={"thinking": {"type": "enabled"}}` — these are **DeepSeek-specific**. Drop them if switching providers.
- Custom `.env` parser (no python-dotenv dependency).

## base64_decoder position

Place `base64_decoder.py` **after** `url_decoder.py` in the pipe. It decodes Base64 → UTF-8. Only needed when payloads are Base64-wrapped (common in time-based attacks).

## Testing

No test framework or CI. Verify by running the full pipe with example logs:

```
cat log_example/bool_access.log | python 1_log_parser/1_web_log_parser.py | python 1_log_parser/2_param_detector.py | python 1_log_parser/3_param_extractor.py | python 2_payload_decoder/url_decoder.py | python 3_payload_analyzer/ai_config_generator.py | python 3_payload_analyzer/sqlmap_analyzer.py --config auto | python 4_data_reconstructor/default_data_reconstructor.py | python 5_report_generator/default_report_generator.py -o txt
```

## Dependencies

```
pip install pyyaml openai
```

Python 3.6+. No setup.py/pyproject.toml.
