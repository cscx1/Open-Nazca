# Open Nazca

Security scanner for source code: pattern-based detection, taint analysis for reachability, and a verdict layer (Confirmed / Out-of-scope / Unverified). Optional LLM analysis and Snowflake storage. Reports in JSON, HTML, or Markdown.

Run via CLI, Streamlit UI, or Python API.

---

## Quick start

**Requirements:** Python 3.8+

```bash
git clone https://github.com/cscx1/Open-Nazca.git
cd Open-Nazca
pip install -r requirements.txt
cp .env.example .env
# Edit .env if using Snowflake or LLM (OpenAI/Anthropic)
```

**Web UI:**

```bash
streamlit run app.py
```

Open http://localhost:8501 to upload files and run scans.

**CLI:**

```bash
# Single file (no Snowflake, no LLM)
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --no-llm

# With Snowflake and LLM
python cli.py scan myfile.py --snowflake

# Directory
python cli.py scan-dir ./myproject --recursive --snowflake
```

Snowflake setup: [docs/SNOWFLAKE_SETUP.md](docs/SNOWFLAKE_SETUP.md).

---

## Pipeline

1. **Ingestion** — Read file, detect language (by extension), validate.
2. **Detection** — Regex/pattern detectors (prompt injection, secrets, SQL/XSS/other injection, weak crypto, etc.). Output: findings list.
3. **Analysis** (Python only) — AST taint tracking → attack graph → path enumeration → reachability (sanitizer check along paths).
4. **Merge** — Enrich detector findings with attack paths and reachability; add AST-only findings.
5. **Verdict** — Classify each finding: Confirmed, Out-of-scope, or Unverified using context rules.
6. **Optional** — LLM (risk/fix text), Snowflake storage, reports.

---

## Usage

| Command | Description |
|--------|-------------|
| `python cli.py scan <file>` | Scan one file |
| `python cli.py scan-dir <dir>` | Scan directory (`--recursive` for subdirs) |
| `python cli.py ui` | Launch Streamlit app |

Options: `--snowflake`, `--no-llm`, `--format html markdown`.

**Python API:**

```python
from src.scanner import AICodeScanner

with AICodeScanner(use_snowflake=False, use_llm_analysis=False) as scanner:
    results = scanner.scan_file("path/to/code.py")
```

---

## Project layout

| Path | Purpose |
|------|--------|
| `app.py` | Streamlit UI |
| `cli.py` | CLI entrypoint |
| `src/scanner.py` | Pipeline orchestrator |
| `src/ingestion/` | File read, language detection |
| `src/detectors/` | Pattern-based detectors |
| `src/analysis/` | Taint tracker, attack graph, reachability, remediator |
| `src/verdict/` | Verdict engine and rules |
| `src/llm_reasoning/` | LLM analysis (Cortex, OpenAI, Anthropic) |
| `src/snowflake_integration/` | Scan/finding storage |
| `src/report_generation/` | JSON / HTML / Markdown reports |
| `config/` | config.yaml, Snowflake schema |
| `docs/` | [ARCHITECTURE.md](docs/ARCHITECTURE.md), [FULL_PROGRAM_MAP.md](docs/FULL_PROGRAM_MAP.md), [SNOWFLAKE_SETUP.md](docs/SNOWFLAKE_SETUP.md) |

---

## Testing

Example scans:

```bash
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --no-llm
python cli.py scan examples/vulnerable_code/example2_hardcoded_secrets.py --no-llm
```

Scripts (from repo root):

- `python scripts/validate_test3_regressions.py` — regression tests
- `python scripts/run_test3_remediation_check.py` — remediator vs reference
- `python scripts/validate_detectors.py` — detector checks (needs bandit-tests/)
- `python scripts/benchmark_test.py` — OWASP Benchmark (needs BenchmarkPython/)

---

## Security and use

The scanner only reads and analyzes code; it does not execute it. Use on your own code, in review or CI. Do not use to generate exploits or to scan systems without authorization.

---

## License

MIT. See [LICENSE](LICENSE).
