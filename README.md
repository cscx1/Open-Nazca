# Open Nazca

Open Nazca is a security scanner for code. It reads your files, runs a set of detectors for common vulnerabilities (prompt injection, hardcoded secrets, SQL injection, XSS, weak crypto, and others), uses taint analysis to see if findings are actually reachable, then applies a verdict layer so you get Confirmed, Out-of-scope, or Unverified for each finding. You can optionally send findings to an LLM (Snowflake Cortex, OpenAI, or Anthropic) for plain-language explanations and fix suggestions, and optionally store scans and results in Snowflake. Reports come out as JSON, HTML, or Markdown.

You can run it from the command line, from a Streamlit web app (Open Nazca Security Analytics), or by calling the scanner from Python.

## Quick start

**Requirements:** Python 3.8+

```bash
git clone https://github.com/cscx1/Open-Nazca.git
cd Open-Nazca
pip install -r requirements.txt
cp .env.example .env
# Edit .env with Snowflake credentials (and optional OpenAI/Anthropic keys)
```

**Run the web UI:**

```bash
streamlit run app.py
```

Then open http://localhost:8501. You can upload files and run scans from there.

**Run from the command line:**

```bash
# Scan a file (no Snowflake, no LLM — works out of the box)
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --no-llm

# Scan with Snowflake and LLM analysis
python cli.py scan myfile.py --snowflake

# Scan a directory
python cli.py scan-dir ./myproject --recursive --snowflake
```

Snowflake is optional. For full setup (schema, Cortex, etc.), see [docs/SNOWFLAKE_SETUP.md](docs/SNOWFLAKE_SETUP.md).

## What it does

1. **Ingestion** — Reads your file, detects language, validates size and type.
2. **Detection** — Pattern-based detectors look for prompt injection, hardcoded secrets, overprivileged AI tools, SQL/XSS/ldap/xpath injection, deserialization, weak crypto, insecure cookies, and more. Findings are merged and deduplicated.
3. **Analysis** — Taint tracking and attack graphs figure out whether user-controlled data can reach dangerous sinks. Reachability is checked (e.g. sanitizers on the path).
4. **Verdict** — Each finding gets a verdict: Confirmed (exploitable), Out-of-scope (e.g. already sanitized or not in a web context), or Unverified (pattern-only, not confirmed by flow).
5. **LLM (optional)** — Findings can be sent to Snowflake Cortex or OpenAI/Anthropic for risk explanations and suggested fixes.
6. **Reports** — JSON, HTML, and Markdown reports (and a console summary) including verdict and, when used, LLM output.

So you get a list of issues with a clear verdict and optional human-readable explanation and fix suggestions.

## Usage

**CLI:**

- `python cli.py scan <file>` — scan one file  
- `python cli.py scan-dir <dir>` — scan a directory (use `--recursive` for subdirs)  
- `python cli.py ui` — launch the Streamlit app  

Options: `--snowflake` to use Snowflake, `--no-llm` to skip LLM analysis, `--format html markdown` for report formats.

**Python API:**

```python
from src.scanner import AICodeScanner

with AICodeScanner(use_snowflake=False, use_llm_analysis=False) as scanner:
    results = scanner.scan_file("path/to/code.py")
# results contain findings, verdicts, attack paths, etc.
```

## Project layout

- **app.py** — Streamlit UI (Open Nazca Security Analytics).  
- **cli.py** — Command-line interface.  
- **src/scanner.py** — Orchestrates the full pipeline (ingestion → detectors → taint → verdict → optional LLM → reports).  
- **src/ingestion/** — File reading, language detection.  
- **src/detectors/** — All vulnerability detectors (prompt injection, secrets, SQL, XSS, crypto, etc.).  
- **src/analysis/** — Taint tracking, attack graph, reachability, remediator.  
- **src/verdict/** — Verdict engine and rules (Confirmed / Out-of-scope / Unverified).  
- **src/llm_reasoning/** — LLM analysis (Cortex, OpenAI, Anthropic).  
- **src/snowflake_integration/** — Store scans and findings in Snowflake.  
- **src/report_generation/** — JSON, HTML, Markdown reports.  
- **config/** — config.yaml, snowflake_schema.sql.  
- **examples/vulnerable_code/** — Example vulnerable files for testing.  
- **scripts/** — Validation and benchmark scripts (see below).  
- **docs/** — [FULL_PROGRAM_MAP.md](docs/FULL_PROGRAM_MAP.md) (every file and what it does), [ARCHITECTURE.md](docs/ARCHITECTURE.md), [SNOWFLAKE_SETUP.md](docs/SNOWFLAKE_SETUP.md), and more.

For a complete file-by-file map, see [docs/FULL_PROGRAM_MAP.md](docs/FULL_PROGRAM_MAP.md).

## Testing and validation

Try the example files:

```bash
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --no-llm
python cli.py scan examples/vulnerable_code/example2_hardcoded_secrets.py --no-llm
python cli.py scan examples/vulnerable_code/example3_overprivileged_tools.py --no-llm
```

From the repo root you can also run:

- `python scripts/validate_test3_regressions.py` — regression tests (no extra setup).  
- `python scripts/run_test3_remediation_check.py` — compare scanner remediator output to the reference secure file.  
- `python scripts/validate_detectors.py` — detector checks (requires bandit-tests/).  
- `python scripts/benchmark_test.py` — OWASP Benchmark run (requires BenchmarkPython/).

## Security and use

The tool only reads and analyzes code; it does not execute it. Use it on your own code, in code review, or in CI. Do not use it to generate exploits or to scan systems you are not authorized to test.

## License

MIT. See the LICENSE file.
