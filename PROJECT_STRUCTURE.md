# LLMCheck (KnightCheck) – Project structure

## What this project does

- **Scanner:** Static + optional LLM analysis over Python code to find security issues (SQL/command injection, XSS, crypto, deserialization, etc.).
- **Main app:** `app.py` – KnightCheck Security Analytics (Streamlit): scan files, sandbox, RAG, reports.
- **CLI:** `cli.py` – run scans or open the UI (`knightcheck ui` → runs `app.py`).

## Core layout (what you need)

```
├── app.py                 # Main Streamlit app (KnightCheck Security Analytics)
├── cli.py                 # CLI: knightcheck scan / knightcheck ui
├── src/
│   ├── scanner.py         # Scan orchestration, runs all detectors
│   ├── detectors/         # ~20 detector modules (one per vuln category)
│   ├── analysis/          # Remediation, reachability, taint, sink classification
│   ├── ingestion.py       # Code ingestion
│   └── rag_manager.py     # RAG for app
├── config/
│   └── config.yaml
├── scripts/               # Validation & benchmarking (run from repo root)
│   ├── benchmark_test.py           # OWASP BenchmarkPython accuracy
│   ├── validate_detectors.py       # Bandit examples sanity checks
│   ├── validate_test3_regressions.py
│   └── run_test3_remediation_check.py
├── examples/              # Example vulnerable code (including Test2/Test3 copies)
├── reports/               # Generated scan reports (HTML/JSON)
├── Test2.py, Test3.py     # Primary test files for tuning (also under examples/)
└── PROJECT_STRUCTURE.md   # This file
```

## Optional / external data (can be removed or ignored)

- **BenchmarkPython/** – OWASP benchmark (~2500 files). Used only by `scripts/benchmark_test.py`. Not required for normal use. To run the benchmark, clone it once and run from repo root: `python scripts/benchmark_test.py`.
- **bandit-tests/** – Bandit’s test examples. Used by `scripts/validate_detectors.py`. Keep if you run detector validation; otherwise optional.
- **dvpwa/** – Not referenced by any project code. Safe to remove.
- **semgrep-tests/** – External Semgrep rules/tests. Not used by our scanner. Safe to remove.

If you delete **BenchmarkPython**, **semgrep-tests**, or **dvpwa**, add them to `.gitignore` so they are not re-committed if recreated.

## Two UIs

- **app.py** – Full KnightCheck Security Analytics (default). Run: `streamlit run app.py` or `knightcheck ui`.
- **ui/streamlit_app.py** – Simpler “upload & scan” UI. Run: `streamlit run ui/streamlit_app.py`. Kept as an alternate; main supported UI is `app.py`.

## Running validation / benchmarks

From the **repository root**:

- OWASP benchmark (requires BenchmarkPython):  
  `python scripts/benchmark_test.py`
- Detector checks (requires bandit-tests):  
  `python scripts/validate_detectors.py`
- Test3 regression / remediation:  
  `python scripts/validate_test3_regressions.py`  
  `python scripts/run_test3_remediation_check.py`

## Known accuracy issues (to fix)

The scanner still has known problems; fixing them is the next focus:

- Incomplete SQL/command-injection fixes (params/list form vs. leftover f-strings/command strings).
- Confusing vuln types (e.g. pickle vs YAML).
- False positives: base64 as “Static IV”, non-web code as XSS.
- Poor eval guidance (e.g. literal_eval where it doesn’t fit).
- Duplicate findings, wrong line numbers, vague “Guided remediation required”.
- Misses: some race conditions, CSRF, rate limiting.
- Overly simplistic or wrong remediation; taint/reachability tuning.

Test2.py and Test3.py are the main regression targets when changing detectors or remediation.
