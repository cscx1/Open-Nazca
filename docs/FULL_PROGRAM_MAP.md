# Full Program Map: Every Folder and File

What the entire Open Nazca program is doing now. Every folder and file listed with a one-line purpose.

---

## Repository root

| File / folder | Purpose |
|---------------|---------|
| **app.py** | Main UI. Streamlit app (Open Nazca Security Analytics): upload files, run scans, view findings, reports, RAG, sandbox. Run with `streamlit run app.py`. |
| **cli.py** | Command-line interface. `scan <file>`, `scan-dir <dir>`, `ui` (launches app.py). Options: `--snowflake`, `--no-llm`, `--format`. |
| **README.md** | Project overview, quick start, usage, project structure, validation commands. |
| **requirements.txt** | Python dependencies for the project. |
| **setup.py** | Package setup (installable as a package). |
| **setup_snowflake.py** | One-off script to set up Snowflake (tables, etc.) from config/snowflake_schema.sql. |
| **LICENSE** | Project license (e.g. MIT). |
| **.env.example** | Example environment file (Snowflake, optional OpenAI/Anthropic). Copy to `.env` and fill in. |
| **.gitignore** | Ignore patterns: .env, venv, __pycache__, BenchmarkPython, semgrep-tests, dvpwa, bandit-tests, etc. |
| **.streamlit/** | Streamlit config for app.py. |
| **config/** | Configuration and schema. |
| **docs/** | All documentation. |
| **examples/** | Example vulnerable code for demos and manual testing. |
| **scripts/** | Validation and benchmark scripts (not part of the main app). |
| **src/** | All application and scanner source code. |
| **tests/** | Regression samples and (future) unit/integration tests. |
| **reports/** | Generated scan reports (JSON/HTML/MD). Created on demand; may be empty. |
| **knowledge_base/** | RAG index directory used by app.py. May be empty. |
| **temp_scans/** | Temporary scan artifacts if used by app. May be empty. |

---

## .streamlit/

| File | Purpose |
|------|---------|
| **config.toml** | Streamlit UI settings (theme, server options) for app.py. |

---

## config/

| File | Purpose |
|------|---------|
| **config.yaml** | Application configuration (scanner/report/app settings). |
| **snowflake_schema.sql** | Snowflake DDL: tables for code scans, findings, and related data. Run once (or via setup_snowflake.py) to create schema. |

---

## docs/

| File | Purpose |
|------|---------|
| **README.md** | Index of all docs with short descriptions. |
| **CURRENT_PROGRAM_STRUCTURE.md** | Snapshot of “what the program does now”: pipeline, src layout, scripts, no implementation detail. |
| **FULL_PROGRAM_MAP.md** | This file. Every folder and file and what it does. |
| **PROJECT_STRUCTURE.md** | Repo layout, scripts, optional data (BenchmarkPython, bandit-tests), how to run validation. |
| **QUICKSTART.md** | Get running quickly: install, env, run app/CLI. |
| **SNOWFLAKE_SETUP.md** | Snowflake account setup, schema, Cortex, troubleshooting. |
| **ARCHITECTURE.md** | System design, module breakdown, diagrams (ingestion, detectors, LLM, Snowflake, reports). |
| **SUMMARY.md** | One-page project overview (problem, solution, tech stack). |
| **DETECTORS_TECHNICAL_GUIDE.txt** | Detector implementation details and behavior. |
| **OFFENSIVE_SECURITY_ANALYSIS.md** | Security analysis notes (threats, mitigations). |
| **ROADMAP_BEST_IN_CLASS.md** | Why many detectors; plan for verdict layer, attack path, libraries, extensibility. |
| **TESTING_STRATEGY.md** | Unit, integration, benchmark, and regression test layout. |
| **verdict/RULES_ORDER.md** | Verdict rule order, precedence (Unverified does not stop), how to add rules. |

---

## examples/

| File | Purpose |
|------|---------|
| **CodeTester.py** | Mock vulnerable program (API keys, prompt injection, overprivileged config) for testing the scanner. |
| **CodeTester.txt** | Fixture content (obfuscated keys, prompts, config) used with CodeTester or as expected-findings reference. |
| **vulnerable_code/README.md** | Describes the example vulnerable files. |
| **vulnerable_code/example1_prompt_injection.py** | Small demo: prompt injection patterns for scanner demo. |
| **vulnerable_code/example2_hardcoded_secrets.py** | Small demo: hardcoded secrets for scanner demo. |
| **vulnerable_code/example3_overprivileged_tools.py** | Small demo: overprivileged AI tools for scanner demo. |
| **vulnerable_code/SampleTest.py** | Vulnerable chatbot-style examples (prompt injection). |
| **vulnerable_code/addon.py** | Extra example code (vulnerable patterns). |
| **vulnerable_code/Test/StaticAnalysis(SAST).py** | Static analysis / SAST-style example file. |

---

## scripts/

| File | Purpose |
|------|---------|
| **benchmark_test.py** | Runs the scanner on OWASP BenchmarkPython (~1230 cases), computes TP/FP/TN/FN and score. Requires BenchmarkPython/ (clone separately; in .gitignore). |
| **run_test3_remediation_check.py** | Loads tests/regression/Test3.py, runs scanner + remediator, prints suggested fixes and a short comparison note to Test3_remediated_secure.py. |
| **validate_detectors.py** | Runs a subset of detectors on Bandit example files; reports what each finds. Requires bandit-tests/ (in .gitignore). |
| **validate_test3_regressions.py** | Inline code snippets: checks false positives (e.g. safe f-string, base64) and expected behaviors (headers, CSRF, dedup, remediation policy). No external files. |

---

## src/

| File | Purpose |
|------|---------|
| **__init__.py** | Package root. |
| **__main__.py** | Entry for `python -m src <file>`: runs scanner on given file path. |
| **scanner.py** | Main orchestrator. Holds ingestion, detectors, taint_tracker, reachability_verifier, llm_analyzer, snowflake_client, report_generator, rag_manager. Runs the scan pipeline: ingest → detect → taint/reachability → verdict layer → optional LLM → reports. |
| **rag_manager.py** | RAG for app: index documents, retrieve context for LLM. Used by app.py (and optionally by LLM analyzer). |

---

## src/ingestion/

| File | Purpose |
|------|---------|
| **__init__.py** | Exposes CodeIngestion (and what the scanner imports). |
| **code_ingestion.py** | Reads files, detects language, validates size/type, computes hash. Returns file_data (code_content, file_name, language, etc.). Used by scanner and scripts. |

---

## src/detectors/

| File | Purpose |
|------|---------|
| **README.md** | Explains detector categories (injection, crypto, etc.) and how they’re loaded. |
| **__init__.py** | Imports all detector classes and Finding; defines __all__. Scanner imports from here. |
| **base_detector.py** | Abstract base class BaseDetector (name, detect()) and Finding dataclass (severity, line, snippet, reachability fields, etc.). |
| **prompt_injection_detector.py** | Detects unsafe concatenation of user input into AI prompts (f-strings, format, etc.). |
| **hardcoded_secrets_detector.py** | Detects API keys, passwords, tokens in source (regex patterns; masks in output). |
| **overprivileged_tools_detector.py** | Detects dangerous AI agent tool config (delete, exec, etc.). |
| **sql_injection_detector.py** | Pattern-based SQL injection (raw queries, f-strings in execute, etc.). |
| **xss_detector.py** | XSS / template injection (e.g. unescaped output, render_template_string). |
| **ldap_injection_detector.py** | LDAP injection patterns. |
| **xpath_injection_detector.py** | XPath injection patterns. |
| **log_injection_detector.py** | Log injection / CRLF patterns. |
| **deserialization_detector.py** | Unsafe deserialization (pickle, yaml.load, etc.). |
| **xxe_detector.py** | XML External Entity (XXE) patterns. |
| **crypto_misuse_detector.py** | Weak crypto (MD5, static IV, bad ciphers, etc.). |
| **weak_hash_detector.py** | Weak hash usage (MD5, SHA1 for security). |
| **weak_random_detector.py** | Weak randomness (random for secrets). |
| **secure_cookie_detector.py** | Insecure cookie flags (httponly, secure). |
| **trust_boundary_detector.py** | Trust boundary / privilege violations. |
| **general_flow_detector.py** | Data-flow style checks (e.g. request → dangerous use). |
| **unsafe_reflection_detector.py** | Unsafe use of __import__, importlib, etc. |
| **toctou_detector.py** | Time-of-check to time-of-use (e.g. mktemp). |
| **memory_safety_detector.py** | Memory-safety style issues. |
| **type_confusion_detector.py** | Type confusion / unsafe casts. |
| **evasion_patterns_detector.py** | Evasion / obfuscation patterns. |
| **operational_security_detector.py** | Operational issues (debug mode, CSRF, rate limiting, etc.). |
| **vuln_ownership.py** | Helper: “owner” detector per type (not in scanner’s default detector list). |

---

## src/verdict/

| File | Purpose |
|------|---------|
| **__init__.py** | Exposes VerdictEngine, Verdict, FindingWithVerdict, ContextAggregator, FileContext, ProjectContext. |
| **models.py** | Verdict (status, reason), VerdictStatus (Confirmed / Out-of-scope / Unverified), FindingWithVerdict (Finding + Verdict). |
| **engine.py** | ContextAggregator: project signature (requirements/pyproject, urls/views, package.json); file context (imports, is_entry_point, is_test_file, route_path). VerdictEngine: rule precedence (Unverified does not stop; Confirmed/Out-of-scope terminate); optional extra_rules. |
| **rules/__init__.py** | Exposes all verdict rule classes. |
| **rules/base_rule.py** | Abstract BaseVerdictRule: evaluate() → Optional[Verdict]; None = does not apply; stateless. |
| **rules/environment_neutralizer_rule.py** | is_test_file (/tests/, /examples/) → Unverified. |
| **rules/xss_context_rule.py** | XSS: Confirmed only with HTML/JS output context + reachable + entry; Out-of-scope if no web/routing. |
| **rules/sql_sanitizer_rule.py** | SQL Injection + parameterized markers on line → Out-of-scope (runs before Taint). |
| **rules/input_validation_rule.py** | Same-line allowlist/sanitize/validate → Out-of-scope. |
| **rules/taint_reachability_rule.py** | Confirmed Reachable → Confirmed verdict. |
| **rules/pattern_only_fallback_rule.py** | No attack_path and reachability None/Unverifiable → Unverified. |

---

## src/analysis/

| File | Purpose |
|------|---------|
| **__init__.py** | Exposes TaintTracker, SinkClassifier, AttackGraph, ReachabilityVerifier, FunctionalRemediator, and related types. |
| **taint_tracker.py** | AST-based taint: SOURCE_CALLS (input, request.*, etc.), sink list, builds TaintNode and TaintEdge list from Python source. |
| **sink_classifier.py** | Registry of call name → SinkInfo (vulnerability type, CWE, severity). Single source of truth for “this API = this vuln.” |
| **attack_graph.py** | NetworkX graph from taint nodes/edges; enumerates AttackPaths (source → transforms → sink). |
| **reachability.py** | For each attack path, checks lines between source and sink for sanitizers; sets ReachabilityResult status (Confirmed Reachable, Reachability Eliminated, Unverifiable, etc.). |
| **remediator.py** | FunctionalRemediator: takes code + reach_results + findings, suggests fixes (parameterized SQL, list form for shell, yaml.safe_load, etc.), returns fixed code and list of RemediationDiff. |

---

## src/llm_reasoning/

| File | Purpose |
|------|---------|
| **__init__.py** | Exposes LLMAnalyzer. |
| **llm_analyzer.py** | Batch LLM analysis: takes findings, calls Snowflake Cortex or OpenAI/Anthropic for risk_explanation and suggested_fix; returns enriched results. |

---

## src/snowflake_integration/

| File | Purpose |
|------|---------|
| **__init__.py** | Exposes SnowflakeClient. |
| **snowflake_client.py** | Insert code scan, insert finding, update finding with LLM analysis, update scan statistics. Reads credentials from env. |

---

## src/report_generation/

| File | Purpose |
|------|---------|
| **__init__.py** | Exposes ReportGenerator. |
| **report_generator.py** | Generates JSON, HTML, and Markdown reports from scan_data and findings (includes verdict_status, verdict_reason when present); generates console summary. Writes to reports/ (or given path). |

---

## tests/

| File | Purpose |
|------|---------|
| **test_verdict_engine.py** | Standalone tests for verdict layer: pattern-only fallback, taint confirmed, environment neutralizer, SQL sanitizer, XSS out-of-scope, FindingWithVerdict.to_dict(). Run: `python3 tests/test_verdict_engine.py`. |
| **regression/README.md** | Explains Test3.py (vulnerable regression sample) and Test3_remediated_secure.py (reference secure version, hand-written). |
| **regression/Test3.py** | Intentionally vulnerable Python file; regression target for scanner and remediator. |
| **regression/Test3_remediated_secure.py** | Reference “secure” version of Test3 (hand-written). Used for comparison with scanner/remediator output. |

---

## Optional / external (not part of core program)

These are not in the repo or are ignored; the program or scripts reference them optionally.

| Item | Purpose |
|------|---------|
| **BenchmarkPython/** | OWASP Benchmark (Python). Clone separately. Used only by scripts/benchmark_test.py. In .gitignore. |
| **bandit-tests/** | Bandit’s example files. In .gitignore. Used only by scripts/validate_detectors.py. |
| **dvpwa/** | External app (e.g. vulnerable Django app). In .gitignore. Not used by Open Nazca. |
| **semgrep-tests/** | External Semgrep rules/tests. In .gitignore. Not used by Open Nazca. |
| **.env** | Local env (secrets). Copy from .env.example; not committed. |

---

## Data flow (one scan)

1. **User** runs CLI or app → **cli.py** or **app.py**.
2. **AICodeScanner.scan_file(path)** in **scanner.py**:
   - **CodeIngestion** (ingestion) → file_data.
   - Optional: **SnowflakeClient** (snowflake_integration) → scan_id.
   - Each **detector** (detectors/) → list of **Finding**; merged and deduplicated.
   - **TaintTracker** (analysis) → nodes, edges.
   - **AttackGraph** (analysis) → attack paths.
   - **ReachabilityVerifier** (analysis) → status per path.
   - **scanner** enriches findings with reachability and attack_path.
   - **VerdictEngine** (verdict): project/file context, then rules (environment → XSS → SQL sanitizer → taint reachability → pattern fallback) → **FindingWithVerdict** per finding.
   - Optional: **LLMAnalyzer** (llm_reasoning) → risk_explanation, suggested_fix; optional **SnowflakeClient** store.
   - **ReportGenerator** (report_generation) → JSON/HTML/MD and console summary (includes verdict_status, verdict_reason).
3. Result returned to CLI or app (findings with verdict, attack_paths, reachability).
