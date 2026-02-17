# Architecture — Open Nazca

This document describes the system architecture for **Open Nazca**: a security scanner that ingests code, runs pattern-based and flow-based detectors, applies a verdict layer, optionally enriches findings with an LLM, and produces reports. For a file-by-file map of the repo, see [FULL_PROGRAM_MAP.md](FULL_PROGRAM_MAP.md).

## System architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          User interface                                  │
│  ┌─────────────────┐  ┌─────────────────┐                              │
│  │ Streamlit (app)  │  │ CLI (cli.py)    │  → scan, scan-dir, ui        │
│  │ Open Nazca UI   │  │ --snowflake,    │                              │
│  └────────┬────────┘  │ --no-llm, etc.  │                              │
│           └───────────┴────────┬────────┘                              │
└────────────────────────────────┼────────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Scanner orchestrator (src/scanner.py)                 │
│  AICodeScanner: ingestion → detect → taint → verdict → LLM → reports     │
└──┬──────────┬──────────┬──────────┬──────────┬──────────┬───────────────┘
   │          │          │          │          │          │
   ▼          ▼          ▼          ▼          ▼          ▼
┌──────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────┐ ┌──────────────┐
│Ingest│ │Detectors│ │ Analysis│ │ Verdict │ │ LLM  │ │ Snowflake    │
│      │ │(pattern)│ │(taint,  │ │(rules)  │ │(opt) │ │(optional)    │
│      │ │         │ │ paths)  │ │         │ │      │ │              │
└──┬───┘ └────┬────┘ └────┬────┘ └────┬────┘ └──┬───┘ └──────┬───────┘
   │          │           │           │          │            │
   └──────────┴───────────┴───────────┴──────────┴────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  Report generation     │
                    │  JSON / HTML / MD      │
                    │  (verdict in output)   │
                    └────────────────────────┘
```

## Scan pipeline (one file)

1. **Ingestion** (`src/ingestion/`) — Read file, detect language, validate size/type, compute hash → `file_data`.
2. **Optional Snowflake** — Insert code scan row → `scan_id`.
3. **Detection** (`src/detectors/`) — All detectors run; findings merged and deduplicated.
4. **Analysis** (`src/analysis/`) — TaintTracker → nodes/edges; AttackGraph → attack paths; ReachabilityVerifier → status per path. Findings enriched with `reachability` and `attack_path`.
5. **Verdict** (`src/verdict/`) — Project/file context (ContextAggregator), then VerdictEngine runs rules in order → each finding gets a Verdict (Confirmed / Out-of-scope / Unverified).
6. **Optional LLM** (`src/llm_reasoning/`) — Batch analysis for `risk_explanation` and `suggested_fix` (Snowflake Cortex or OpenAI/Anthropic). Optional Snowflake update of findings.
7. **Reports** (`src/report_generation/`) — JSON, HTML, Markdown (and console summary), including `verdict_status` and `verdict_reason`.

## Module breakdown

### 1. Ingestion (`src/ingestion/`)

- **CodeIngestion**: Reads files, detects language, validates size/type, handles UTF-8 and fallback encoding, computes hash.
- Output: `file_data` (code_content, file_name, language, etc.) for the scanner and scripts.

### 2. Detectors (`src/detectors/`)

- **Base**: `BaseDetector` (abstract), `Finding` dataclass (severity, line, snippet, reachability-related fields).
- **Pattern-based detectors** (examples): prompt injection, hardcoded secrets, overprivileged tools, SQL/XSS/LDAP/XPath/log injection, deserialization, XXE, crypto misuse, weak hash/random, secure cookie, trust boundary, general flow, unsafe reflection, TOCTOU, memory-safety, type confusion, evasion patterns, operational security.
- Detectors are loaded from this package; scanner runs them and merges/dedupes findings. See `src/detectors/README.md` for categories and loading.

### 3. Analysis (`src/analysis/`)

- **TaintTracker**: AST-based taint; SOURCE_CALLS (e.g. input, request.*) and sinks; builds TaintNode/TaintEdge list.
- **SinkClassifier**: Registry of call name → SinkInfo (vulnerability type, CWE, severity).
- **AttackGraph**: NetworkX graph from taint nodes/edges; enumerates attack paths (source → transforms → sink).
- **ReachabilityVerifier**: For each path, checks for sanitizers between source and sink; sets ReachabilityResult (e.g. Confirmed Reachable, Reachability Eliminated, Unverifiable).
- **Remediator**: FunctionalRemediator — takes code, reach results, findings; suggests fixes (parameterized SQL, safe YAML, etc.); returns fixed code and RemediationDiff list.

### 4. Verdict (`src/verdict/`)

- **Models**: Verdict (status, reason), VerdictStatus (Confirmed / Out-of-scope / Unverified), FindingWithVerdict (Finding + Verdict).
- **ContextAggregator**: Project signature (e.g. requirements, urls/views, package.json); per-file context (imports, is_entry_point, is_test_file, route_path).
- **VerdictEngine**: Applies rules in precedence order. Unverified does not stop; Confirmed or Out-of-scope can terminate. Optional extra_rules.
- **Rules** (examples): environment_neutralizer (test/examples → Unverified), xss_context (HTML/JS + reachable + entry → Confirmed; no web → Out-of-scope), sql_sanitizer (parameterized markers → Out-of-scope), input_validation (allowlist/sanitize on same line → Out-of-scope), taint_reachability (Reachable → Confirmed), pattern_only_fallback (no attack_path / reachability None or Unverifiable → Unverified). See `verdict/RULES_ORDER.md` for order and how to add rules.

### 5. LLM reasoning (`src/llm_reasoning/`)

- **LLMAnalyzer**: Batch analysis of findings; calls Snowflake Cortex or OpenAI/Anthropic for `risk_explanation` and `suggested_fix`; returns enriched results. Optional; scanner works with `--no-llm`.

### 6. Snowflake integration (`src/snowflake_integration/`)

- **SnowflakeClient**: Insert code scan, insert finding, update finding with LLM fields, update scan statistics. Credentials from env. See [SNOWFLAKE_SETUP.md](SNOWFLAKE_SETUP.md).

### 7. Report generation (`src/report_generation/`)

- **ReportGenerator**: Builds JSON, HTML, and Markdown from scan_data and findings (including `verdict_status`, `verdict_reason` when present); writes to `reports/` or given path; console summary as well.

### 8. RAG (`src/rag_manager.py`)

- Used by the Streamlit app: index documents, retrieve context for LLM. Optional for the analyzer.

## Data flow (single scan)

```
User → CLI or app.py
  → AICodeScanner.scan_file(path)
    → CodeIngestion → file_data
    → [optional] SnowflakeClient → scan_id
    → detectors → list of Finding (merged, deduped)
    → TaintTracker → nodes, edges
    → AttackGraph → attack paths
    → ReachabilityVerifier → status per path
    → enrich findings (reachability, attack_path)
    → VerdictEngine (context + rules) → FindingWithVerdict per finding
    → [optional] LLMAnalyzer → risk_explanation, suggested_fix; [optional] SnowflakeClient
    → ReportGenerator → JSON/HTML/MD + console (with verdict_status, verdict_reason)
  → results + report paths
```

## Design decisions

- **Modular pipeline**: Ingestion, detection, analysis, verdict, LLM, and reporting are separate so you can add detectors, change rules, or swap LLM/storage.
- **Optional Snowflake and LLM**: Scanner runs without Snowflake or API keys; use `--snowflake` and enable LLM when needed.
- **Verdict before LLM**: Rules reduce noise (Out-of-scope/Unverified) before expensive LLM calls.
- **Single scanner entry**: All flow is coordinated in `src/scanner.py`; CLI and app both call the same scanner.

## Technology

- **Python**: Security tooling, LLM and Snowflake SDKs, fast iteration.
- **Snowflake**: Analytics, schema in `config/snowflake_schema.sql`; see SNOWFLAKE_SETUP.md.
- **Streamlit**: Open Nazca Security Analytics UI (app.py); RAG, sandbox, report viewing.

For a complete list of every folder and file, see [FULL_PROGRAM_MAP.md](FULL_PROGRAM_MAP.md).
