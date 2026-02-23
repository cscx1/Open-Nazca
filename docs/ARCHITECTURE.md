# Architecture — Open Nazca

This document describes the system architecture for **Open Nazca**: a security scanner that ingests code, runs pattern-based and flow-based detectors, applies a verdict layer, optionally enriches findings with an LLM, and produces reports. For a file-by-file map of the repo, see [FULL_PROGRAM_MAP.md](FULL_PROGRAM_MAP.md).

---

## What we changed (analysis pipeline)

We extended the scanner from **pattern-only detection** to **flow-based analysis** so we can prove whether a finding is actually exploitable.

**Before:** Detectors ran regex/pattern checks and produced a list of findings. There was no proof that user input actually reached the dangerous code.

**After:** For each Python file we now:

1. **Taint tracking** — Parse the AST and build a data-flow graph: where does user input (sources) go, and does it ever reach dangerous APIs (sinks)?
2. **Attack-path enumeration** — Use a NetworkX graph to list every path from source → sink (path enumeration).
3. **Reachability verification** — For each path, check if a sanitizer (e.g. parameterized query, `html.escape`) breaks the chain; classify as Confirmed Reachable, Reachability Eliminated, Unverifiable, or Requires Manual Review.
4. **Enrichment** — Attach this evidence to findings (attack_path, reachability_status) so reports and the verdict layer can use it.
5. **Remediation (Sandbox Lab only)** — Apply rule-based code fixes and re-run the same pipeline to prove paths were eliminated (blast radius reduction).

**Concrete additions:**

- **`src/analysis/taint_tracker.py`** — AST visitor that identifies sources (e.g. `request.form`, `input()`), tracks taint through assignments/f-strings/concatenation/function args, and identifies sinks (e.g. `cursor.execute()`, `eval()`). Output: list of `TaintNode` and `TaintEdge`.
- **`src/analysis/attack_graph.py`** — Builds a directed graph from those nodes/edges and runs `nx.all_simple_paths(source, sink)` to enumerate attack paths; supports `AttackGraph.compare(before, after)` for before/after remediation.
- **`src/analysis/reachability.py`** — For each attack path, inspects the code along the path for known sanitizers and parameterized patterns; assigns a trust-gradient status.
- **`src/analysis/sink_classifier.py`** — Maps API names (e.g. `cursor.execute`) to vulnerability type, CWE, severity (single source of truth for sink classification).
- **`src/analysis/remediator.py`** — Generates functional code fixes (parameterized SQL, `subprocess.run(shell=False)`, env vars for secrets, etc.) and rejects comment-only changes.

**Flow change in the scanner:** After pattern detection and deduplication, we run the analysis pipeline (taint → graph → reachability), enrich findings with `reachability_status` and `attack_path`, then pass the enriched findings into the verdict layer and LLM. Reports and Snowflake now include attack paths and reachability. The Sandbox Lab in the Streamlit app runs the full pipeline twice (before and after fixes) and uses the same math (set comparison of paths, percentage reduction) to show blast radius and confidence.

---

## What is taint tracking?

**Taint tracking** is static analysis that answers: *“Does any user-controlled (untrusted) data ever reach a security-sensitive operation?”*

- **Source** — A place where untrusted data enters the program (e.g. `request.form['id']`, `input()`, `sys.argv`, function parameters we treat as untrusted).
- **Sink** — A dangerous API that must not receive untrusted data without sanitization (e.g. `cursor.execute()` for SQL, `eval()`, `subprocess.run()`, `open()`, LLM API calls).
- **Propagation** — How taint moves: assignments (`x = request.form['id']`), f-strings (`f"SELECT * FROM {x}"`), string concatenation, and passing variables as function arguments. Our implementation tracks these via an AST visitor: when we see an expression that references a tainted variable, we record an edge from the node that produced the taint to the node that consumes it.

We do **not** execute code; we only parse the Python AST and build a graph of “this value flows into that one.” The result is a list of **nodes** (sources, transforms, sinks) and **edges** (data flow). That graph is then used by the attack graph to enumerate all source→sink paths and by the reachability verifier to classify each path. So: **taint tracking is the step that builds the data-flow graph; path enumeration and reachability use that graph to prove (or disprove) exploitability.**

---

## System architecture

### Pipeline diagram (high level)

One code file (path + contents) enters; language is inferred from file extension only (`src/ingestion/code_ingestion.py`). Two pipelines run on the same file; their results are merged, then verdict/LLM/reports run on the combined list.

```
                    ┌─────────────────────────────────────┐
                    │  Input: file path + file contents    │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │  INGESTION                          │
                    │  Read file, validate, language by   │
                    │  extension only                     │
                    └─────────────────┬───────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         │                            │                            │
         ▼                            │                            ▼
┌────────────────────┐               │               ┌────────────────────────────┐
│  PIPELINE A         │               │               │  PIPELINE B (Python only)   │
│  Detectors         │               │               │  AST analysis               │
│  src/detectors/    │               │               │  src/analysis/              │
│                    │               │               │                             │
│  • Raw file text   │               │               │  • parse → taint_tracker    │
│  • Regex/patterns  │               │               │  • build attack_graph        │
│  • All languages   │               │               │  • enumerate paths          │
│  • No data flow    │               │               │  • reachability (sanitizer  │
│                    │               │               │    check in path slice)    │
└─────────┬──────────┘               │               └─────────────┬──────────────┘
          │                          │                             │
          │  List A (findings)       │       Paths + reachability   │
          │  line, type, severity,   │       per path (no findings  │
          │  snippet, etc.           │       list yet)              │
          │                          │                             │
          └──────────────────────────┼─────────────────────────────┘
                                     │
                    ┌────────────────▼───────────────────┐
                    │  MERGE (scanner.py)                │
                    │  _enrich_findings_with_analysis     │
                    │  • Index A by line → line_to_findings
                    │  • For each path (B): match finding │
                    │    by line: sink+type → sink →      │
                    │    transform → source               │
                    │  • Attach attack_path, reachability,│
                    │    sink_api; or add AST-only finding│
                    │  • Deduplicate (line + type)       │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │  Single findings list               │
                    │  (detector-only + enriched + AST-only)
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │  VERDICT → optional LLM → REPORTS   │
                    │  (rules)        (risk/fix)  / Snowflake
                    └─────────────────────────────────────┘
```

**Definitions (for the diagram):**

- **Source** — Place where data is treated as user-controlled (from hardcoded list: e.g. `request.form`, `input()`).
- **Sink** — Dangerous API from list (e.g. `cursor.execute`, `eval()`).
- **Tainted** — Variable recorded in `tainted_vars` as coming from a source or from something already tainted.
- **Edge** — “Value flows from node A to node B”; added only when the AST shows it (same assignment or same variable name across lines).
- **Path** — Sequence of nodes from a source to a sink connected by edges (enumerated by the graph algorithm).
- **Sanitizer check** — String search in the code between source and sink lines for hardcoded sanitizer strings; if found → Reachability Eliminated.

---

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

## Scan pipeline (one file) — exact flow

For each file, the scanner runs in this order:

1. **Ingestion** (`src/ingestion/`) — Read file, detect language, validate size/type, compute hash → `file_data`.
2. **Optional Snowflake** — Insert code scan row → `scan_id`.
3. **Detection** (`src/detectors/`) — All enabled detectors run on `file_data['code_content']`; findings are merged and deduplicated → `all_findings`.
4. **Analysis** (`src/analysis/`) — **Only for Python.**  
   - **TaintTracker.analyse(file_name, code_content)** → `nodes`, `edges` (sources, transforms, sinks and the data-flow edges between them).  
   - **AttackGraph**: build graph from `nodes`/`edges`, then **enumerate all simple paths** from every source to every sink → `attack_paths`.  
   - **ReachabilityVerifier.verify_paths(attack_paths, code_content, file_name)** → for each path, check for sanitizers/parameterized patterns and set status (Confirmed Reachable / Reachability Eliminated / Unverifiable / Requires Manual Review).  
   - **Enrich** `all_findings`: attach `reachability_status`, `attack_path`, and sink classification to matching findings; add new findings for paths that pattern detectors did not report.  
   - Deduplicate again.
5. **Verdict** (`src/verdict/`) — ContextAggregator gathers project/file context; VerdictEngine runs rules (e.g. taint_reachability, sql_sanitizer) → each finding gets a Verdict (Confirmed / Out-of-scope / Unverified) → `verdicted` (list of FindingWithVerdict).
6. **Optional LLM** (`src/llm_reasoning/`) — Batch analyze the underlying findings for `risk_explanation` and `suggested_fix` (Snowflake Cortex or OpenAI/Anthropic); store in Snowflake and in finding metadata.
7. **Reports** (`src/report_generation/`) — Build JSON, HTML, Markdown (and console summary) from `scan_data` and `findings_dicts` (including verdict, reachability, attack_path, LLM fields).

So: **ingest → detect (pattern) → taint → graph → reachability → enrich → verdict → LLM (optional) → reports.** Taint tracking is the step that produces the data-flow graph; the graph is then used for path enumeration and reachability.

## Module breakdown

### 1. Ingestion (`src/ingestion/`)

- **CodeIngestion**: Reads files, detects language, validates size/type, handles UTF-8 and fallback encoding, computes hash.
- Output: `file_data` (code_content, file_name, language, etc.) for the scanner and scripts.

### 2. Detectors (`src/detectors/`)

- **Base**: `BaseDetector` (abstract), `Finding` dataclass (severity, line, snippet, reachability-related fields).
- **Pattern-based detectors** (examples): prompt injection, hardcoded secrets, overprivileged tools, SQL/XSS/LDAP/XPath/log injection, deserialization, XXE, crypto misuse, weak hash/random, secure cookie, trust boundary, general flow, unsafe reflection, TOCTOU, memory-safety, type confusion, evasion patterns, operational security.
- Detectors are loaded from this package; scanner runs them and merges/dedupes findings. See `src/detectors/README.md` for categories and loading.

### 3. Analysis (`src/analysis/`)

- **TaintTracker** (taint tracking): Parses Python AST; identifies SOURCE_CALLS (e.g. `input`, `request.form.get`) and SOURCE_SUBSCRIPTS; tracks taint through assignments, f-strings, concatenation, and function arguments; identifies sinks via `_QUICK_SINK_NAMES`. Builds and returns a list of **TaintNode** (source/transform/sink) and **TaintEdge** (data flow). Single-file only; no cross-file flow.
- **SinkClassifier**: Registry of call name → SinkInfo (vulnerability type, CWE, severity). Used by AttackGraph for library-accurate classification of each path.
- **AttackGraph**: Builds a NetworkX directed graph from taint nodes/edges; enumerates all simple paths from every source to every sink (`nx.all_simple_paths`, cutoff=15); wraps each path as an AttackPath with SinkClassifier info. Provides `compare(before_paths, after_paths)` for eliminated/remaining/introduced paths.
- **ReachabilityVerifier**: For each attack path, inspects the code along the path for known sanitizers (per vulnerability type) and parameterized-query patterns; assigns ReachabilityStatus (Confirmed Reachable, Reachability Eliminated, Unverifiable, Requires Manual Review).
- **Remediator** (FunctionalRemediator): Takes source code and reachability results; for Confirmed Reachable paths, applies fix strategies (e.g. parameterized SQL, `subprocess.run(shell=False)`, env vars for secrets); validates that each change is functional (not comment-only). Returns fixed code and list of RemediationDiff. Used in the Sandbox Lab to generate and verify fixes.

### 4. Verdict (`src/verdict/`) and rules (`src/verdict/rules/`)

**What the verdict and rules folder are for**

The **verdict layer** turns the raw list of findings (from detectors + AST enrichment) into a **final classification** for each finding: **Confirmed**, **Out-of-scope**, or **Unverified**. It runs *after* merge and *before* optional LLM and reports. Its job is to cut false positives and prioritize real issues using context (project type, file role, reachability, and same-line mitigations).

- **Verdict** = one of three outcomes plus a short reason string. It is stored on each finding (e.g. in reports as `verdict_status` and `verdict_reason`).
- **Rules** = small, stateless functions that look at a single finding plus **file context** (imports, whether the file is a test, entry point, route) and **project context** (web app vs library, presence of framework files). Each rule either returns a Verdict (Confirmed / Out-of-scope / Unverified) or `None` (“does not apply”). The engine runs rules in a **fixed order**; only **Confirmed** or **Out-of-scope** stop evaluation—**Unverified** does not, so a later rule can still confirm or scope out the finding.

So: **verdict** = the classification result; **rules** = the logic that produces that classification from context and finding fields (e.g. `reachability_status`, `attack_path`, line content, project/file flags).

**Rule order (critical):** Environment (test/examples) → XSS context → SQL sanitizer → Input validation → Taint reachability → Pattern-only fallback. SQL sanitizer must run before taint reachability so parameterized queries get Out-of-scope instead of Confirmed.

- **Models**: Verdict (status, reason), VerdictStatus (Confirmed / Out-of-scope / Unverified), FindingWithVerdict (Finding + Verdict).
- **ContextAggregator**: Project signature (e.g. requirements, urls/views, package.json); per-file context (imports, is_entry_point, is_test_file, route_path).
- **VerdictEngine**: Applies rules in precedence order. Unverified does not stop; Confirmed or Out-of-scope can terminate. Optional extra_rules.
- **Rules** (in `src/verdict/rules/`): environment_neutralizer (test/examples → Unverified), xss_context (HTML/JS + reachable + entry → Confirmed; no web → Out-of-scope), sql_sanitizer (parameterized markers → Out-of-scope), input_validation (allowlist/sanitize on same line → Out-of-scope), taint_reachability (Confirmed Reachable → Confirmed), pattern_only_fallback (no attack_path / reachability None or Unverifiable → Unverified). See `verdict/RULES_ORDER.md` for order and how to add rules.

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

## Evidence and workflow (Phase 1)

- **Evidence schema** (`src/evidence.py`): Every finding dict can be normalized to a single evidence block (reachability_status, verdict_status, attack_path, evidence_summary). Used so JSON, HTML, and PR outputs share one structure.
- **Evidence-rich outputs**: The scanner attaches an `evidence` key to each finding before reports; JSON/HTML/Markdown include it. No new storage.
- **Diff-aware scanning**: Optional `diff_text` and `path_in_diff` on `scan_file()`; `src/diff_scope.py` parses unified diffs and filters findings to changed lines only. CLI: `--diff path/to/diff.patch`.
- **GitHub PR scaffolding** (`src/integrations/github_pr.py`): `get_pr_changed_files(repo, pr_number)`, `post_pr_comment(repo, pr_number, body)`, and `format_findings_for_comment(findings, file_name)`. Script: `scripts/scan_github_pr.py --repo owner/repo --pr 123` (requires `GITHUB_TOKEN`). Fetches changed files, runs scanner with diff scope, posts one comment.

## Technology

- **Python**: Security tooling, LLM and Snowflake SDKs, fast iteration.
- **Snowflake**: Analytics, schema in `config/snowflake_schema.sql`; see SNOWFLAKE_SETUP.md.
- **Streamlit**: Open Nazca Security Analytics UI (app.py); RAG, sandbox, report viewing.

For a complete list of every folder and file, see [FULL_PROGRAM_MAP.md](FULL_PROGRAM_MAP.md).
