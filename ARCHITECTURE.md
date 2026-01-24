# 🏗️ Architecture Overview - AI Code Breaker

This document describes the system architecture and design decisions for the AI Code Breaker security scanner.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Streamlit UI │  │  CLI Tool    │  │  Python API  │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
└─────────┼──────────────────┼──────────────────┼─────────────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
          ┌─────────────────────────────────────┐
          │      Scanner Orchestrator           │
          │       (src/scanner.py)              │
          └──────────┬──────────────────────────┘
                     │
        ┌────────────┼────────────┬──────────────┐
        ▼            ▼            ▼              ▼
┌─────────────┐ ┌─────────┐ ┌──────────┐ ┌────────────┐
│  Ingestion  │ │Detectors│ │   LLM    │ │ Snowflake  │
│   Module    │ │ Module  │ │ Analyzer │ │Integration │
└─────────────┘ └─────────┘ └──────────┘ └────────────┘
        │            │            │              │
        ▼            ▼            ▼              ▼
┌─────────────────────────────────────────────────────┐
│              Report Generator                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │   JSON   │  │   HTML   │  │ Markdown │         │
│  └──────────┘  └──────────┘  └──────────┘         │
└─────────────────────────────────────────────────────┘
```

## Module Breakdown

### 1. Code Ingestion Module (`src/ingestion/`)

**Purpose**: Safely read and parse code files

**Key Components**:
- `CodeIngestion` class: Main ingestion handler
- Language detection (Python, JS, TS, Java, Go, etc.)
- File validation and size limits
- UTF-8/Latin-1 encoding handling
- SHA-256 hashing for deduplication

**Design Decisions**:
- **Safety First**: Validates file type and size before reading
- **Encoding Fallback**: Tries UTF-8 first, falls back to Latin-1
- **Metadata Extraction**: Captures line count, file hash, language info

### 2. Vulnerability Detectors (`src/detectors/`)

**Purpose**: Identify security vulnerabilities in code

**Architecture**:
```
BaseDetector (Abstract Base Class)
├── PromptInjectionDetector
├── HardcodedSecretsDetector
└── OverprivilegedToolsDetector
```

#### Pattern-Based Detection

Each detector uses:
- **Regex Patterns**: For quick pattern matching
- **Context Analysis**: Multi-line and contextual detection
- **Confidence Scoring**: 0.0-1.0 confidence levels
- **False Positive Filtering**: Excludes common safe patterns

#### Detector Details

**PromptInjectionDetector**:
- Detects: f-strings, .format(), string concatenation
- Context: Looks for AI-related keywords (prompt, gpt, llm)
- Severity: CRITICAL
- CWE: CWE-74 (Improper Neutralization)

**HardcodedSecretsDetector**:
- Detects: API keys, AWS credentials, passwords, tokens
- Patterns: OpenAI, Anthropic, GitHub, Slack, JWT
- Masking: Secrets are masked in output (first 4...last 4 chars)
- Severity: CRITICAL
- CWE: CWE-798 (Hard-coded Credentials)

**OverprivilegedToolsDetector**:
- Detects: delete, exec, eval, drop, sudo operations
- Context: Specifically targets AI agent tool definitions
- Severity: HIGH
- CWE: CWE-269 (Improper Privilege Management)

### 3. LLM Reasoning Module (`src/llm_reasoning/`)

**Purpose**: Generate human-readable explanations and fixes

**Supported Providers**:
- OpenAI (GPT-4, GPT-3.5-turbo)
- Anthropic (Claude 3 Sonnet)
- Snowflake Cortex (placeholder)

**Safety Measures**:
- System prompt enforces defensive security only
- No exploit code generation
- Focused on actionable fixes
- Temperature: 0.3 (more deterministic)

**Fallback Mode**:
- Pre-written explanations when LLM unavailable
- Ensures scanner always works without API keys

### 4. Snowflake Integration (`src/snowflake_integration/`)

**Purpose**: Persist scan results for tracking and analysis

**Database Schema**:

```sql
CODE_SCANS
├── scan_id (PK)
├── file_name
├── code_content
├── language
├── scan_timestamp
└── statistics (total_findings, severity_counts)

FINDINGS
├── finding_id (PK)
├── scan_id (FK)
├── vulnerability_type
├── severity
├── line_number
├── code_snippet
├── risk_explanation (from LLM)
└── suggested_fix (from LLM)
```

**Features**:
- UUID-based primary keys
- Foreign key relationships
- Indexed for fast queries
- Support for JSON metadata
- Pre-built views for common queries

### 5. Report Generation (`src/report_generation/`)

**Purpose**: Create formatted scan reports

**Formats**:

1. **JSON**:
   - Machine-readable
   - CI/CD integration friendly
   - Full data export

2. **HTML**:
   - Beautiful visual reports
   - Color-coded severity
   - Syntax-highlighted code snippets
   - Stakeholder-friendly

3. **Markdown**:
   - Easy to read
   - Git-friendly
   - Documentation integration

**Design Features**:
- Severity color coding (Critical=Red, High=Orange, etc.)
- Code snippet extraction with context
- Summary statistics
- Downloadable from web UI

### 6. Scanner Orchestrator (`src/scanner.py`)

**Purpose**: Coordinate the complete scanning workflow

**Workflow**:
```
1. Ingest File
   ↓
2. Store in Snowflake (optional)
   ↓
3. Run Detectors (parallel)
   ↓
4. LLM Analysis (optional, per finding)
   ↓
5. Update Snowflake with findings
   ↓
6. Generate Reports
   ↓
7. Return Results
```

**Features**:
- Context manager support (`with AICodeScanner() as scanner:`)
- Configurable components (enable/disable Snowflake, LLM)
- Progress logging
- Error handling and recovery
- Statistics tracking (scan duration, finding counts)

## Data Flow

### Single File Scan

```
User Input (file.py)
    ↓
Validation (size, type, encoding)
    ↓
Language Detection (Python)
    ↓
Content Extraction + Hashing
    ↓
Snowflake Insert (CODE_SCANS)
    ↓
┌─────────────────────────────┐
│   Parallel Detection        │
│  ┌─────────────────────┐   │
│  │ PromptInjection     │   │
│  │ HardcodedSecrets    │   │
│  │ OverprivilegedTools │   │
│  └─────────────────────┘   │
└─────────────────────────────┘
    ↓
Findings Collection
    ↓
┌─────────────────────────────┐
│   LLM Analysis (per finding)│
│  ┌─────────────────────┐   │
│  │ Risk Explanation    │   │
│  │ Suggested Fix       │   │
│  └─────────────────────┘   │
└─────────────────────────────┘
    ↓
Snowflake Insert (FINDINGS)
    ↓
Update Statistics
    ↓
┌─────────────────────────────┐
│   Report Generation         │
│  ┌─────┬───────┬─────────┐ │
│  │JSON │ HTML  │Markdown │ │
│  └─────┴───────┴─────────┘ │
└─────────────────────────────┘
    ↓
Results + Report Paths
```

## Design Decisions

### 1. Modular Architecture
**Why**: Easy to add new detectors, swap LLM providers, or change storage backends
**Trade-off**: More files and imports, but much better maintainability

### 2. Optional Dependencies
**Why**: Scanner works without Snowflake or LLM APIs for quick testing
**Trade-off**: More configuration options, but better flexibility

### 3. Pattern-Based Detection
**Why**: Fast, deterministic, no ML model required
**Trade-off**: May miss complex vulnerabilities, but great for MVP

### 4. Context Manager Pattern
**Why**: Ensures proper resource cleanup (Snowflake connections)
**Trade-off**: Slightly more verbose usage

### 5. Severity Levels
**Why**: Clear prioritization of security issues
**Mapping**: 
  - CRITICAL: Direct exploit paths (prompt injection, secrets)
  - HIGH: Privilege escalation risks
  - MEDIUM: Potential issues requiring context
  - LOW: Best practice violations

## Performance Considerations

### Optimization Strategies

1. **File Size Limits**: Default 10MB, configurable
2. **Batch Processing**: Snowflake batch inserts for multiple findings
3. **Lazy Loading**: LLM analysis only when enabled
4. **Caching**: File hash prevents duplicate scans (future enhancement)

### Scalability

**Current State** (MVP):
- Single file: ~1-5 seconds
- With LLM: +2-5 seconds per finding
- Snowflake: +0.5-1 second per file

**Future Enhancements**:
- Parallel file processing
- LLM request batching
- Connection pooling
- Result caching

## Security Considerations

### The Tool Itself is Secure

1. **No Code Execution**: Only reads and analyzes, never runs user code
2. **Input Validation**: File size limits, type checking
3. **Secret Masking**: API keys and passwords are masked in reports
4. **SQL Injection Protection**: Parameterized queries for Snowflake
5. **API Key Storage**: Environment variables, never in code

### Responsible Disclosure

- Reports include safe fixes only
- No exploit code generation
- Defensive security focus
- Clear usage guidelines

## Testing Strategy

### Unit Tests (Future Enhancement)
```python
tests/
├── test_ingestion.py
├── test_detectors.py
├── test_llm_analyzer.py
└── test_scanner.py
```

### Example Files
```python
examples/vulnerable_code/
├── example1_prompt_injection.py
├── example2_hardcoded_secrets.py
└── example3_overprivileged_tools.py
```

### Manual Testing
1. Scan example files
2. Verify finding counts
3. Check report generation
4. Validate Snowflake storage

## Future Architecture Enhancements

1. **Plugin System**: Load custom detectors dynamically
2. **CI/CD Integration**: GitHub Actions, GitLab CI plugins
3. **Real-time Scanning**: VS Code / IDE extensions
4. **ML-Based Detection**: Train models on vulnerability patterns
5. **Fix Automation**: Auto-generate PRs with fixes
6. **Dashboard**: Web dashboard for team-wide metrics

## Technology Choices

### Why Python?
- Rich ecosystem for security tools
- Easy integration with LLMs and Snowflake
- Fast prototyping for hackathons
- Excellent string/text processing

### Why Snowflake?
- Built for analytics and reporting
- Easy schema management
- Cloud-native scalability
- Hackathon sponsor integration

### Why Streamlit?
- Fastest way to build web UIs in Python
- No frontend coding required
- Interactive widgets out of the box
- Perfect for MVPs and demos

## Conclusion

The AI Code Breaker architecture prioritizes:
1. **Modularity**: Easy to extend and modify
2. **Safety**: No code execution, secure by default
3. **Usability**: Multiple interfaces (CLI, UI, API)
4. **Flexibility**: Optional components for different use cases
5. **Performance**: Fast enough for real-time use

This design supports rapid iteration during the hackathon while maintaining production-ready code quality.

