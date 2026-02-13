# 🔒 AI Code Breaker: LLM Security Scanner

**Find and fix security vulnerabilities in AI systems before attackers do.**

A comprehensive security scanning tool designed for the HoyaHacks 2026 hackathon that detects vulnerabilities in AI-related code, explains risks in plain language, and suggests safe fixes. All findings are stored in Snowflake for tracking and analysis.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 What It Does

AI Code Breaker scans your codebase for three critical security vulnerabilities:

1. **🎭 Prompt Injection** - Detects unsafe concatenation of user input into AI prompts
2. **🔑 Hardcoded Secrets** - Finds API keys, tokens, and passwords in source code
3. **⚠️ Over-Privileged AI Tools** - Identifies AI agents with dangerous permissions

## ✨ Key Features

- **🔍 Smart Detection**: Pattern-based and AST analysis for accurate vulnerability detection
- **🤖 LLM Analysis**: Uses GPT-4/Claude to generate plain-language explanations and fix suggestions
- **❄️ Snowflake Integration**: Store scan results for tracking and trend analysis
- **📊 Beautiful Reports**: Generate JSON, HTML, and Markdown reports
- **🖥️ Streamlit UI**: User-friendly web interface for easy scanning
- **⚡ Fast & Efficient**: Optimized for hackathon speed (35 hours MVP-ready)

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- **Snowflake account** (for data storage and LLM analysis via Cortex)

### Installation

```bash
# Clone the repository
git clone https://github.com/cscx1/LLMCheck.git
cd LLMCheck

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys and Snowflake credentials
```

### Configuration

Edit `.env` file with your Snowflake credentials:

```bash
# Snowflake Configuration (Required)
SNOWFLAKE_ACCOUNT=your_account.region
SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_DATABASE=LLMCHECK_DB
SNOWFLAKE_WAREHOUSE=COMPUTE_WH
SNOWFLAKE_ROLE=ACCOUNTADMIN

# Optional: Use external LLM providers instead of Snowflake Cortex
# OPENAI_API_KEY=sk-your-openai-key
# ANTHROPIC_API_KEY=sk-ant-your-anthropic-key
```

### Snowflake Setup

**Required for full functionality:**

See **[SNOWFLAKE_SETUP.md](SNOWFLAKE_SETUP.md)** for complete setup instructions.

Quick version:
```bash
# 1. Run the schema creation script in Snowflake
# File: config/snowflake_schema.sql

# 2. Add Snowflake credentials to .env

# 3. Test connection
python -c "from src.snowflake_integration import SnowflakeClient; SnowflakeClient()"
```

## 💻 Usage

### Option 1: Web UI (Recommended)

```bash
# Launch main app (KnightCheck Security Analytics)
streamlit run app.py

# Or use the CLI
python cli.py ui
```

Then open http://localhost:8501 in your browser. For a minimal upload-and-scan UI use `streamlit run app.py`.

### Option 2: Command Line

```bash
# Scan a single file (uses Snowflake by default)
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --snowflake

# Scan with Snowflake Cortex LLM analysis
python cli.py scan myfile.py --snowflake --llm-provider snowflake_cortex

# Scan a directory
python cli.py scan-dir ./myproject --recursive --snowflake

# Fast scan (no LLM analysis, no Snowflake)
python cli.py scan myfile.py --no-llm

# Use alternative LLM provider (requires separate API key)
python cli.py scan myfile.py --snowflake --llm-provider openai

# Generate specific report formats
python cli.py scan myfile.py --snowflake --format html markdown
```

### Option 3: Python API

```python
from src.scanner import AICodeScanner

# Initialize scanner with Snowflake
scanner = AICodeScanner(
    use_snowflake=True,
    use_llm_analysis=True,
    llm_provider="snowflake_cortex"  # Uses Snowflake Cortex LLM
)

# Scan a file
results = scanner.scan_file("path/to/code.py")

# Print results
print(f"Found {results['total_findings']} vulnerabilities")
for finding in results['findings']:
    print(f"- {finding['vulnerability_type']}: {finding['description']}")

# Close scanner
scanner.close()
```

## 📁 Project Structure

```
LLMCheck/
├── src/
│   ├── ingestion/          # Code file ingestion and parsing
│   ├── detectors/          # Vulnerability detection engines
│   │   ├── prompt_injection_detector.py
│   │   ├── hardcoded_secrets_detector.py
│   │   └── overprivileged_tools_detector.py
│   ├── llm_reasoning/      # LLM analysis for explanations
│   ├── snowflake_integration/  # Snowflake data persistence
│   ├── report_generation/  # Report creation (JSON/HTML/MD)
│   └── scanner.py          # Main orchestrator
├── app.py                  # Main Streamlit app (KnightCheck Security Analytics)
├── ui/
│   └── streamlit_app.py    # Alternate minimal upload-and-scan UI
├── scripts/                # Validation & benchmarking (run from repo root)
│   ├── benchmark_test.py
│   ├── validate_detectors.py
│   ├── validate_test3_regressions.py
│   └── run_test3_remediation_check.py
├── config/
│   ├── snowflake_schema.sql  # Database schema
│   └── config.yaml         # Configuration settings
├── examples/
│   └── vulnerable_code/    # Example vulnerable files for testing
├── tests/                  # Unit tests
├── cli.py                  # Command-line interface
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## 🧪 Testing with Examples

We've included intentionally vulnerable code examples for testing:

```bash
# Test prompt injection detection
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py

# Test hardcoded secrets detection
python cli.py scan examples/vulnerable_code/example2_hardcoded_secrets.py

# Test over-privileged tools detection
python cli.py scan examples/vulnerable_code/example3_overprivileged_tools.py
```

**Expected Output:**
- Multiple CRITICAL and HIGH severity findings
- Detailed explanations of each vulnerability
- Safe code fix suggestions

## 📊 Sample Scan Output

```
======================================================================
🔒 AI CODE SECURITY SCAN RESULTS
======================================================================

File: example1_prompt_injection.py
Language: python
Scan ID: abc-123-def-456

SUMMARY:
  🔴 Critical: 3
  🟠 High:     1
  🟡 Medium:   0
  🔵 Low:      0
  ─────────────────────
  Total:      4

BY TYPE:
  • Prompt Injection: 3
  • Hardcoded Secret: 1

======================================================================
```

## 🛠️ Technology Stack

- **Language**: Python 3.8+
- **Detectors**: Custom pattern matching + AST analysis
- **LLM Analysis**: Snowflake Cortex (Mistral-Large)
- **Storage**: Snowflake Data Cloud
- **UI**: Streamlit
- **Reports**: JSON, HTML, Markdown

**Note:** OpenAI and Anthropic are supported as alternative LLM providers, but Snowflake Cortex is the default and recommended option.

## 🔐 Security & Ethics

This tool is designed for **defensive security only**. 

**Acceptable Use:**
- ✅ Scanning your own code
- ✅ Code review and security audits
- ✅ Educational purposes
- ✅ CI/CD pipeline integration

**Prohibited Use:**
- ❌ Generating exploit code
- ❌ Attacking systems without authorization
- ❌ Scanning code you don't own without permission

## 🤝 Contributing

This is a hackathon project, but contributions are welcome!

```bash
# Clone and create a branch
git checkout -b feature/your-feature-name

# Make changes and test
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py

# Commit and push
git add .
git commit -m "Add your feature"
git push origin feature/your-feature-name
```

## 📚 Resources

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE: Common Weakness Enumeration](https://cwe.mitre.org/)
- [Snowflake Security Best Practices](https://docs.snowflake.com/en/user-guide/security)

## 🐛 Troubleshooting

### "ModuleNotFoundError" when running scanner

```bash
# Make sure you're in the project root directory
cd LLMCheck

# Run as a module
python -m src.scanner
```

### "Snowflake connection failed"

- Check your `.env` file has correct credentials
- Verify your Snowflake account is active
- Try disabling Snowflake: `python cli.py scan myfile.py`

### "LLM provider not available"

- Default uses Snowflake Cortex (requires Snowflake connection)
- For quick testing without Snowflake: `python cli.py scan myfile.py --no-llm`
- To use OpenAI/Anthropic: Add API key to `.env` and use `--llm-provider openai`

## 📝 License

MIT License - See LICENSE file for details

## 👥 Team

Built with ❤️ for HoyaHacks 2026

## 🎉 Hackathon Demos

For a quick demo:

```bash
# 1. Launch the web UI
streamlit run app.py

# 2. Upload an example file from examples/vulnerable_code/

# 3. Enable LLM Analysis for best results

# 4. Click "Start Security Scan"

# 5. View detailed findings with explanations and fixes!
```

## Validation & benchmarking

See **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** for layout and optional data (BenchmarkPython, bandit-tests). From repo root:

- `python scripts/benchmark_test.py` — OWASP Benchmark accuracy (requires BenchmarkPython)
- `python scripts/validate_detectors.py` — detector checks vs Bandit examples
- `python scripts/validate_test3_regressions.py` — regression tests for Test3 fixes
- `python scripts/run_test3_remediation_check.py` — compare scanner fixes to Test3_remediated_secure.py

## 🚧 Future Enhancements

- [ ] Additional vulnerability detectors
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] Support for more programming languages
- [ ] Real-time scanning in IDEs
- [ ] Automated fix generation
- [ ] Machine learning-based detection

---

**Remember:** Security is not a one-time check. Regular scanning and staying updated on security best practices are essential for maintaining secure AI systems! 🔒
