# 🚀 Quick Start Guide - AI Code Breaker

Get up and running in 5 minutes!

## ⚡ Super Fast Setup (No External Services)

Perfect for hackathon demos and quick testing.

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run a scan immediately (no setup needed!)
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --no-llm

# 3. Launch web UI
streamlit run ui/streamlit_app.py
```

✅ **You're done!** The scanner works without Snowflake or LLM APIs.

## 🎯 5-Minute Full Setup with Snowflake

For the complete experience with Snowflake Cortex LLM analysis:

### Step 1: Set Up Snowflake

1. Get your Snowflake account credentials
2. Run the schema SQL: `config/snowflake_schema.sql` in your Snowflake account
3. Ensure Snowflake Cortex is enabled (available in most regions)

### Step 2: Configure

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and add your Snowflake credentials:
SNOWFLAKE_ACCOUNT=your_account.region
SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_DATABASE=LLMCHECK_DB
SNOWFLAKE_WAREHOUSE=COMPUTE_WH
```

### Step 3: Test It!

```bash
# Scan with Snowflake Cortex LLM analysis
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --snowflake

# Or use the web UI
streamlit run ui/streamlit_app.py
```

## 🎬 Demo Flow for Presentations

Perfect 2-minute demo:

```bash
# 1. Show the vulnerable code
cat examples/vulnerable_code/example1_prompt_injection.py

# 2. Run the scan
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py

# 3. Show the generated HTML report
open reports/*.html  # Mac/Linux
start reports\*.html  # Windows
```

Or use the web UI for a visual demo:

```bash
# 1. Launch UI
streamlit run ui/streamlit_app.py

# 2. Upload example file from examples/vulnerable_code/

# 3. Enable LLM Analysis checkbox

# 4. Click "Start Security Scan"

# 5. Show the detailed findings!
```

## 📊 What You'll See

### Console Output
```
======================================================================
🔒 AI CODE SECURITY SCAN RESULTS
======================================================================

File: example1_prompt_injection.py
Language: python

SUMMARY:
  🔴 Critical: 3
  🟠 High:     1
  🟡 Medium:   0
  🔵 Low:      0

BY TYPE:
  • Prompt Injection: 3
  • Hardcoded Secret: 1
======================================================================
```

### In Reports
- **JSON**: Machine-readable format for CI/CD integration
- **HTML**: Beautiful visual report with syntax highlighting
- **Markdown**: Easy to read and share

## 🔧 Common Issues

### "No module named 'src'"
```bash
# Make sure you're in the project root
cd LLMCheck
python cli.py scan myfile.py
```

### "Snowflake connection failed"
```bash
# Check your .env file has correct Snowflake credentials
# Or use --no-llm flag for scanning without LLM/Snowflake
python cli.py scan myfile.py --no-llm
```

### "Port already in use" (Streamlit)
```bash
# Use a different port
streamlit run ui/streamlit_app.py --server.port 8502
```

## 🎯 Next Steps

1. **Scan Your Own Code**
   ```bash
   python cli.py scan path/to/your/code.py
   ```

2. **Integrate into CI/CD**
   ```bash
   # Add to your CI pipeline
   python cli.py scan-dir ./src --recursive
   if [ $? -ne 0 ]; then
     echo "Security issues found!"
     exit 1
   fi
   ```

3. **Set Up Snowflake** (Optional)
   - See main README.md for Snowflake setup
   - Run `config/snowflake_schema.sql`
   - Add credentials to `.env`

## 💡 Pro Tips

- Use `--no-llm` for faster scans during development
- Enable LLM analysis for demos and final reports
- Generate HTML reports for stakeholder presentations
- Scan before every commit to catch issues early

## 🆘 Need Help?

Check the main [README.md](README.md) for:
- Detailed usage instructions
- Full API documentation
- Troubleshooting guide
- Architecture details

---

**Ready to find vulnerabilities?** Start scanning! 🔍

