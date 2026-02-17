# ❄️ Snowflake Setup Guide

This guide walks you through setting up Snowflake for AI Code Breaker.

## Why Snowflake?

AI Code Breaker uses Snowflake for **everything**:
- ✅ **Data Storage**: Store all scan results and findings
- ✅ **LLM Analysis**: Use Snowflake Cortex for risk explanations
- ✅ **Analytics**: Track vulnerability trends over time
- ✅ **Single Platform**: One system for all needs

## Prerequisites

1. Active Snowflake account
2. ACCOUNTADMIN role (or appropriate permissions)
3. Snowflake Cortex enabled in your region

## Step-by-Step Setup

### 1. Create Database and Schema

Log into your Snowflake account and run:

```sql
-- File: config/snowflake_schema.sql
-- This creates all necessary tables, indexes, and views

CREATE DATABASE IF NOT EXISTS LLMCHECK_DB;
USE DATABASE LLMCHECK_DB;
CREATE SCHEMA IF NOT EXISTS PUBLIC;
USE SCHEMA PUBLIC;

-- Run the complete schema file
-- (See config/snowflake_schema.sql for full script)
```

### 2. Verify Snowflake Cortex

Check if Cortex is available:

```sql
-- Test Snowflake Cortex
SELECT SNOWFLAKE.CORTEX.COMPLETE(
    'mistral-large',
    'Hello, how are you?'
) AS test_response;
```

If this works, you're good to go! ✅

### 3. Configure Environment Variables

Create `.env` file in project root:

```bash
# Copy from example
cp .env.example .env
```

Edit `.env` with your credentials:

```bash
SNOWFLAKE_ACCOUNT=myorg-myaccount
SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_DATABASE=LLMCHECK_DB
SNOWFLAKE_WAREHOUSE=COMPUTE_WH
SNOWFLAKE_ROLE=ACCOUNTADMIN
```

**Finding Your Account Identifier:**
- Format: `<orgname>-<account_name>`
- Example: `abc12345.us-east-1` or `myorg-prod`
- Check: Snowflake UI → Admin → Accounts

### 4. Test Connection

```bash
# Test Python connection
python -c "from src.snowflake_integration import SnowflakeClient; client = SnowflakeClient(); print('✅ Connected!'); client.close()"
```

### 5. Run Your First Scan

```bash
# Scan with Snowflake storage and Cortex LLM
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --snowflake
```

## Snowflake Cortex Models

Available models in Cortex:
- **mistral-large** (default) - Fast and accurate
- **llama2-70b-chat** - Alternative option
- **mixtral-8x7b** - Another good choice

To change models, edit `config/config.yaml`:

```yaml
llm:
  provider: snowflake_cortex
  model: mistral-large  # Change this
```

## Database Schema Overview

### Tables Created

1. **CODE_SCANS**
   - Stores each scanned file
   - Metadata: filename, language, timestamp
   - Statistics: finding counts by severity

2. **FINDINGS**
   - Individual vulnerabilities detected
   - Links to CODE_SCANS via scan_id
   - Includes LLM-generated explanations

3. **SCAN_HISTORY** (Optional)
   - Aggregated metrics over time
   - Track trends and improvements

### Sample Queries

```sql
-- View all scans
SELECT * FROM SCAN_SUMMARY ORDER BY scan_timestamp DESC;

-- View critical findings
SELECT * FROM CRITICAL_FINDINGS;

-- Count findings by type
SELECT vulnerability_type, COUNT(*) as count
FROM FINDINGS
GROUP BY vulnerability_type
ORDER BY count DESC;

-- Track progress over time
SELECT 
    DATE_TRUNC('day', scan_timestamp) as scan_date,
    SUM(critical_count) as critical,
    SUM(high_count) as high
FROM CODE_SCANS
GROUP BY scan_date
ORDER BY scan_date DESC;
```

## Cost Considerations

### Snowflake Cortex Pricing
- Pay-per-token usage
- Typically $0.002 - $0.005 per request
- Mistral-Large is cost-effective

### Storage Costs
- Minimal for code scans
- Estimate: ~1KB per scan + findings

### Optimization Tips
1. Use `--no-llm` for quick scans during development
2. Enable LLM analysis for final scans only
3. Set appropriate file size limits
4. Use smaller warehouses (X-Small is fine)

## Troubleshooting

### Connection Issues

**Error: "Account not found"**
```bash
# Check account identifier format
# Should be: orgname-accountname or xxx12345.region
```

**Error: "Invalid username or password"**
```bash
# Verify credentials in .env
# Try logging into Snowflake web UI with same credentials
```

**Error: "Database does not exist"**
```bash
# Run the schema creation script first
# File: config/snowflake_schema.sql
```

### Cortex Issues

**Error: "Cortex function not found"**
```bash
# Snowflake Cortex not available in your region
# Options:
# 1. Use a different region
# 2. Use external LLM: --llm-provider openai
```

**Error: "Insufficient privileges"**
```bash
# Grant Cortex permissions:
GRANT USAGE ON FUNCTION SNOWFLAKE.CORTEX.COMPLETE TO ROLE ACCOUNTADMIN;
```

## Alternative: Use Without Snowflake

For quick testing without Snowflake:

```bash
# Scan without any external services
python cli.py scan myfile.py --no-llm

# Results still save to local reports
# Just no persistence or LLM analysis
```

## Security Best Practices

1. **Never commit `.env` file** - It's in `.gitignore`
2. **Use least privilege** - Create dedicated role instead of ACCOUNTADMIN
3. **Rotate passwords** - Change credentials regularly
4. **Enable MFA** - On your Snowflake account
5. **Network policies** - Restrict access by IP if possible

## Advanced: Custom Role Setup

For production use, create a dedicated role:

```sql
-- Create custom role
CREATE ROLE LLMCHECK_ROLE;

-- Grant permissions
GRANT USAGE ON DATABASE LLMCHECK_DB TO ROLE LLMCHECK_ROLE;
GRANT USAGE ON SCHEMA PUBLIC TO ROLE LLMCHECK_ROLE;
GRANT ALL ON ALL TABLES IN SCHEMA PUBLIC TO ROLE LLMCHECK_ROLE;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE LLMCHECK_ROLE;

-- Grant Cortex access
GRANT USAGE ON FUNCTION SNOWFLAKE.CORTEX.COMPLETE TO ROLE LLMCHECK_ROLE;

-- Assign to user
GRANT ROLE LLMCHECK_ROLE TO USER your_username;
```

Then use in `.env`:
```bash
SNOWFLAKE_ROLE=LLMCHECK_ROLE
```

## Support

- Snowflake Documentation: https://docs.snowflake.com/
- Cortex Guide: https://docs.snowflake.com/en/user-guide/snowflake-cortex
- Issues: Check project [README](../README.md) for troubleshooting

---

**Need help?** Check the main [README](../README.md) or [QUICKSTART](QUICKSTART.md) for more guidance!

