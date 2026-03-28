# Snowflake Setup — Open Nazca

This guide covers creating the Snowflake database, verifying Cortex access, and configuring the environment variables that Open Nazca reads at runtime.

Snowflake is **optional**. Run `python cli.py scan <file> --no-llm` to scan locally without any external services.

---

## Prerequisites

- Active Snowflake account
- ACCOUNTADMIN role (or a role with SYSADMIN + USAGE on a warehouse)
- Snowflake Cortex enabled in your region (required only for the Cortex LLM provider)

---

## 1. Create database and schema

Log into Snowflake and run:

```sql
-- File: config/snowflake_schema.sql (run this file in full to create all tables)
CREATE DATABASE IF NOT EXISTS OPEN_NAZCA_DB;
USE DATABASE OPEN_NAZCA_DB;
CREATE SCHEMA IF NOT EXISTS PUBLIC;
USE SCHEMA PUBLIC;
```

Running `config/snowflake_schema.sql` creates the `CODE_SCANS` and `FINDINGS` tables and their views.

---

## 2. Verify Snowflake Cortex

```sql
SELECT SNOWFLAKE.CORTEX.COMPLETE(
    'mistral-large',
    'Hello, how are you?'
) AS test_response;
```

If this returns a response, Cortex is available in your region. If not, use `--llm-provider openai` or `--llm-provider anthropic` instead.

---

## 3. Configure environment variables

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

```bash
SNOWFLAKE_ACCOUNT=myorg-myaccount      # format: <orgname>-<accountname>
SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_DATABASE=OPEN_NAZCA_DB
SNOWFLAKE_WAREHOUSE=COMPUTE_WH
SNOWFLAKE_ROLE=ACCOUNTADMIN
```

Finding your account identifier: Snowflake UI → Admin → Accounts.  
Format is `<orgname>-<account_name>` or `xxx12345.region` depending on your deployment.

---

## 4. Test the connection

```bash
python -c "from src.snowflake import SnowflakeClient; c = SnowflakeClient(); print('Connected'); c.close()"
```

---

## 5. Run a scan with Snowflake storage

```bash
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --snowflake
```

---

## Cortex model options

Edit `config/config.yaml` to change the default model:

```yaml
llm:
  provider: snowflake_cortex
  model: mistral-large   # alternatives: llama2-70b-chat, mixtral-8x7b
```

---

## Database schema overview

| Table | Purpose |
|-------|---------|
| `CODE_SCANS` | One row per scanned file; metadata, language, severity counts, duration |
| `FINDINGS` | One row per finding; links to `CODE_SCANS` via `scan_id`; includes LLM fields |

Useful queries:

```sql
-- Recent scans
SELECT * FROM SCAN_SUMMARY ORDER BY scan_timestamp DESC;

-- Critical findings
SELECT * FROM CRITICAL_FINDINGS;

-- Findings by type
SELECT vulnerability_type, COUNT(*) AS count
FROM FINDINGS
GROUP BY vulnerability_type
ORDER BY count DESC;

-- Daily severity trend
SELECT
    DATE_TRUNC('day', scan_timestamp) AS scan_date,
    SUM(critical_count) AS critical,
    SUM(high_count)     AS high
FROM CODE_SCANS
GROUP BY scan_date
ORDER BY scan_date DESC;
```

---

## Cost notes

- Cortex is billed per token; typical scan costs $0.002–$0.005.
- Storage is minimal (~1 KB per scan and its findings).
- Use `--no-llm` during development to avoid Cortex charges.
- X-Small warehouse is sufficient for scan ingestion.

---

## Troubleshooting

**"Account not found"** — Check the account identifier format; it must match exactly what Snowflake shows in Admin → Accounts.

**"Invalid username or password"** — Verify `.env` values match your Snowflake login.

**"Database does not exist"** — Run `config/snowflake_schema.sql` first.

**"Cortex function not found"** — Cortex is not available in your region. Switch to an external LLM: `--llm-provider openai`.

**"Insufficient privileges"** — Grant Cortex access:
```sql
GRANT USAGE ON FUNCTION SNOWFLAKE.CORTEX.COMPLETE TO ROLE <your_role>;
```

---

## Production role setup

For production, avoid ACCOUNTADMIN. Create a dedicated role:

```sql
CREATE ROLE OPEN_NAZCA_ROLE;

GRANT USAGE ON DATABASE OPEN_NAZCA_DB TO ROLE OPEN_NAZCA_ROLE;
GRANT USAGE ON SCHEMA PUBLIC TO ROLE OPEN_NAZCA_ROLE;
GRANT ALL ON ALL TABLES IN SCHEMA PUBLIC TO ROLE OPEN_NAZCA_ROLE;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE OPEN_NAZCA_ROLE;
GRANT USAGE ON FUNCTION SNOWFLAKE.CORTEX.COMPLETE TO ROLE OPEN_NAZCA_ROLE;

GRANT ROLE OPEN_NAZCA_ROLE TO USER your_username;
```

Then set `SNOWFLAKE_ROLE=OPEN_NAZCA_ROLE` in `.env`.

---

## Security best practices

- Never commit `.env` — it is in `.gitignore`.
- Use a dedicated role with least privilege instead of ACCOUNTADMIN.
- Rotate credentials regularly.
- Enable MFA on your Snowflake account.
- Restrict access with network policies if possible.

---

See [README](../README.md) for general usage and the full pipeline description.
