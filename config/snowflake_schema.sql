-- LLMCheck: Snowflake Database Schema
-- Creates tables for storing code scans and vulnerability findings
-- Create database and schema
CREATE DATABASE IF NOT EXISTS LLMCHECK_DB;
USE DATABASE LLMCHECK_DB;
CREATE SCHEMA IF NOT EXISTS PUBLIC;
USE SCHEMA PUBLIC;
-- Table 1: CODE_SCANS
-- Stores information about each code file that has been scanned
CREATE TABLE IF NOT EXISTS CODE_SCANS (
    scan_id VARCHAR(36) PRIMARY KEY,
    file_name VARCHAR(500) NOT NULL,
    file_path VARCHAR(2000),
    language VARCHAR(50) NOT NULL,
    file_size_bytes INTEGER,
    code_content TEXT NOT NULL,
    scan_timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    scan_duration_ms INTEGER,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    scanned_by VARCHAR(100),
    metadata VARIANT
);
-- Table 2: FINDINGS
-- Stores individual vulnerability findings for each scan
CREATE TABLE IF NOT EXISTS FINDINGS (
    finding_id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL,
    detector_name VARCHAR(100) NOT NULL,
    vulnerability_type VARCHAR(200) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence FLOAT,
    line_number INTEGER,
    code_snippet TEXT,
    description TEXT,
    risk_explanation TEXT,
    suggested_fix TEXT,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    detected_timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    remediation_status VARCHAR(50) DEFAULT 'OPEN',
    metadata VARIANT,
    FOREIGN KEY (scan_id) REFERENCES CODE_SCANS(scan_id)
);
-- Table 3: SCAN_HISTORY
-- For tracking trends over time
CREATE TABLE IF NOT EXISTS SCAN_HISTORY (
    history_id VARCHAR(36) PRIMARY KEY,
    project_name VARCHAR(200),
    scan_date DATE,
    total_scans INTEGER,
    total_vulnerabilities INTEGER,
    risk_score FLOAT,
    metadata VARIANT
);
-- View: CRITICAL_FINDINGS
-- Quick access to critical vulnerabilities
CREATE OR REPLACE VIEW CRITICAL_FINDINGS AS
SELECT f.finding_id,
    f.vulnerability_type,
    f.severity,
    f.code_snippet,
    f.risk_explanation,
    c.file_name,
    c.language,
    c.scan_timestamp
FROM FINDINGS f
    JOIN CODE_SCANS c ON f.scan_id = c.scan_id
WHERE f.severity = 'CRITICAL'
ORDER BY f.detected_timestamp DESC;
-- View: SCAN_SUMMARY
-- Overview of all scans
CREATE OR REPLACE VIEW SCAN_SUMMARY AS
SELECT scan_id,
    file_name,
    language,
    scan_timestamp,
    total_findings,
    critical_count,
    high_count,
    medium_count,
    low_count,
    scan_duration_ms
FROM CODE_SCANS
ORDER BY scan_timestamp DESC;
-- Grant permissions
GRANT ALL ON DATABASE LLMCHECK_DB TO ROLE ACCOUNTADMIN;
GRANT ALL ON SCHEMA PUBLIC TO ROLE ACCOUNTADMIN;
GRANT ALL ON ALL TABLES IN SCHEMA PUBLIC TO ROLE ACCOUNTADMIN;
GRANT ALL ON ALL VIEWS IN SCHEMA PUBLIC TO ROLE ACCOUNTADMIN;
SELECT 'Snowflake schema created successfully!' AS status;