-- AI Code Breaker: Snowflake Database Schema
-- This script creates the necessary tables for storing code scans and vulnerability findings

-- Create database and schema (run as ACCOUNTADMIN)
CREATE DATABASE IF NOT EXISTS LLMCHECK_DB;
USE DATABASE LLMCHECK_DB;
CREATE SCHEMA IF NOT EXISTS PUBLIC;
USE SCHEMA PUBLIC;

-- Table 1: CODE_SCANS
-- Stores information about each code file that has been scanned
CREATE TABLE IF NOT EXISTS CODE_SCANS (
    scan_id VARCHAR(36) PRIMARY KEY,           -- UUID for each scan
    file_name VARCHAR(500) NOT NULL,           -- Name of the scanned file
    file_path VARCHAR(2000),                   -- Original file path
    language VARCHAR(50) NOT NULL,             -- Programming language (Python, JavaScript, etc.)
    file_size_bytes INTEGER,                   -- Size of the file
    code_content TEXT NOT NULL,                -- Full source code
    scan_timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),  -- When scan occurred
    scan_duration_ms INTEGER,                  -- How long the scan took
    total_findings INTEGER DEFAULT 0,          -- Count of vulnerabilities found
    critical_count INTEGER DEFAULT 0,          -- Count of critical issues
    high_count INTEGER DEFAULT 0,              -- Count of high severity issues
    medium_count INTEGER DEFAULT 0,            -- Count of medium severity issues
    low_count INTEGER DEFAULT 0,               -- Count of low severity issues
    scanned_by VARCHAR(100),                   -- User or system that initiated scan
    metadata VARIANT                           -- Additional JSON metadata
);

-- Table 2: FINDINGS
-- Stores individual vulnerability findings for each scan
CREATE TABLE IF NOT EXISTS FINDINGS (
    finding_id VARCHAR(36) PRIMARY KEY,        -- UUID for each finding
    scan_id VARCHAR(36) NOT NULL,              -- Foreign key to CODE_SCANS
    detector_name VARCHAR(100) NOT NULL,       -- Name of the detector that found it
    vulnerability_type VARCHAR(200) NOT NULL,  -- Type of vulnerability (e.g., "Prompt Injection")
    severity VARCHAR(20) NOT NULL,             -- CRITICAL, HIGH, MEDIUM, LOW
    confidence FLOAT,                          -- Confidence score (0.0 - 1.0)
    line_number INTEGER,                       -- Line number where issue was found
    code_snippet TEXT,                         -- Vulnerable code snippet
    description TEXT,                          -- Technical description
    risk_explanation TEXT,                     -- Plain-language explanation (from LLM)
    suggested_fix TEXT,                        -- Safe code fix suggestion (from LLM)
    cwe_id VARCHAR(20),                        -- Common Weakness Enumeration ID
    owasp_category VARCHAR(100),               -- OWASP classification
    detected_timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    remediation_status VARCHAR(50) DEFAULT 'OPEN',  -- OPEN, IN_PROGRESS, FIXED, FALSE_POSITIVE
    metadata VARIANT,                          -- Additional JSON metadata
    FOREIGN KEY (scan_id) REFERENCES CODE_SCANS(scan_id)
);

-- Table 3: SCAN_HISTORY (Optional - for tracking trends)
CREATE TABLE IF NOT EXISTS SCAN_HISTORY (
    history_id VARCHAR(36) PRIMARY KEY,
    project_name VARCHAR(200),
    scan_date DATE,
    total_scans INTEGER,
    total_vulnerabilities INTEGER,
    risk_score FLOAT,
    metadata VARIANT
);

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON CODE_SCANS(scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_language ON CODE_SCANS(language);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON FINDINGS(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON FINDINGS(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON FINDINGS(vulnerability_type);

-- Views for common queries
CREATE OR REPLACE VIEW CRITICAL_FINDINGS AS
SELECT 
    f.finding_id,
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

CREATE OR REPLACE VIEW SCAN_SUMMARY AS
SELECT 
    scan_id,
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

-- Grant permissions (adjust as needed for your team)
GRANT ALL ON DATABASE LLMCHECK_DB TO ROLE ACCOUNTADMIN;
GRANT ALL ON SCHEMA PUBLIC TO ROLE ACCOUNTADMIN;
GRANT ALL ON ALL TABLES IN SCHEMA PUBLIC TO ROLE ACCOUNTADMIN;
GRANT ALL ON ALL VIEWS IN SCHEMA PUBLIC TO ROLE ACCOUNTADMIN;

SELECT 'Snowflake schema created successfully!' AS status;

