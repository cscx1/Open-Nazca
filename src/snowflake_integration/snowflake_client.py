"""
Snowflake Integration Module for AI Code Breaker
Handles secure connections to Snowflake and data persistence operations.
"""

import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
import snowflake.connector
from snowflake.connector import DictCursor
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SnowflakeClient:
    """
    Secure Snowflake client for storing code scans and vulnerability findings.
    """
    
    def __init__(self):
        """Initialize Snowflake connection with credentials from environment."""
        self.connection = None
        self.cursor = None
        self._connect()
    
    def _connect(self) -> None:
        """
        Establish secure connection to Snowflake using environment variables.
        """
        try:
            self.connection = snowflake.connector.connect(
                account=os.getenv('SNOWFLAKE_ACCOUNT'),
                user=os.getenv('SNOWFLAKE_USER'),
                password=os.getenv('SNOWFLAKE_PASSWORD'),
                database=os.getenv('SNOWFLAKE_DATABASE', 'LLMCHECK_DB'),
                schema=os.getenv('SNOWFLAKE_SCHEMA', 'PUBLIC'),
                warehouse=os.getenv('SNOWFLAKE_WAREHOUSE', 'COMPUTE_WH'),
                role=os.getenv('SNOWFLAKE_ROLE', 'ACCOUNTADMIN')
            )
            self.cursor = self.connection.cursor(DictCursor)
            logger.info("✓ Connected to Snowflake successfully")
        except Exception as e:
            logger.error(f"✗ Failed to connect to Snowflake: {e}")
            raise
    
    def insert_code_scan(
        self,
        file_name: str,
        file_path: str,
        language: str,
        code_content: str,
        file_size_bytes: int,
        scanned_by: str = "system",
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Insert a new code scan record into Snowflake.
        
        Args:
            file_name: Name of the scanned file
            file_path: Original file path
            language: Programming language (e.g., 'python', 'javascript')
            code_content: Full source code content
            file_size_bytes: Size of the file in bytes
            scanned_by: User or system that initiated the scan
            metadata: Optional additional metadata as dictionary
        
        Returns:
            scan_id: UUID of the created scan record
        """
        scan_id = str(uuid.uuid4())
        
        try:
            # Convert metadata to JSON string if provided
            import json
            metadata_json = json.dumps(metadata) if metadata else '{}'
            
            # Use INSERT...SELECT to allow PARSE_JSON
            insert_query = """
            INSERT INTO CODE_SCANS (
                scan_id, file_name, file_path, language, file_size_bytes,
                code_content, scan_timestamp, scanned_by, metadata
            ) 
            SELECT %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP(), %s, PARSE_JSON(%s)
            """
            
            self.cursor.execute(insert_query, (
                scan_id,
                file_name,
                file_path,
                language,
                file_size_bytes,
                code_content,
                scanned_by,
                metadata_json
            ))
            
            self.connection.commit()
            logger.info(f"✓ Inserted code scan: {file_name} (ID: {scan_id})")
            return scan_id
            
        except Exception as e:
            logger.error(f"✗ Failed to insert code scan: {e}")
            self.connection.rollback()
            raise
    
    def insert_finding(
        self,
        scan_id: str,
        detector_name: str,
        vulnerability_type: str,
        severity: str,
        line_number: Optional[int],
        code_snippet: str,
        description: str,
        confidence: float = 1.0,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Insert a vulnerability finding into Snowflake.
        
        Args:
            scan_id: UUID of the associated code scan
            detector_name: Name of the detector that found the issue
            vulnerability_type: Type of vulnerability (e.g., "Prompt Injection")
            severity: CRITICAL, HIGH, MEDIUM, or LOW
            line_number: Line number where vulnerability was found
            code_snippet: Vulnerable code snippet
            description: Technical description of the vulnerability
            confidence: Confidence score (0.0 to 1.0)
            cwe_id: Common Weakness Enumeration ID
            owasp_category: OWASP classification
            metadata: Optional additional metadata
        
        Returns:
            finding_id: UUID of the created finding record
        """
        finding_id = str(uuid.uuid4())
        
        try:
            import json
            metadata_json = json.dumps(metadata) if metadata else '{}'
            
            # Use INSERT...SELECT to allow PARSE_JSON
            insert_query = """
            INSERT INTO FINDINGS (
                finding_id, scan_id, detector_name, vulnerability_type,
                severity, confidence, line_number, code_snippet,
                description, detected_timestamp, cwe_id, owasp_category,
                remediation_status, metadata
            )
            SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP(),
                %s, %s, 'OPEN', PARSE_JSON(%s)
            """
            
            self.cursor.execute(insert_query, (
                finding_id,
                scan_id,
                detector_name,
                vulnerability_type,
                severity,
                confidence,
                line_number,
                code_snippet,
                description,
                cwe_id,
                owasp_category,
                metadata_json
            ))
            
            self.connection.commit()
            logger.info(f"✓ Inserted finding: {vulnerability_type} (ID: {finding_id})")
            return finding_id
            
        except Exception as e:
            logger.error(f"✗ Failed to insert finding: {e}")
            self.connection.rollback()
            raise
    
    def update_finding_with_llm_analysis(
        self,
        finding_id: str,
        risk_explanation: str,
        suggested_fix: str
    ) -> None:
        """
        Update a finding with LLM-generated risk explanation and fix suggestion.
        
        Args:
            finding_id: UUID of the finding to update
            risk_explanation: Plain-language explanation from LLM
            suggested_fix: Safe code fix suggestion from LLM
        """
        try:
            update_query = """
            UPDATE FINDINGS
            SET risk_explanation = %s,
                suggested_fix = %s
            WHERE finding_id = %s
            """
            
            self.cursor.execute(update_query, (
                risk_explanation,
                suggested_fix,
                finding_id
            ))
            
            self.connection.commit()
            logger.info(f"✓ Updated finding with LLM analysis: {finding_id}")
            
        except Exception as e:
            logger.error(f"✗ Failed to update finding: {e}")
            self.connection.rollback()
            raise
    
    def update_scan_statistics(
        self,
        scan_id: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        scan_duration_ms: int
    ) -> None:
        """
        Update scan record with finding statistics and duration.
        
        Args:
            scan_id: UUID of the scan to update
            total_findings: Total number of vulnerabilities found
            critical_count: Number of critical issues
            high_count: Number of high severity issues
            medium_count: Number of medium severity issues
            low_count: Number of low severity issues
            scan_duration_ms: Scan duration in milliseconds
        """
        try:
            update_query = """
            UPDATE CODE_SCANS
            SET total_findings = %s,
                critical_count = %s,
                high_count = %s,
                medium_count = %s,
                low_count = %s,
                scan_duration_ms = %s
            WHERE scan_id = %s
            """
            
            self.cursor.execute(update_query, (
                total_findings,
                critical_count,
                high_count,
                medium_count,
                low_count,
                scan_duration_ms,
                scan_id
            ))
            
            self.connection.commit()
            logger.info(f"✓ Updated scan statistics for: {scan_id}")
            
        except Exception as e:
            logger.error(f"✗ Failed to update scan statistics: {e}")
            self.connection.rollback()
            raise
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Retrieve complete scan results including all findings.
        
        Args:
            scan_id: UUID of the scan to retrieve
        
        Returns:
            Dictionary containing scan info and all associated findings
        """
        try:
            # Get scan info
            scan_query = "SELECT * FROM CODE_SCANS WHERE scan_id = %s"
            self.cursor.execute(scan_query, (scan_id,))
            scan_data = self.cursor.fetchone()
            
            # Get all findings for this scan
            findings_query = "SELECT * FROM FINDINGS WHERE scan_id = %s ORDER BY severity, line_number"
            self.cursor.execute(findings_query, (scan_id,))
            findings_data = self.cursor.fetchall()
            
            return {
                "scan": scan_data,
                "findings": findings_data
            }
            
        except Exception as e:
            logger.error(f"✗ Failed to retrieve scan results: {e}")
            raise
    
    def get_all_scans(self, limit: int = 100) -> List[Dict]:
        """
        Retrieve recent scans.
        
        Args:
            limit: Maximum number of scans to retrieve
        
        Returns:
            List of scan records
        """
        try:
            query = """
            SELECT * FROM CODE_SCANS 
            ORDER BY scan_timestamp DESC 
            LIMIT %s
            """
            self.cursor.execute(query, (limit,))
            return self.cursor.fetchall()
            
        except Exception as e:
            logger.error(f"✗ Failed to retrieve scans: {e}")
            raise
    
    def close(self) -> None:
        """Close Snowflake connection."""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
            logger.info("✓ Snowflake connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Example usage
if __name__ == "__main__":
    # Test connection
    with SnowflakeClient() as client:
        print("Snowflake client initialized successfully!")

