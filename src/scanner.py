"""
Main Scanner Orchestrator for AI Code Breaker
Coordinates the complete security scanning workflow.
"""

import time
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path

# Import all modules
# Import all modules
from .ingestion import CodeIngestion
from .detectors import (
    PromptInjectionDetector,
    HardcodedSecretsDetector,
    OverprivilegedToolsDetector,
    Finding
)
from .llm_reasoning import LLMAnalyzer
from .snowflake_integration import SnowflakeClient
from .report_generation import ReportGenerator
from .rag_manager import RAGManager

logger = logging.getLogger(__name__)


class AICodeScanner:
    """
    Main scanner orchestrator that coordinates the entire security scanning workflow:
    1. Code ingestion
    2. Vulnerability detection
    3. LLM analysis (risk explanation + fixes)
    4. Snowflake storage
    5. Report generation
    """
    
    def __init__(
        self,
        use_snowflake: bool = True,
        use_llm_analysis: bool = True,
        llm_provider: str = "snowflake_cortex",
        max_file_size_mb: int = 10
    ):
        """
        Initialize the AI Code Scanner.
        
        Args:
            use_snowflake: Whether to store results in Snowflake
            use_llm_analysis: Whether to use LLM for analysis
            llm_provider: LLM provider
            max_file_size_mb: Maximum file size to scan
        """
        self.use_snowflake = use_snowflake
        self.use_llm_analysis = use_llm_analysis
        logger.info("Initializing AI Code Scanner...")
        
        self.ingestion = CodeIngestion(max_file_size_mb=max_file_size_mb)
        logger.info("✓ Code ingestion module loaded")
        
        # Initialize RAG Manager (for policy context)
        self.rag_manager = None
        try:
            self.rag_manager = RAGManager()
            logger.info("✓ RAG Manager initialized")
        except Exception as e:
            logger.warning(f"RAG Manager init failed: {e}")
        
        # Initialize detectors
        self.detectors = [
            PromptInjectionDetector(enabled=True),
            HardcodedSecretsDetector(enabled=True),
            OverprivilegedToolsDetector(enabled=True)
        ]
        logger.info(f"✓ Loaded {len(self.detectors)} vulnerability detectors")
        
        # Initialize LLM analyzer (if enabled)
        if self.use_llm_analysis:
            try:
                # Pass RAG Manager to Analyzer
                self.llm_analyzer = LLMAnalyzer(
                    provider=llm_provider,
                    rag_manager=self.rag_manager
                )
                logger.info(f"✓ LLM analyzer initialized ({llm_provider})")
            except Exception as e:
                logger.warning(f"LLM analyzer not available: {e}. Using fallback mode.")
                self.use_llm_analysis = False
        
        # Initialize Snowflake client (if enabled)
        if self.use_snowflake:
            try:
                self.snowflake_client = SnowflakeClient()
                logger.info("✓ Snowflake client connected")
            except Exception as e:
                logger.warning(f"Snowflake not available: {e}. Results won't be persisted.")
                self.use_snowflake = False
        
        # Initialize report generator
        self.report_generator = ReportGenerator()
        logger.info("✓ Report generator loaded")
        
        logger.info("🚀 AI Code Scanner ready!")
    
    def scan_file(
        self,
        file_path: str,
        scanned_by: str = "system",
        generate_reports: bool = True,
        report_formats: List[str] = None
    ) -> Dict[str, Any]:
        """
        Scan a single code file for security vulnerabilities.
        
        Args:
            file_path: Path to the code file
            scanned_by: User or system initiating the scan
            generate_reports: Whether to generate report files
            report_formats: List of report formats ('json', 'html', 'markdown')
        
        Returns:
            Dictionary containing scan results
        """
        if report_formats is None:
            report_formats = ['json', 'html']
        
        start_time = time.time()
        logger.info(f"\n{'='*70}")
        logger.info(f"🔍 Starting security scan: {file_path}")
        logger.info(f"{'='*70}")
        
        try:
            # Step 1: Ingest the code file
            logger.info("\n[1/5] Ingesting code file...")
            file_data = self.ingestion.ingest_file(file_path)
            logger.info(f"✓ Ingested {file_data['line_count']} lines of {file_data['language']} code")
            
            # Step 2: Store in Snowflake (if enabled)
            scan_id = None
            if self.use_snowflake:
                logger.info("\n[2/5] Storing in Snowflake...")
                scan_id = self.snowflake_client.insert_code_scan(
                    file_name=file_data['file_name'],
                    file_path=file_data['file_path'],
                    language=file_data['language'],
                    code_content=file_data['code_content'],
                    file_size_bytes=file_data['file_size_bytes'],
                    scanned_by=scanned_by,
                    metadata=file_data['metadata']
                )
                logger.info(f"✓ Stored with scan_id: {scan_id}")
            else:
                logger.info("\n[2/5] Skipping Snowflake storage (disabled)")
                scan_id = f"local-{int(time.time())}"
            
            # Step 3: Run vulnerability detectors
            logger.info("\n[3/5] Running vulnerability detectors...")
            all_findings: List[Finding] = []
            
            for detector in self.detectors:
                if detector.enabled:
                    logger.info(f"  Running {detector.name}...")
                    findings = detector.detect(
                        code=file_data['code_content'],
                        language=file_data['language'],
                        file_name=file_data['file_name']
                    )
                    all_findings.extend(findings)
                    logger.info(f"  ✓ Found {len(findings)} issues")
            
            # Deduplicate findings - keep only one finding per line per vulnerability type
            all_findings = self._deduplicate_findings(all_findings)
            
            logger.info(f"✓ Detection complete: {len(all_findings)} total vulnerabilities found")
            
            # Step 4: LLM Analysis (if enabled)
            if self.use_llm_analysis and all_findings:
                logger.info(f"\n[4/5] Running LLM analysis on {len(all_findings)} findings with 15 parallel workers...")
                
                # Use batch_analyze for parallel processing
                analyzed_results = self.llm_analyzer.batch_analyze(all_findings, max_workers=15)
                
                # Store analysis in Snowflake and update findings
                for i, (finding, analysis) in enumerate(analyzed_results, 1):
                    try:
                        # Store analysis in Snowflake
                        if self.use_snowflake:
                            # First, insert the finding
                            finding_dict = finding.to_dict()
                            finding_id = self.snowflake_client.insert_finding(
                                scan_id=scan_id,
                                detector_name=finding_dict['detector_name'],
                                vulnerability_type=finding_dict['vulnerability_type'],
                                severity=finding_dict['severity'],
                                line_number=finding_dict['line_number'],
                                code_snippet=finding_dict['code_snippet'],
                                description=finding_dict['description'],
                                confidence=finding_dict['confidence'],
                                cwe_id=finding_dict.get('cwe_id'),
                                owasp_category=finding_dict.get('owasp_category'),
                                metadata=finding_dict.get('metadata')
                            )
                            
                            # Then update with LLM analysis
                            self.snowflake_client.update_finding_with_llm_analysis(
                                finding_id=finding_id,
                                risk_explanation=analysis['risk_explanation'],
                                suggested_fix=analysis['suggested_fix']
                            )
                        
                        logger.info(f"  ✓ Stored finding {i}/{len(analyzed_results)}")
                        
                    except Exception as e:
                        logger.warning(f"  ⚠ Failed to store finding {i}: {e}")
                
                logger.info("✓ LLM analysis complete")
            else:
                logger.info("\n[4/5] Skipping LLM analysis")
                
                # Still insert findings into Snowflake without LLM analysis
                if self.use_snowflake and all_findings:
                    for finding in all_findings:
                        finding_dict = finding.to_dict()
                        self.snowflake_client.insert_finding(
                            scan_id=scan_id,
                            detector_name=finding_dict['detector_name'],
                            vulnerability_type=finding_dict['vulnerability_type'],
                            severity=finding_dict['severity'],
                            line_number=finding_dict['line_number'],
                            code_snippet=finding_dict['code_snippet'],
                            description=finding_dict['description'],
                            confidence=finding_dict['confidence'],
                            cwe_id=finding_dict.get('cwe_id'),
                            owasp_category=finding_dict.get('owasp_category'),
                            metadata=finding_dict.get('metadata')
                        )
            
            # Calculate statistics
            scan_duration_ms = int((time.time() - start_time) * 1000)
            severity_counts = self._count_by_severity(all_findings)
            
            # Update Snowflake with statistics
            if self.use_snowflake:
                self.snowflake_client.update_scan_statistics(
                    scan_id=scan_id,
                    total_findings=len(all_findings),
                    critical_count=severity_counts.get('CRITICAL', 0),
                    high_count=severity_counts.get('HIGH', 0),
                    medium_count=severity_counts.get('MEDIUM', 0),
                    low_count=severity_counts.get('LOW', 0),
                    scan_duration_ms=scan_duration_ms
                )
            
            # Step 5: Generate reports
            logger.info("\n[5/5] Generating reports...")
            report_paths = {}
            
            scan_data = {
                'scan_id': scan_id,
                'file_name': file_data['file_name'],
                'language': file_data['language'],
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration_ms': scan_duration_ms
            }
            
            # Convert findings to dictionaries for reports
            findings_dicts = []
            for finding in all_findings:
                finding_dict = finding.to_dict()
                # Add LLM analysis if available
                if finding.metadata:
                    # Check for nested llm_analysis (from batch_analyze)
                    if 'llm_analysis' in finding.metadata:
                        analysis = finding.metadata['llm_analysis']
                        finding_dict['risk_explanation'] = analysis.get('risk_explanation')
                        finding_dict['suggested_fix'] = analysis.get('suggested_fix')
                    # Fallback for direct keys
                    elif 'risk_explanation' in finding.metadata:
                        finding_dict['risk_explanation'] = finding.metadata['risk_explanation']
                        finding_dict['suggested_fix'] = finding.metadata['suggested_fix']
                        
                findings_dicts.append(finding_dict)
            
            if generate_reports:
                # Create reports directory
                reports_dir = Path('reports')
                reports_dir.mkdir(exist_ok=True)
                
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                base_name = Path(file_path).stem
                
                if 'json' in report_formats:
                    json_path = self.report_generator.generate_json_report(
                        scan_data=scan_data,
                        findings=findings_dicts,
                        output_path=f"reports/{base_name}_{timestamp}.json"
                    )
                    report_paths['json'] = json_path
                
                if 'html' in report_formats:
                    html_path = self.report_generator.generate_html_report(
                        scan_data=scan_data,
                        findings=findings_dicts,
                        output_path=f"reports/{base_name}_{timestamp}.html"
                    )
                    report_paths['html'] = html_path
                
                if 'markdown' in report_formats:
                    md_path = self.report_generator.generate_markdown_report(
                        scan_data=scan_data,
                        findings=findings_dicts,
                        output_path=f"reports/{base_name}_{timestamp}.md"
                    )
                    report_paths['markdown'] = md_path
                
                logger.info(f"✓ Generated {len(report_paths)} report(s)")
            
            # Print console summary
            console_summary = self.report_generator.generate_console_summary(
                scan_data=scan_data,
                findings=findings_dicts
            )
            print(console_summary)
            
            # Return results
            results = {
                'success': True,
                'scan_id': scan_id,
                'file_name': file_data['file_name'],
                'language': file_data['language'],
                'total_findings': len(all_findings),
                'severity_counts': severity_counts,
                'scan_duration_ms': scan_duration_ms,
                'findings': findings_dicts,
                'report_paths': report_paths
            }
            
            logger.info(f"\n✅ Scan complete! Duration: {scan_duration_ms}ms")
            logger.info(f"{'='*70}\n")
            
            return results
            
        except Exception as e:
            logger.error(f"✗ Scan failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'file_name': file_path
            }
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings on the same line for the same vulnerability type.
        Keeps the finding with highest confidence.
        
        Args:
            findings: List of all findings
        
        Returns:
            Deduplicated list of findings
        """
        # Key: (line_number, vulnerability_type)
        # Value: Finding with highest confidence
        unique_findings: Dict[tuple, Finding] = {}
        
        for finding in findings:
            key = (finding.line_number, finding.vulnerability_type)
            
            if key not in unique_findings:
                unique_findings[key] = finding
            else:
                # Keep the one with higher confidence
                if finding.confidence > unique_findings[key].confidence:
                    unique_findings[key] = finding
        
        deduped = list(unique_findings.values())
        
        if len(findings) != len(deduped):
            logger.info(f"  Deduplicated: {len(findings)} → {len(deduped)} findings")
        
        return deduped
    
    def scan_directory(
        self,
        directory_path: str,
        recursive: bool = True,
        scanned_by: str = "system"
    ) -> List[Dict[str, Any]]:
        """
        Scan all code files in a directory.
        
        Args:
            directory_path: Path to directory
            recursive: Whether to scan subdirectories
            scanned_by: User or system initiating the scan
        
        Returns:
            List of scan results for each file
        """
        logger.info(f"📁 Scanning directory: {directory_path}")
        
        # Ingest all files
        files_data = self.ingestion.ingest_directory(
            directory_path=directory_path,
            recursive=recursive
        )
        
        # Scan each file
        results = []
        for file_data in files_data:
            result = self.scan_file(
                file_path=file_data['file_path'],
                scanned_by=scanned_by
            )
            results.append(result)
        
        logger.info(f"✅ Directory scan complete: {len(results)} files scanned")
        return results
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.severity
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def close(self):
        """Clean up resources."""
        if self.use_snowflake and hasattr(self, 'snowflake_client'):
            self.snowflake_client.close()
        logger.info("✓ Scanner closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create scanner instance
    with AICodeScanner(use_snowflake=False, use_llm_analysis=False) as scanner:
        print("AI Code Scanner initialized!")
        print("Ready to scan files. Example usage:")
        print("  results = scanner.scan_file('path/to/code.py')")

