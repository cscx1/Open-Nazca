"""
Main Scanner Orchestrator for Open Nazca
Coordinates the complete security scanning workflow.

Pipeline:
  1. Code ingestion
  2. Pattern-based vulnerability detection
  3. AST-based taint analysis  →  attack-path graph  →  reachability verification
  4. LLM analysis (optional enrichment)
  5. Report generation with trust-gradient classification
"""

import time
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path

# Import all modules
from .ingestion import CodeIngestion
from .detectors import (
    PromptInjectionDetector,
    HardcodedSecretsDetector,
    OverprivilegedToolsDetector,
    WeakRandomDetector,
    WeakHashDetector,
    XPathInjectionDetector,
    XXEDetector,
    DeserializationDetector,
    SecureCookieDetector,
    TrustBoundaryDetector,
    LDAPInjectionDetector,
    SQLInjectionDetector,
    UnsafeReflectionDetector,
    CryptoMisuseDetector,
    TOCTOUDetector,
    MemorySafetyDetector,
    TypeConfusionDetector,
    LogInjectionDetector,
    XSSDetector,
    EvasionPatternsDetector,
    OperationalSecurityDetector,
    Finding,
)
from .detectors.vuln_ownership import is_owner
from .llm_reasoning import LLMAnalyzer
from .snowflake_integration import SnowflakeClient
from .report_generation import ReportGenerator
from .rag_manager import RAGManager
from . import evidence
from . import diff_scope

# Analysis pipeline
from .analysis.taint_tracker import TaintTracker
from .analysis.attack_graph import AttackGraph
from .analysis.sink_classifier import SinkClassifier
from .analysis.reachability import ReachabilityVerifier, ReachabilityStatus
from .verdict import VerdictEngine

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
        Initialize the Open Nazca Scanner.
        
        Args:
            use_snowflake: Whether to store results in Snowflake
            use_llm_analysis: Whether to use LLM for analysis
            llm_provider: LLM provider
            max_file_size_mb: Maximum file size to scan
        """
        self.use_snowflake = use_snowflake
        self.use_llm_analysis = use_llm_analysis
        logger.info("Initializing Open Nazca Scanner...")
        
        self.ingestion = CodeIngestion(max_file_size_mb=max_file_size_mb)
        logger.info("Code ingestion module loaded")
        
        # Initialize RAG Manager (for policy context)
        self.rag_manager = None
        try:
            self.rag_manager = RAGManager()
            logger.info("RAG Manager initialized")
        except Exception as e:
            logger.warning(f"RAG Manager init failed: {e}")
        
        # Initialize detectors
        self.detectors = [
            PromptInjectionDetector(enabled=True),
            HardcodedSecretsDetector(enabled=True),
            OverprivilegedToolsDetector(enabled=True),
            WeakRandomDetector(enabled=True),
            WeakHashDetector(enabled=True),
            SQLInjectionDetector(enabled=True),
            XPathInjectionDetector(enabled=True),
            XXEDetector(enabled=True),
            DeserializationDetector(enabled=True),
            SecureCookieDetector(enabled=True),
            TrustBoundaryDetector(enabled=True),
            LDAPInjectionDetector(enabled=True),
            UnsafeReflectionDetector(enabled=True),
            CryptoMisuseDetector(enabled=True),
            TOCTOUDetector(enabled=True),
            MemorySafetyDetector(enabled=True),
            TypeConfusionDetector(enabled=True),
            LogInjectionDetector(enabled=True),
            XSSDetector(enabled=True),
            EvasionPatternsDetector(enabled=True),
            OperationalSecurityDetector(enabled=True),
        ]
        logger.info(f"Loaded {len(self.detectors)} vulnerability detectors")
        
        # Initialize LLM analyzer (if enabled)
        if self.use_llm_analysis:
            try:
                # Pass RAG Manager to Analyzer
                self.llm_analyzer = LLMAnalyzer(
                    provider=llm_provider,
                    rag_manager=self.rag_manager
                )
                logger.info(f"LLM analyzer initialized ({llm_provider})")
            except Exception as e:
                logger.warning(f"LLM analyzer not available: {e}. Using fallback mode.")
                self.use_llm_analysis = False
        
        # Initialize Snowflake client (if enabled)
        if self.use_snowflake:
            try:
                self.snowflake_client = SnowflakeClient()
                logger.info("Snowflake client connected")
            except Exception as e:
                logger.warning(f"Snowflake not available: {e}. Results won't be persisted.")
                self.use_snowflake = False
        
        # Initialize analysis pipeline
        self.taint_tracker = TaintTracker()
        self.reachability_verifier = ReachabilityVerifier()
        logger.info("Analysis pipeline loaded (taint tracker + reachability verifier)")

        # Initialize report generator
        self.report_generator = ReportGenerator()
        logger.info("Report generator loaded")
        
        logger.info("Open Nazca Scanner ready!")
    
    def scan_file(
        self,
        file_path: str,
        scanned_by: str = "system",
        generate_reports: bool = True,
        report_formats: List[str] = None,
        diff_text: Optional[str] = None,
        path_in_diff: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scan a single code file for security vulnerabilities.
        
        Args:
            file_path: Path to the code file
            scanned_by: User or system initiating the scan
            generate_reports: Whether to generate report files
            report_formats: List of report formats ('json', 'html', 'markdown')
            diff_text: Optional unified diff; when set, only findings in changed lines are reported
            path_in_diff: Path of this file as it appears in the diff (defaults to file_path)
        
        Returns:
            Dictionary containing scan results
        """
        if report_formats is None:
            report_formats = ['json', 'html']
        
        start_time = time.time()
        logger.info(f"\n{'='*70}")
        logger.info(f"Starting security scan: {file_path}")
        logger.info(f"{'='*70}")
        
        try:
            # Step 1: Ingest the code file
            logger.info("\n[1/6] Ingesting code file...")
            file_data = self.ingestion.ingest_file(file_path)
            logger.info(f"Ingested {file_data['line_count']} lines of {file_data['language']} code")
            
            # Step 2: Store in Snowflake (if enabled)
            scan_id = None
            if self.use_snowflake:
                logger.info("\n[2/6] Storing in Snowflake...")
                scan_id = self.snowflake_client.insert_code_scan(
                    file_name=file_data['file_name'],
                    file_path=file_data['file_path'],
                    language=file_data['language'],
                    code_content=file_data['code_content'],
                    file_size_bytes=file_data['file_size_bytes'],
                    scanned_by=scanned_by,
                    metadata=file_data['metadata']
                )
                logger.info(f"Stored with scan_id: {scan_id}")
            else:
                logger.info("\n[2/6] Skipping Snowflake storage (disabled)")
                scan_id = f"local-{int(time.time())}"
            
            # Step 3: Run vulnerability detectors
            logger.info("\n[3/6] Running vulnerability detectors...")
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
                    logger.info(f"  Found {len(findings)} issues")
            
            # Deduplicate findings - keep only one finding per line per vulnerability type
            all_findings = self._deduplicate_findings(all_findings)
            
            logger.info(f"Detection complete: {len(all_findings)} total vulnerabilities found")
            
            # Step 3.5: AST-based taint analysis + attack-path graph + reachability
            logger.info("\n[4/6] Running static analysis pipeline...")
            attack_paths_data = []
            reachability_data = []
            try:
                if file_data['language'] == 'python':
                    nodes, edges = self.taint_tracker.analyse(
                        file_data['file_name'], file_data['code_content']
                    )
                    if nodes:
                        graph = AttackGraph()
                        graph.add_nodes_and_edges(nodes, edges)
                        attack_paths = graph.enumerate_attack_paths()
                        logger.info(f"  Built attack graph: {graph.node_count} nodes, "
                                    f"{graph.edge_count} edges, {len(attack_paths)} paths")
                        
                        # Verify reachability
                        reach_results = self.reachability_verifier.verify_paths(
                            attack_paths, file_data['code_content'], file_data['file_name']
                        )
                        
                        # Enrich findings with trust-gradient classification
                        all_findings = self._enrich_findings_with_analysis(
                            all_findings, reach_results
                        )
                        # Re-run dedupe because enrichment can add AST-only findings
                        # that overlap pattern findings on the same sink line.
                        all_findings = self._deduplicate_findings(all_findings)

                        attack_paths_data = [p.to_dict() for p in attack_paths]
                        reachability_data = [r.to_dict() for r in reach_results]
                        
                        # Log reachability summary
                        status_counts: Dict[str, int] = {}
                        for r in reach_results:
                            s = r.status.value
                            status_counts[s] = status_counts.get(s, 0) + 1
                        for status, count in status_counts.items():
                            logger.info(f"    {status}: {count}")
                    else:
                        logger.info("  No taint nodes found — skipping graph construction")
                else:
                    logger.info(f"  AST analysis not yet supported for {file_data['language']} "
                                f"— using pattern-based results only")
            except Exception as e:
                logger.warning(f"  Analysis pipeline error: {e}")

            # Verdict layer: context-aware classification (reduces false positives)
            project_root = str(Path(file_path).resolve().parent)
            verdict_engine = VerdictEngine(project_root)
            verdicted = verdict_engine.run(
                all_findings,
                file_data["file_path"],
                file_data["code_content"],
            )
            logger.info(f"  Verdict layer: {len(verdicted)} findings classified")

            # Step 4: LLM Analysis (if enabled)
            if self.use_llm_analysis and verdicted:
                logger.info(f"\n[5/6] Running LLM analysis on {len(verdicted)} findings with 15 parallel workers...")
                
                # Use batch_analyze for parallel processing (on underlying findings)
                findings_for_llm = [fwv.finding for fwv in verdicted]
                analyzed_results = self.llm_analyzer.batch_analyze(findings_for_llm, max_workers=15)
                
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
                        
                        logger.info(f"  Stored finding {i}/{len(analyzed_results)}")
                        
                    except Exception as e:
                        logger.warning(f"  Failed to store finding {i}: {e}")
                
                logger.info("LLM analysis complete")
            else:
                logger.info("\n[5/6] Skipping LLM analysis")
                
                # Still insert findings into Snowflake without LLM analysis
                if self.use_snowflake and verdicted:
                    for fwv in verdicted:
                        finding = fwv.finding
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
            
            # Calculate statistics (full counts for Snowflake)
            scan_duration_ms = int((time.time() - start_time) * 1000)
            severity_counts_full = self._count_by_severity([fwv.finding for fwv in verdicted])
            
            # Update Snowflake with statistics (full scan counts)
            if self.use_snowflake:
                self.snowflake_client.update_scan_statistics(
                    scan_id=scan_id,
                    total_findings=len(verdicted),
                    critical_count=severity_counts_full.get('CRITICAL', 0),
                    high_count=severity_counts_full.get('HIGH', 0),
                    medium_count=severity_counts_full.get('MEDIUM', 0),
                    low_count=severity_counts_full.get('LOW', 0),
                    scan_duration_ms=scan_duration_ms
                )
            
            # Step 5: Generate reports
            logger.info("\n[6/6] Generating reports...")
            report_paths = {}
            
            scan_data = {
                'scan_id': scan_id,
                'file_name': file_data['file_name'],
                'language': file_data['language'],
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration_ms': scan_duration_ms
            }
            
            # Convert findings to dictionaries for reports (include verdict + evidence block)
            findings_dicts = []
            for fwv in verdicted:
                finding_dict = fwv.to_dict()
                finding = fwv.finding
                if getattr(finding, "metadata", None):
                    if "llm_analysis" in finding.metadata:
                        analysis = finding.metadata["llm_analysis"]
                        finding_dict["risk_explanation"] = analysis.get("risk_explanation")
                        finding_dict["suggested_fix"] = analysis.get("suggested_fix")
                    elif "risk_explanation" in finding.metadata:
                        finding_dict["risk_explanation"] = finding.metadata["risk_explanation"]
                        finding_dict["suggested_fix"] = finding.metadata["suggested_fix"]
                findings_dicts.append(evidence.with_evidence(finding_dict))

            # Optional: scope to diff (only report findings in changed regions)
            if diff_text:
                changed = diff_scope.parse_unified_diff(diff_text)
                path_key = path_in_diff if path_in_diff is not None else file_path
                findings_dicts = diff_scope.filter_findings_by_diff(
                    findings_dicts, path_key, changed
                )
                if changed:
                    logger.info(f"  Diff scope: {len(findings_dicts)} findings in changed lines")

            # Severity counts and total for reports/return (diff-scoped when diff_text set)
            severity_counts = self._count_by_severity_from_dicts(findings_dicts)
            total_findings_for_report = len(findings_dicts)
            
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
                
                logger.info(f"Generated {len(report_paths)} report(s)")
            
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
                'total_findings': total_findings_for_report,
                'severity_counts': severity_counts,
                'scan_duration_ms': scan_duration_ms,
                'findings': findings_dicts,
                'report_paths': report_paths,
                'attack_paths': attack_paths_data,
                'reachability': reachability_data,
            }
            
            logger.info(f"\nScan complete! Duration: {scan_duration_ms}ms")
            logger.info(f"{'='*70}\n")
            
            return results
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'file_name': file_path
            }
    
    def _enrich_findings_with_analysis(
        self,
        findings: List[Finding],
        reach_results: List,
    ) -> List[Finding]:
        """
        Annotate pattern-based findings with trust-gradient classification
        derived from the AST analysis pipeline.

        Matching strategy (in priority order):
        1. Exact match: sink line + vulnerability type
        2. Sink line match (any type)
        3. Transform line match: pattern detectors often flag the line where
           tainted data is concatenated (a transform), not the sink API call.
           We search the attack path's transform nodes for a matching line.
        4. Source line match: some pattern detectors flag the source line.
        5. No match: create a new finding from the AST analysis.
        """
        from .analysis.reachability import ReachabilityResult

        # Build lookup: line → list of findings on that line
        line_to_findings: Dict[int, List[Finding]] = {}
        for f in findings:
            line_to_findings.setdefault(f.line_number, []).append(f)

        # Track which findings have already been enriched
        enriched: set = set()

        for rr in reach_results:
            if not isinstance(rr, ReachabilityResult):
                continue
            path = rr.path
            sink_line = path.sink.line
            vuln_type = path.vulnerability_type.lower()

            matched = None

            # 1) Exact match on sink line + type
            for f in line_to_findings.get(sink_line, []):
                if f.vulnerability_type.lower() == vuln_type and id(f) not in enriched:
                    matched = f
                    break

            # 2) Sink line, any type
            if matched is None:
                for f in line_to_findings.get(sink_line, []):
                    if id(f) not in enriched:
                        matched = f
                        break

            # 3) Transform line match
            if matched is None:
                for transform in path.transforms:
                    for f in line_to_findings.get(transform.line, []):
                        if id(f) not in enriched:
                            matched = f
                            break
                    if matched:
                        break

            # 4) Source line match
            if matched is None:
                for f in line_to_findings.get(path.source.line, []):
                    if id(f) not in enriched:
                        matched = f
                        break

            if matched is not None:
                # Enrich the existing finding
                enriched.add(id(matched))
                matched.reachability_status = rr.status.value
                matched.reachability_reasoning = rr.reasoning
                matched.attack_path = path.to_dict()
                matched.sink_api = path.sink.name
                # Upgrade classification if analysis gives more specific type
                sink_info = SinkClassifier.classify(path.sink.name)
                if sink_info:
                    matched.vulnerability_type = sink_info.vulnerability_type
                    matched.severity = sink_info.severity
                    matched.cwe_id = sink_info.cwe_id
            else:
                # Create a new finding from the AST analysis
                sink_info = SinkClassifier.classify(path.sink.name)
                new_finding = Finding(
                    detector_name="StaticAnalysisPipeline",
                    vulnerability_type=path.vulnerability_type,
                    severity=path.severity,
                    line_number=sink_line,
                    code_snippet="",
                    description=path.sink.detail,
                    confidence=0.9,
                    cwe_id=path.cwe_id or None,
                    reachability_status=rr.status.value,
                    reachability_reasoning=rr.reasoning,
                    attack_path=path.to_dict(),
                    sink_api=path.sink.name,
                )
                findings.append(new_finding)

        return findings

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings on the same line for the same vulnerability type.
        Prefers the finding from the canonical "owner" detector for that type,
        then reachability strength, then confidence.
        """
        alias_map = {
            "attribute injection": "mass assignment",
        }
        unique_findings: Dict[tuple, Finding] = {}

        for finding in findings:
            normalized = alias_map.get(
                finding.vulnerability_type.lower(), finding.vulnerability_type.lower()
            )
            key = (finding.line_number, normalized, finding.sink_api or "")

            if key not in unique_findings:
                unique_findings[key] = finding
                continue

            existing = unique_findings[key]
            # Prefer owner: if one finding is from the canonical detector for this type, keep it.
            existing_is_owner = is_owner(existing.detector_name, existing.vulnerability_type)
            candidate_is_owner = is_owner(finding.detector_name, finding.vulnerability_type)
            if candidate_is_owner and not existing_is_owner:
                unique_findings[key] = finding
                continue
            if existing_is_owner and not candidate_is_owner:
                continue
            # Tie-break: reachability, then confidence.
            existing_rank = self._reachability_rank(existing.reachability_status)
            candidate_rank = self._reachability_rank(finding.reachability_status)
            if candidate_rank > existing_rank:
                unique_findings[key] = finding
            elif candidate_rank == existing_rank and finding.confidence > existing.confidence:
                unique_findings[key] = finding

        deduped = list(unique_findings.values())
        if len(findings) != len(deduped):
            logger.info(f"  Deduplicated: {len(findings)} → {len(deduped)} findings")
        return deduped

    @staticmethod
    def _reachability_rank(status: Optional[str]) -> int:
        order = {
            ReachabilityStatus.CONFIRMED_REACHABLE.value: 4,
            ReachabilityStatus.REQUIRES_MANUAL_REVIEW.value: 3,
            ReachabilityStatus.UNVERIFIABLE.value: 2,
            ReachabilityStatus.REACHABILITY_ELIMINATED.value: 1,
        }
        return order.get(status or "", 0)
    
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
        logger.info(f"Scanning directory: {directory_path}")
        
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
        
        logger.info(f"Directory scan complete: {len(results)} files scanned")
        return results
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.severity
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_by_severity_from_dicts(self, findings_dicts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity from list of finding dicts (e.g. after diff filter)."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings_dicts:
            severity = f.get('severity', 'LOW')
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def close(self):
        """Clean up resources."""
        if self.use_snowflake and hasattr(self, 'snowflake_client'):
            self.snowflake_client.close()
        logger.info("Scanner closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


if __name__ == "__main__":
    import sys as _sys

    logging.basicConfig(level=logging.WARNING)  # suppress INFO noise during self-test

    _fixture = (
        Path(__file__).resolve().parent.parent
        / "examples" / "vulnerable_code" / "example1_prompt_injection.py"
    )
    if not _fixture.exists():
        print(f"SKIP  fixture not found: {_fixture}")
        _sys.exit(0)

    print(f"Self-test: scanning {_fixture.name} ...")
    with AICodeScanner(use_snowflake=False, use_llm_analysis=False) as _scanner:
        _results = _scanner.scan_file(
            file_path=str(_fixture),
            generate_reports=False,
        )

    if not _results.get("success"):
        print(f"FAIL  scan returned success=False: {_results.get('error')}")
        _sys.exit(1)

    _n = _results["total_findings"]
    if _n == 0:
        print("FAIL  no findings returned for known-vulnerable fixture")
        _sys.exit(1)

    print(f"PASS  {_n} finding(s) detected in {_results['scan_duration_ms']}ms")
    _sys.exit(0)

