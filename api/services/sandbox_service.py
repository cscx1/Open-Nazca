"""
Sandbox pipeline adapter extracted from app.py _execute_sandbox_on_user_code().
Runs the full 5-phase Identify → Analyse → Verify → Remediate → Re-verify flow.
Only this file and scan_service.py may import from src/.
"""

import sys
import os
import shutil
import logging
import asyncio
import tempfile
from pathlib import Path
from typing import Any

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.ingestion.code_ingestion import CodeIngestion  # noqa: E402
from src.detectors import (  # noqa: E402
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
    UnsafeReflectionDetector,
    CryptoMisuseDetector,
    TOCTOUDetector,
    MemorySafetyDetector,
    TypeConfusionDetector,
    LogInjectionDetector,
    XSSDetector,
    EvasionPatternsDetector,
    OperationalSecurityDetector,
)
from src.analysis.taint_tracker import TaintTracker  # noqa: E402
from src.analysis.attack_graph import AttackGraph  # noqa: E402
from src.analysis.sink_classifier import SinkClassifier  # noqa: E402
from src.analysis.reachability import ReachabilityVerifier  # noqa: E402
from src.analysis.remediator import FunctionalRemediator  # noqa: E402

logger = logging.getLogger(__name__)


def _deduplicate_items(items: list[dict]) -> list[dict]:
    def _rank(status: str | None) -> int:
        return {
            "Confirmed Reachable": 4,
            "Requires Manual Review": 3,
            "Unverifiable": 2,
            "Reachability Eliminated": 1,
        }.get(status or "", 0)

    alias_map = {"attribute injection": "mass assignment"}
    unique: dict[tuple, dict] = {}
    for item in items:
        normalized = alias_map.get(
            str(item.get("vulnerability_type", "")).lower(),
            str(item.get("vulnerability_type", "")).lower(),
        )
        key = (item.get("line_number"), normalized, item.get("sink_api", ""))
        if key not in unique:
            unique[key] = item
            continue
        cur = unique[key]
        if _rank(item.get("reachability_status")) > _rank(cur.get("reachability_status")):
            unique[key] = item
        elif (
            _rank(item.get("reachability_status")) == _rank(cur.get("reachability_status"))
            and float(item.get("confidence", 0)) > float(cur.get("confidence", 0))
        ):
            unique[key] = item
    return list(unique.values())


def run_sandbox(
    file_contents: dict[str, bytes],
    job_id: str,
    loop: asyncio.AbstractEventLoop,
) -> dict[str, Any]:
    """
    Synchronous — called via asyncio.to_thread().
    file_contents: mapping of filename → raw bytes
    Returns SandboxResults dict matching web/lib/types.ts SandboxResults.
    """
    from api.core.job_store import get_job

    job = get_job(job_id)

    def push_event(event: dict) -> None:
        if job is not None:
            job.events.append(event)
            loop.call_soon_threadsafe(job.event_queue.put_nowait, event)

    results: dict[str, Any] = {
        "files": {},
        "totals_before": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        "totals_after": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        "total_fixes": 0,
        "total_functional_fixes": 0,
        "total_rejected_fixes": 0,
        "log_lines": [],
    }
    log_lines: list[str] = results["log_lines"]

    def log(msg: str) -> None:
        log_lines.append(msg)
        logger.info("[sandbox:%s] %s", job_id, msg)

    # ── PHASE 0 — SETUP ───────────────────────────────────────────
    push_event({"type": "progress", "message": "Setting up sandbox environment…", "pct": 5})
    sandbox_dir = Path(tempfile.mkdtemp(prefix="nazca_sb_"))

    try:
        ingestion = CodeIngestion(max_file_size_mb=10)
        detectors = [
            PromptInjectionDetector(enabled=True),
            HardcodedSecretsDetector(enabled=True),
            OverprivilegedToolsDetector(enabled=True),
            WeakRandomDetector(enabled=True),
            WeakHashDetector(enabled=True),
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
        taint_tracker = TaintTracker()
        reachability_verifier = ReachabilityVerifier()
        remediator = FunctionalRemediator()

        # Stage all files
        file_data: dict[str, dict] = {}
        for fname, raw in file_contents.items():
            content = raw.decode("utf-8", errors="replace")
            fpath = sandbox_dir / fname
            fpath.write_text(content, encoding="utf-8")
            file_data[fname] = {"content": content, "path": str(fpath)}
            log(f"Staged: {fname} ({len(content.splitlines())} lines)")

        # ── PHASE 1 — DETECTION ───────────────────────────────────
        push_event({"type": "progress", "message": "Phase 1: Pattern detection…", "pct": 15})
        all_before: dict[str, list[dict]] = {}
        all_findings_objs_before: dict[str, list] = {}

        for fname, fdata in file_data.items():
            fd = ingestion.ingest_file(fdata["path"])
            findings = []
            for det in detectors:
                hits = det.detect(fd["code_content"], fd["language"], fd["file_name"])
                findings.extend(hits)
            all_findings_objs_before[fname] = findings
            flist = _deduplicate_items([x.to_dict() for x in findings])
            all_before[fname] = flist
            for item in flist:
                sev = item.get("severity", "MEDIUM").lower()
                results["totals_before"][sev] = results["totals_before"].get(sev, 0) + 1
                results["totals_before"]["total"] += 1

        tb = results["totals_before"]["total"]
        log(f"Phase 1 complete: {tb} pattern finding(s)")

        # ── PHASE 2 — ANALYSIS ────────────────────────────────────
        push_event({"type": "progress", "message": "Phase 2: Static analysis…", "pct": 30})
        attack_paths_before_all: dict[str, list] = {}
        reach_results_before_all: dict[str, list] = {}

        for fname, fdata in file_data.items():
            fd = ingestion.ingest_file(fdata["path"])
            attack_paths: list = []
            reach_results: list = []

            if fd.get("language") == "python":
                nodes, edges = taint_tracker.analyse(fname, fdata["content"])
                if nodes:
                    graph = AttackGraph()
                    graph.add_nodes_and_edges(nodes, edges)
                    attack_paths = graph.enumerate_attack_paths()
                    reach_results = reachability_verifier.verify_paths(
                        attack_paths, fdata["content"], fname
                    )
                    for rr in reach_results:
                        sink_line = rr.path.sink.line
                        matched = False
                        for fd_item in all_before.get(fname, []):
                            if fd_item.get("line_number") == sink_line:
                                fd_item["reachability_status"] = rr.status.value
                                fd_item["reachability_reasoning"] = rr.reasoning
                                fd_item["attack_path"] = rr.path.to_dict()
                                fd_item["sink_api"] = rr.path.sink.name
                                sink_info = SinkClassifier.classify(rr.path.sink.name)
                                if sink_info:
                                    fd_item["vulnerability_type"] = sink_info.vulnerability_type
                                    fd_item["severity"] = sink_info.severity
                                    fd_item["cwe_id"] = sink_info.cwe_id
                                matched = True
                                break
                        if not matched:
                            sink_info = SinkClassifier.classify(rr.path.sink.name)
                            new_item: dict = {
                                "detector_name": "StaticAnalysisPipeline",
                                "vulnerability_type": (
                                    sink_info.vulnerability_type
                                    if sink_info
                                    else rr.path.vulnerability_type
                                ),
                                "severity": sink_info.severity if sink_info else rr.path.severity,
                                "line_number": sink_line,
                                "code_snippet": rr.path.sink.detail,
                                "description": (
                                    f"Tainted data from {rr.path.source.name} "
                                    f"(line {rr.path.source.line}) reaches "
                                    f"{rr.path.sink.name}() at line {sink_line}."
                                ),
                                "confidence": 0.9,
                                "cwe_id": getattr(rr.path, "cwe_id", "") or "",
                                "reachability_status": rr.status.value,
                                "reachability_reasoning": rr.reasoning,
                                "attack_path": rr.path.to_dict(),
                                "sink_api": rr.path.sink.name,
                            }
                            if sink_info:
                                new_item["cwe_id"] = sink_info.cwe_id
                            all_before.setdefault(fname, []).append(new_item)

            attack_paths_before_all[fname] = attack_paths
            reach_results_before_all[fname] = reach_results

        # Recalculate totals after AST enrichment
        results["totals_before"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for fname, items in list(all_before.items()):
            deduped = _deduplicate_items(items)
            all_before[fname] = deduped
            for item in deduped:
                sev = item.get("severity", "MEDIUM").lower()
                results["totals_before"][sev] = results["totals_before"].get(sev, 0) + 1
                results["totals_before"]["total"] += 1

        tb = results["totals_before"]["total"]
        log(f"Phase 2 complete: {tb} total finding(s) after AST analysis")

        if tb == 0:
            for fname in file_data:
                results["files"][fname] = {
                    "findings_before": [],
                    "findings_after": [],
                    "fixes": [],
                    "original_code": file_data[fname]["content"],
                    "fixed_code": file_data[fname]["content"],
                    "attack_paths_before": [
                        p.to_dict() for p in attack_paths_before_all.get(fname, [])
                    ],
                    "attack_paths_after": [],
                    "reachability_before": [
                        r.to_dict() for r in reach_results_before_all.get(fname, [])
                    ],
                    "reachability_after": [],
                }
            results["log_lines"] = log_lines
            push_event({"type": "complete", "results": results})
            return results

        # ── PHASE 3 — REMEDIATION ─────────────────────────────────
        push_event({"type": "progress", "message": "Phase 3: Applying fixes…", "pct": 55})
        fixed_files: dict[str, dict] = {}
        total_functional = 0
        total_rejected = 0

        for fname, reach_results in reach_results_before_all.items():
            original = file_data[fname]["content"]
            pattern_findings = all_before.get(fname, [])
            fixed_code, diffs = remediator.remediate(
                original, reach_results, findings=pattern_findings
            )
            fix_dicts = [d.to_dict() for d in diffs]
            fixed_files[fname] = {"code": fixed_code, "fixes": fix_dicts}
            for d in diffs:
                if d.is_functional:
                    total_functional += 1
                else:
                    total_rejected += 1

        for fname in file_data:
            if fname not in fixed_files:
                fixed_files[fname] = {"code": file_data[fname]["content"], "fixes": []}

        results["total_fixes"] = total_functional + total_rejected
        results["total_functional_fixes"] = total_functional
        results["total_rejected_fixes"] = total_rejected
        log(f"Phase 3 complete: {total_functional} fix(es) applied")

        # ── PHASE 4 — RE-VERIFICATION ─────────────────────────────
        push_event({"type": "progress", "message": "Phase 4: Re-verification…", "pct": 75})
        all_after: dict[str, list[dict]] = {}
        attack_paths_after_all: dict[str, list] = {}
        reach_results_after_all: dict[str, list] = {}

        for fname, fdata_fixed in fixed_files.items():
            fixed_path = sandbox_dir / f"fixed_{fname}"
            fixed_path.write_text(fdata_fixed["code"], encoding="utf-8")
            fd = ingestion.ingest_file(str(fixed_path))

            findings = []
            for det in detectors:
                findings.extend(det.detect(fd["code_content"], fd["language"], fd["file_name"]))
            flist = _deduplicate_items([x.to_dict() for x in findings])
            all_after[fname] = flist

            attack_paths_after: list = []
            reach_results_after: list = []
            if fd.get("language") == "python":
                nodes, edges = taint_tracker.analyse(f"fixed_{fname}", fdata_fixed["code"])
                if nodes:
                    graph = AttackGraph()
                    graph.add_nodes_and_edges(nodes, edges)
                    attack_paths_after = graph.enumerate_attack_paths()
                    reach_results_after = reachability_verifier.verify_paths(
                        attack_paths_after, fdata_fixed["code"], fname
                    )
                    for rr in reach_results_after:
                        sink_line = rr.path.sink.line
                        already = any(
                            fi.get("line_number") == sink_line for fi in all_after.get(fname, [])
                        )
                        if not already:
                            sink_info = SinkClassifier.classify(rr.path.sink.name)
                            new_item = {
                                "detector_name": "StaticAnalysisPipeline",
                                "vulnerability_type": (
                                    sink_info.vulnerability_type
                                    if sink_info
                                    else rr.path.vulnerability_type
                                ),
                                "severity": (
                                    sink_info.severity if sink_info else rr.path.severity
                                ),
                                "line_number": sink_line,
                                "code_snippet": rr.path.sink.detail,
                                "description": (
                                    f"Tainted data from {rr.path.source.name} "
                                    f"(line {rr.path.source.line}) reaches "
                                    f"{rr.path.sink.name}() at line {sink_line}."
                                ),
                                "confidence": 0.9,
                                "cwe_id": (sink_info.cwe_id if sink_info else ""),
                                "reachability_status": rr.status.value,
                                "reachability_reasoning": rr.reasoning,
                                "attack_path": rr.path.to_dict(),
                                "sink_api": rr.path.sink.name,
                            }
                            all_after.setdefault(fname, []).append(new_item)

            attack_paths_after_all[fname] = attack_paths_after
            reach_results_after_all[fname] = reach_results_after

        # Recalculate after-totals
        results["totals_after"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for fname, items in list(all_after.items()):
            deduped = _deduplicate_items(items)
            all_after[fname] = deduped
            for item in deduped:
                sev = item.get("severity", "MEDIUM").lower()
                results["totals_after"][sev] = results["totals_after"].get(sev, 0) + 1
                results["totals_after"]["total"] += 1

        ta = results["totals_after"]["total"]
        log(f"Phase 4 complete: {ta} remaining finding(s) (was {tb})")

        # ── PHASE 5 — ASSEMBLE RESULTS ────────────────────────────
        push_event({"type": "progress", "message": "Phase 5: Assembling results…", "pct": 92})
        for fname in file_data:
            results["files"][fname] = {
                "findings_before": all_before.get(fname, []),
                "findings_after": all_after.get(fname, []),
                "fixes": fixed_files.get(fname, {}).get("fixes", []),
                "original_code": file_data[fname]["content"],
                "fixed_code": fixed_files.get(fname, {}).get("code", ""),
                "attack_paths_before": [
                    p.to_dict() for p in attack_paths_before_all.get(fname, [])
                ],
                "attack_paths_after": [
                    p.to_dict() for p in attack_paths_after_all.get(fname, [])
                ],
                "reachability_before": [
                    r.to_dict() for r in reach_results_before_all.get(fname, [])
                ],
                "reachability_after": [
                    r.to_dict() for r in reach_results_after_all.get(fname, [])
                ],
            }

        results["log_lines"] = log_lines
        push_event({"type": "complete", "results": results})
        return results

    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
