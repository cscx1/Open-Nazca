#!/usr/bin/env python3
"""
OWASP Benchmark accuracy test harness.

Runs the LLMCheck scanner against all 1230 OWASP BenchmarkPython test cases
and computes per-category and overall accuracy metrics.

Usage (from repo root):
    python scripts/benchmark_test.py

Requires BenchmarkPython/ (clone OWASP Benchmark if missing).
"""

import csv
import os
import sys
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass, field

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.detectors import (
    PromptInjectionDetector,
    HardcodedSecretsDetector,
    OverprivilegedToolsDetector,
    Finding,
)
from src.detectors.weak_random_detector import WeakRandomDetector
from src.detectors.weak_hash_detector import WeakHashDetector
from src.detectors.xpath_injection_detector import XPathInjectionDetector
from src.detectors.xxe_detector import XXEDetector
from src.detectors.sql_injection_detector import SQLInjectionDetector
from src.detectors.deserialization_detector import DeserializationDetector
from src.detectors.secure_cookie_detector import SecureCookieDetector
from src.detectors.trust_boundary_detector import TrustBoundaryDetector
from src.detectors.ldap_injection_detector import LDAPInjectionDetector
from src.detectors.general_flow_detector import GeneralFlowDetector
from src.analysis.taint_tracker import TaintTracker
from src.analysis.attack_graph import AttackGraph
from src.analysis.sink_classifier import SinkClassifier
from src.analysis.reachability import ReachabilityVerifier, ReachabilityStatus

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ── OWASP category → our vulnerability type mapping ──────────────

OWASP_TO_VULN_TYPES: Dict[str, Set[str]] = {
    "pathtraver":      {"Path Traversal"},
    "sqli":            {"SQL Injection"},
    "xpathi":          {"XPath Injection"},
    "xxe":             {"XML External Entity (XXE)"},
    "weakrand":        {"Weak Random"},
    "hash":            {"Weak Hash"},
    "xss":             {"XSS / Template Injection", "XSS"},
    "deserialization": {"Unsafe Deserialization"},
    "securecookie":    {"Insecure Cookie"},
    "trustbound":      {"Trust Boundary Violation"},
    "redirect":        {"Open Redirect"},
    "ldapi":           {"LDAP Injection"},
    "cmdi":            {"Command Injection"},
    "codeinj":         {"Code Execution", "Code Injection"},
}


@dataclass
class CategoryStats:
    tp: int = 0   # true positive: expected vuln, detected
    fp: int = 0   # false positive: expected safe, detected as vuln
    tn: int = 0   # true negative: expected safe, not detected
    fn: int = 0   # false negative: expected vuln, not detected
    errors: int = 0

    @property
    def total(self): return self.tp + self.fp + self.tn + self.fn

    @property
    def accuracy(self):
        t = self.total
        return (self.tp + self.tn) / t if t else 0.0

    @property
    def tpr(self):
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self):
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def precision(self):
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def f1(self):
        p, r = self.precision, self.tpr
        return 2 * p * r / (p + r) if (p + r) else 0.0


def load_expected(csv_path: str) -> List[Tuple[str, str, bool, int]]:
    """Parse expectedresults CSV → list of (test_name, category, is_vuln, cwe)."""
    results = []
    with open(csv_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            name = parts[0].strip()
            cat = parts[1].strip()
            is_vuln = parts[2].strip().lower() == "true"
            cwe = int(parts[3].strip())
            results.append((name, cat, is_vuln, cwe))
    return results


def scan_file_lightweight(
    code: str,
    file_name: str,
    detectors: list,
    taint_tracker: TaintTracker,
    reachability_verifier: ReachabilityVerifier,
) -> List[Finding]:
    """Run all detectors + taint pipeline on code, return findings."""
    all_findings: List[Finding] = []

    # 1. Pattern-based detectors
    for det in detectors:
        try:
            findings = det.detect(code, "python", file_name)
            all_findings.extend(findings)
        except Exception as e:
            logger.debug(f"Detector {det.name} error on {file_name}: {e}")

    # 2. Taint analysis
    try:
        nodes, edges = taint_tracker.analyse(file_name, code)
        if nodes:
            graph = AttackGraph()
            graph.add_nodes_and_edges(nodes, edges)
            paths = graph.enumerate_attack_paths()
            if paths:
                reach = reachability_verifier.verify_paths(paths, code, file_name)
                for rr in reach:
                    if rr.status in (
                        ReachabilityStatus.CONFIRMED_REACHABLE,
                        ReachabilityStatus.UNVERIFIABLE,
                        ReachabilityStatus.REQUIRES_MANUAL_REVIEW,
                    ):
                        sink_info = SinkClassifier.classify(rr.path.sink.name)
                        vuln_type = rr.path.vulnerability_type
                        severity = rr.path.severity
                        cwe_id = rr.path.cwe_id
                        if sink_info:
                            vuln_type = sink_info.vulnerability_type
                            severity = sink_info.severity
                            cwe_id = sink_info.cwe_id

                        finding = Finding(
                            detector_name="TaintAnalysis",
                            vulnerability_type=vuln_type,
                            severity=severity,
                            line_number=rr.path.sink.line,
                            code_snippet="",
                            description=rr.path.sink.detail,
                            confidence=0.9,
                            cwe_id=cwe_id,
                            reachability_status=rr.status.value,
                        )
                        all_findings.append(finding)
    except Exception as e:
        logger.debug(f"Taint analysis error on {file_name}: {e}")

    return all_findings


def findings_match_category(
    findings: List[Finding], owasp_cat: str
) -> bool:
    """Check if any finding matches the expected OWASP category."""
    expected_types = OWASP_TO_VULN_TYPES.get(owasp_cat, set())
    for f in findings:
        vtype = f.vulnerability_type
        if vtype in expected_types:
            return True
        # Fuzzy matching for variants
        vtype_lower = vtype.lower()
        for et in expected_types:
            if et.lower() in vtype_lower or vtype_lower in et.lower():
                return True
    return False


def main():
    benchmark_dir = REPO_ROOT / "BenchmarkPython"
    csv_path = benchmark_dir / "expectedresults-0.1.csv"
    testcode_dir = benchmark_dir / "testcode"

    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found. Clone BenchmarkPython first.")
        sys.exit(1)

    # Load expected results
    expected = load_expected(str(csv_path))
    print(f"Loaded {len(expected)} test cases from OWASP Benchmark")

    # Initialize detectors
    detectors = [
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
        GeneralFlowDetector(enabled=True),
    ]
    taint_tracker = TaintTracker()
    reachability = ReachabilityVerifier()

    print(f"Initialized {len(detectors)} detectors + taint analysis pipeline")
    print("=" * 80)
    print("Running benchmark...")

    # Per-category stats
    cat_stats: Dict[str, CategoryStats] = {}
    overall = CategoryStats()

    start = time.time()
    total = len(expected)

    for i, (test_name, category, is_vuln, cwe) in enumerate(expected):
        if category not in cat_stats:
            cat_stats[category] = CategoryStats()

        file_path = testcode_dir / f"{test_name}.py"
        if not file_path.exists():
            cat_stats[category].errors += 1
            continue

        code = file_path.read_text(errors="replace")

        findings = scan_file_lightweight(
            code, test_name + ".py", detectors, taint_tracker, reachability
        )

        detected = findings_match_category(findings, category)

        if is_vuln and detected:
            cat_stats[category].tp += 1
            overall.tp += 1
        elif is_vuln and not detected:
            cat_stats[category].fn += 1
            overall.fn += 1
        elif not is_vuln and detected:
            cat_stats[category].fp += 1
            overall.fp += 1
        else:
            cat_stats[category].tn += 1
            overall.tn += 1

        # Progress
        if (i + 1) % 100 == 0 or (i + 1) == total:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            eta = (total - i - 1) / rate if rate else 0
            print(f"  [{i+1:4d}/{total}] {rate:.0f} files/sec, ETA {eta:.0f}s "
                  f"| TP={overall.tp} FP={overall.fp} TN={overall.tn} FN={overall.fn}")

    elapsed = time.time() - start

    # ── Report ────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("OWASP BENCHMARK RESULTS")
    print("=" * 80)

    print(f"\n{'Category':<18} {'Total':>5} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Acc':>6} {'TPR':>6} {'FPR':>6} {'Prec':>6} {'F1':>6}")
    print("-" * 80)

    for cat in sorted(cat_stats.keys()):
        s = cat_stats[cat]
        print(f"{cat:<18} {s.total:>5} {s.tp:>4} {s.fp:>4} {s.tn:>4} {s.fn:>4} "
              f"{s.accuracy:>5.1%} {s.tpr:>5.1%} {s.fpr:>5.1%} "
              f"{s.precision:>5.1%} {s.f1:>5.1%}")

    print("-" * 80)
    print(f"{'OVERALL':<18} {overall.total:>5} {overall.tp:>4} {overall.fp:>4} "
          f"{overall.tn:>4} {overall.fn:>4} "
          f"{overall.accuracy:>5.1%} {overall.tpr:>5.1%} {overall.fpr:>5.1%} "
          f"{overall.precision:>5.1%} {overall.f1:>5.1%}")

    print(f"\nElapsed: {elapsed:.1f}s ({len(expected)/elapsed:.0f} files/sec)")
    print(f"Overall Accuracy: {overall.accuracy:.1%}")
    print(f"Benchmark Score (TPR - FPR): {overall.tpr - overall.fpr:.1%}")


if __name__ == "__main__":
    main()
