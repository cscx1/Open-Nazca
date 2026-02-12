#!/usr/bin/env python3
"""
Validate each new detector against Bandit's example files.
Reports what each detector finds and highlights false positives / missed patterns.

Usage (from repo root):
    python scripts/validate_detectors.py

Requires bandit-tests/ (Bandit example files).
"""
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.detectors.xxe_detector import XXEDetector
from src.detectors.crypto_misuse_detector import CryptoMisuseDetector
from src.detectors.unsafe_reflection_detector import UnsafeReflectionDetector
from src.detectors.toctou_detector import TOCTOUDetector
from src.detectors.memory_safety_detector import MemorySafetyDetector
from src.detectors.type_confusion_detector import TypeConfusionDetector
from src.detectors.weak_random_detector import WeakRandomDetector
from src.detectors.weak_hash_detector import WeakHashDetector
from src.detectors.deserialization_detector import DeserializationDetector

BANDIT = REPO_ROOT / "bandit-tests" / "examples"

# Map: (Detector, [test_files], expected_finding_description)
TESTS = [
    # ── XXE ────────────────────────────────────────────────
    ("XXE Detector", XXEDetector(), [
        "xml_etree_elementtree.py",
        "xml_etree_celementtree.py",
        "xml_sax.py",
        "xml_minidom.py",
        "xml_pulldom.py",
        "xml_expatbuilder.py",
        "xml_expatreader.py",
    ], "Should find XXE vulns in all stdlib XML files"),

    # ── Crypto ─────────────────────────────────────────────
    ("Crypto Misuse Detector", CryptoMisuseDetector(), [
        "ciphers.py",
        "cipher-modes.py",
        "pycrypto.py",
        "crypto-md5.py",
        "weak_cryptographic_key_sizes.py",
    ], "Should find weak ciphers, ECB, weak keys, weak hashes"),

    # ── Reflection ─────────────────────────────────────────
    ("Unsafe Reflection Detector", UnsafeReflectionDetector(), [
        "imports-with-importlib.py",
        "imports-function.py",
    ], "Should find __import__, importlib patterns"),

    # ── TOCTOU ─────────────────────────────────────────────
    ("TOCTOU Detector", TOCTOUDetector(), [
        "mktemp.py",
    ], "Should find mktemp usage"),

    # ── Deserialization ────────────────────────────────────
    ("Deserialization Detector", DeserializationDetector(), [
        "pickle_deserialize.py",
        "marshal_deserialize.py",
        "yaml_load.py",
        "shelve_open.py",
        "dill.py",
        "jsonpickle.py",
    ], "Should find all unsafe deserialization"),

    # ── Weak Random ────────────────────────────────────────
    ("Weak Random Detector", WeakRandomDetector(), [
        "random_module.py",
    ], "Should find random module usage"),

    # ── Weak Hash ──────────────────────────────────────────
    ("Weak Hash Detector", WeakHashDetector(), [
        "hashlib_new_insecure_functions.py",
        "crypto-md5.py",
    ], "Should find MD5/SHA1 usage"),

    # ── Safe file (FALSE POSITIVE check) ──────────────────
    ("All Detectors (FP check)", None, [
        "okay.py",
    ], "Should find ZERO vulnerabilities (safe code)"),
]


def run_tests():
    total_pass = 0
    total_fail = 0

    for test_name, detector, files, description in TESTS:
        print(f"\n{'='*70}")
        print(f"  {test_name}")
        print(f"  {description}")
        print(f"{'='*70}")

        for fname in files:
            fpath = BANDIT / fname
            if not fpath.exists():
                print(f"  ⚠ {fname}: FILE NOT FOUND")
                continue

            code = fpath.read_text(errors="replace")

            if detector is None:
                # FP check: run ALL detectors
                from src.detectors import (
                    XXEDetector, CryptoMisuseDetector,
                    UnsafeReflectionDetector, TOCTOUDetector,
                    MemorySafetyDetector, TypeConfusionDetector,
                )
                all_findings = []
                for d in [XXEDetector(), CryptoMisuseDetector(),
                          UnsafeReflectionDetector(), TOCTOUDetector(),
                          MemorySafetyDetector(), TypeConfusionDetector()]:
                    all_findings.extend(d.detect(code, "python", fname))
                findings = all_findings
            else:
                findings = detector.detect(code, "python", fname)

            if findings:
                status = "✅" if detector is not None else "❌ FALSE POSITIVE"
                if detector is None:
                    total_fail += 1
                else:
                    total_pass += 1
            else:
                status = "❌ MISSED" if detector is not None else "✅ CLEAN"
                if detector is not None:
                    total_fail += 1
                else:
                    total_pass += 1

            print(f"  {status} {fname}: {len(findings)} findings")
            for f in findings[:5]:
                print(f"      L{f.line_number}: [{f.severity}] {f.vulnerability_type}")
            if len(findings) > 5:
                print(f"      ... and {len(findings) - 5} more")

    print(f"\n{'='*70}")
    print(f"SUMMARY: {total_pass} passed, {total_fail} failed")
    print(f"{'='*70}")


if __name__ == "__main__":
    run_tests()
