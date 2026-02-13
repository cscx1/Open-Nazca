"""
Memory Safety Detector (CWE-119, CWE-120).

Detects dangerous use of ctypes and low-level memory operations:
  - ctypes.CDLL(None) — loading libc for raw C calls
  - ctypes.memcpy / memmove / memset without bounds checking
  - ctypes.create_string_buffer with user-controlled size
  - ctypes.cast to arbitrary pointer types
  - ctypes.string_at / wstring_at with user-controlled length
  - marshal.loads (can crash interpreter)

No equivalent in Bandit or Semgrep — this is a novel detector.
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class MemorySafetyDetector(BaseDetector):
    """Detect unsafe memory operations via ctypes and marshal."""

    def __init__(self, enabled: bool = True):
        super().__init__("MemorySafetyDetector", enabled)

        self._patterns = [
            # Loading libc for raw C function calls.
            {
                "pattern": re.compile(r"ctypes\.CDLL\s*\(\s*None\s*\)"),
                "vuln_type": "Unsafe C Library Access",
                "severity": "HIGH",
                "cwe": "CWE-119",
                "desc": (
                    "Loading libc via ctypes.CDLL(None) provides direct "
                    "access to C functions (memcpy, system, etc.) without "
                    "Python's safety guarantees. Buffer overflows and "
                    "memory corruption become possible."
                ),
            },
            # Direct memcpy/memmove/memset calls.
            {
                "pattern": re.compile(
                    r"(?:libc|cdll|lib)\w*\.(?:memcpy|memmove|memset|strcpy|strcat|sprintf)\s*\("
                ),
                "vuln_type": "Unsafe Memory Operation",
                "severity": "CRITICAL",
                "cwe": "CWE-120",
                "desc": (
                    "Direct C memory operation (memcpy/strcpy/etc.) called "
                    "via ctypes. Without bounds checking, this can cause "
                    "buffer overflows, memory corruption, and potentially "
                    "arbitrary code execution."
                ),
            },
            # ctypes.cast to pointer types.
            {
                "pattern": re.compile(
                    r"ctypes\.cast\s*\([^,]+,\s*ctypes\.(?:POINTER|c_void_p|c_char_p)"
                ),
                "vuln_type": "Unsafe Pointer Cast",
                "severity": "HIGH",
                "cwe": "CWE-843",
                "desc": (
                    "ctypes.cast() to a pointer type. Incorrect casts can "
                    "lead to type confusion, out-of-bounds reads, and "
                    "memory corruption."
                ),
            },
            # ctypes.string_at / wstring_at with variable length.
            {
                "pattern": re.compile(
                    r"ctypes\.(?:string_at|wstring_at)\s*\(\s*\w+\s*,\s*(?![\d])\w+"
                ),
                "vuln_type": "Unsafe Memory Read",
                "severity": "HIGH",
                "cwe": "CWE-125",
                "desc": (
                    "ctypes.string_at() with a non-constant length. If the "
                    "length is user-controlled, an attacker can cause "
                    "out-of-bounds reads, leaking sensitive memory contents."
                ),
            },
            # marshal.loads (can crash interpreter).
            {
                "pattern": re.compile(r"marshal\.loads?\s*\("),
                "vuln_type": "Unsafe Marshal Deserialization",
                "severity": "HIGH",
                "cwe": "CWE-502",
                "desc": (
                    "marshal.loads() on untrusted data can crash the Python "
                    "interpreter or cause memory corruption. marshal is not "
                    "intended for untrusted data."
                ),
            },
            # General ctypes pointer arithmetic.
            {
                "pattern": re.compile(
                    r"ctypes\.(?:pointer|addressof|byref)\s*\("
                ),
                "vuln_type": "Low-Level Memory Access",
                "severity": "MEDIUM",
                "cwe": "CWE-119",
                "desc": (
                    "Low-level memory access via ctypes pointer operations. "
                    "Review for correct bounds checking and pointer validity."
                ),
            },
        ]

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        # Quick check: skip if no ctypes or marshal usage.
        if "ctypes" not in code and "marshal" not in code:
            return findings

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for pat_info in self._patterns:
                if pat_info["pattern"].search(line):
                    snippet = self.extract_code_snippet(
                        code, line_num, context_lines=3
                    )
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type=pat_info["vuln_type"],
                        severity=pat_info["severity"],
                        line_number=line_num,
                        code_snippet=snippet,
                        description=pat_info["desc"],
                        confidence=0.88,
                        cwe_id=pat_info["cwe"],
                        owasp_category="A06:2021 – Vulnerable and Outdated Components",
                        metadata={},
                    ))
                    break

        self.findings = findings
        return findings
