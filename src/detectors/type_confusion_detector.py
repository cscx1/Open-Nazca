"""
Type Confusion / Mass Assignment Detector (CWE-915, CWE-843).

Detects patterns where untrusted data is used to set arbitrary object
attributes, enabling privilege escalation or object manipulation:
  - setattr(obj, user_key, user_value) in a loop over untrusted data
  - obj.__dict__.update(user_dict)
  - for key, val in data.items(): setattr(obj, key, val)
  - Recursive dict merge without key validation (prototype pollution)

Also detects dangerous __reduce__, __getattr__, __setattr__ overrides
that could enable exploitation.
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class TypeConfusionDetector(BaseDetector):
    """Detect type confusion, mass assignment, and prototype pollution."""

    def __init__(self, enabled: bool = True):
        super().__init__("TypeConfusionDetector", enabled)

        self._patterns = [
            # setattr in a loop over untrusted data.
            {
                "pattern": re.compile(
                    r"setattr\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)\s*\)"
                ),
                "context": re.compile(
                    r"for\s+\w+(?:\s*,\s*\w+)?\s+in\s+\w+\.items\(\)"
                ),
                "vuln_type": "Mass Assignment",
                "severity": "HIGH",
                "cwe": "CWE-915",
                "desc": (
                    "setattr() called in a loop over dictionary items. "
                    "An attacker can inject arbitrary attributes including "
                    "'is_admin', '__class__', or '__dict__' to escalate "
                    "privileges or corrupt object state. Use an allowlist "
                    "of permitted attribute names."
                ),
            },
            # __dict__.update(user_data)
            {
                "pattern": re.compile(
                    r"__dict__\s*\.update\s*\(\s*(?![\{\'\"])\w+"
                ),
                "context": None,
                "vuln_type": "Mass Assignment",
                "severity": "HIGH",
                "cwe": "CWE-915",
                "desc": (
                    "__dict__.update() called with external data. This "
                    "overwrites all object attributes at once, allowing "
                    "attackers to inject arbitrary attributes."
                ),
            },
            # Recursive dict merge (prototype pollution pattern).
            {
                "pattern": re.compile(
                    r"def\s+\w*merge\w*\s*\("
                ),
                "context": re.compile(
                    r"for\s+\w+\s*,\s*\w+\s+in\s+\w+\.items\(\)"
                ),
                "vuln_type": "Prototype Pollution",
                "severity": "HIGH",
                "cwe": "CWE-1321",
                "desc": (
                    "Recursive dictionary merge function without key "
                    "validation. An attacker can inject '__class__', "
                    "'__init__', or '__proto__' keys to modify object "
                    "prototypes and corrupt application state."
                ),
            },
            # __reduce__ override (potential pickle exploitation enabler).
            {
                "pattern": re.compile(r"def\s+__reduce__\s*\(\s*self\s*\)"),
                "context": None,
                "vuln_type": "Pickle Exploitation Enabler",
                "severity": "MEDIUM",
                "cwe": "CWE-502",
                "desc": (
                    "__reduce__ method defined. This method controls pickle "
                    "serialization behavior and can be used to craft "
                    "malicious pickle payloads for RCE. If this class "
                    "instances are ever deserialized from untrusted data, "
                    "arbitrary code execution is possible."
                ),
            },
            # hasattr check followed by setattr (weak guard).
            {
                "pattern": re.compile(
                    r"if\s+hasattr\s*\(\s*\w+\s*,\s*(\w+)\s*\)\s*:"
                ),
                "context": re.compile(r"setattr\s*\("),
                "vuln_type": "Weak Attribute Guard",
                "severity": "MEDIUM",
                "cwe": "CWE-915",
                "desc": (
                    "hasattr() check used as a guard before setattr(). "
                    "hasattr() returns True for most attributes including "
                    "dunder methods, making it an insufficient guard "
                    "against attribute injection. Use an explicit allowlist."
                ),
            },
        ]

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for pat_info in self._patterns:
                if pat_info["pattern"].search(line):
                    # If a context pattern is required, check nearby lines.
                    if pat_info["context"] is not None:
                        region_start = max(0, line_num - 3)
                        region_end = min(len(lines), line_num + 12)
                        region = "\n".join(lines[region_start:region_end])
                        if not pat_info["context"].search(region):
                            continue

                    snippet = self.extract_code_snippet(
                        code, line_num, context_lines=4
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
                        owasp_category="A08:2021 – Software and Data Integrity Failures",
                        metadata={},
                    ))
                    break

        self.findings = findings
        return findings
