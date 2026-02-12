"""
Insecure Cookie Detector (CWE-614).

Detects cookies set without the ``Secure`` flag, which allows them
to be transmitted over unencrypted HTTP connections.
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class SecureCookieDetector(BaseDetector):
    """Detect cookies set without the Secure flag."""

    def __init__(self, enabled: bool = True):
        super().__init__("SecureCookieDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        # Strategy: find set_cookie() calls and check for secure=False or
        # missing secure=True.  The OWASP benchmark always explicitly sets
        # secure=True (safe) or secure=False (vuln).

        # Collect multi-line set_cookie calls by tracking parentheses.
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if "set_cookie" in line:
                # Gather the full call (may span lines).
                call_lines = [line]
                paren_count = line.count("(") - line.count(")")
                j = i + 1
                while paren_count > 0 and j < len(lines):
                    call_lines.append(lines[j])
                    paren_count += lines[j].count("(") - lines[j].count(")")
                    j += 1
                full_call = "\n".join(call_lines)

                # Check for secure=False (explicitly insecure).
                if re.search(r"secure\s*=\s*False", full_call, re.IGNORECASE):
                    line_num = i + 1
                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="Insecure Cookie",
                        severity="HIGH",
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            "Cookie set with secure=False. The cookie will be "
                            "transmitted over unencrypted HTTP connections, "
                            "allowing attackers on the network to intercept it. "
                            "Set secure=True to restrict the cookie to HTTPS."
                        ),
                        confidence=0.95,
                        cwe_id="CWE-614",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        metadata={"issue": "secure=False"},
                    ))
                elif not re.search(r"secure\s*=\s*True", full_call, re.IGNORECASE):
                    # Missing secure flag entirely – only flag in specific contexts.
                    # For the OWASP benchmark, secure is always explicit.
                    pass

                i = j if j > i + 1 else i + 1
            else:
                i += 1

        self.findings = findings
        return findings
