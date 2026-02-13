"""
Trust Boundary Violation Detector (CWE-501).

Detects when user-controlled data crosses a trust boundary by being
stored in a session, application context, or other trusted data store
without validation.
"""

import re
from typing import List, Set
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# Trusted storage sinks.
_TRUST_SINKS = re.compile(
    r"(?:flask\.)?session\s*\[|"
    r"(?:flask\.)?g\.\w+\s*=|"
    r"app\.config\s*\[",
)

# Input source patterns.
_SOURCE_PATTERN = re.compile(
    r"(\w+)\s*=\s*(?:urllib\.parse\.unquote_plus\s*\()?(?:request\."
    r"(?:cookies|form|args|json|headers|data)(?:\.get(?:list)?)?|"
    r"input\s*\(|params\[|sys\.argv)",
)


class TrustBoundaryDetector(BaseDetector):
    """Detect trust boundary violations (user data → session/config)."""

    def __init__(self, enabled: bool = True):
        super().__init__("TrustBoundaryDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if language not in ("python", "javascript", "typescript"):
            return findings

        lines = code.split("\n")

        # Collect tainted variables.
        tainted: Set[str] = set()
        for line in lines:
            m = _SOURCE_PATTERN.search(line)
            if m:
                tainted.add(m.group(1))

        # Propagate taint through simple assignments (3 passes).
        for _ in range(3):
            for line in lines:
                m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
                if m:
                    lhs, rhs = m.group(1), m.group(2)
                    # Iterate over a snapshot; tainted may grow during propagation.
                    for t in tuple(tainted):
                        if re.search(rf"\b{re.escape(t)}\b", rhs):
                            tainted.add(lhs)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if _TRUST_SINKS.search(line):
                # Check if tainted variable is used in the session assignment.
                for t in tainted:
                    if re.search(rf"\b{re.escape(t)}\b", line):
                        snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                        findings.append(Finding(
                            detector_name=self.name,
                            vulnerability_type="Trust Boundary Violation",
                            severity="HIGH",
                            line_number=line_num,
                            code_snippet=snippet,
                            description=(
                                f"User-controlled variable '{t}' is stored in a trusted "
                                f"data store (session/config). This crosses a trust "
                                f"boundary and may allow attackers to manipulate "
                                f"application state or escalate privileges."
                            ),
                            confidence=0.88,
                            cwe_id="CWE-501",
                            owasp_category="A04:2021 – Insecure Design",
                            metadata={"tainted_var": t},
                        ))
                        break

        self.findings = findings
        return findings
