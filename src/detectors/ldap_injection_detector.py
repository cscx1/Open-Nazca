"""
LDAP Injection Detector (CWE-90).

Detects user input interpolated into LDAP filter strings, which
allows attackers to modify the query and bypass authentication or
extract data.
"""

import re
from typing import List, Set
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# LDAP sink patterns.
_LDAP_SINKS = re.compile(
    r"(?:conn|connection|ldap_conn|l)\.search(?:_s|_ext|_ext_s)?\s*\(",
    re.IGNORECASE,
)

# LDAP filter construction patterns.
_FILTER_PATTERN = re.compile(
    r"(?:filter|ldap_filter|search_filter)\s*=\s*f['\"]|"
    r"(?:filter|ldap_filter|search_filter)\s*=\s*['\"].*?%|"
    r"(?:filter|ldap_filter|search_filter)\s*=\s*['\"].*?\+",
    re.IGNORECASE,
)

# Input source patterns.
_SOURCE_PATTERN = re.compile(
    r"(\w+)\s*=\s*(?:urllib\.parse\.unquote_plus\s*\()?(?:request\."
    r"(?:cookies|form|args|json|headers|data)(?:\.get(?:list)?)?|"
    r"input\s*\(|params\[|sys\.argv)",
)


class LDAPInjectionDetector(BaseDetector):
    """Detect LDAP injection via unsanitised user input in filters."""

    def __init__(self, enabled: bool = True):
        super().__init__("LDAPInjectionDetector", enabled)

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
        # Propagate.
        for _ in range(3):
            for line in lines:
                m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
                if m:
                    lhs, rhs = m.group(1), m.group(2)
                    # Iterate over a snapshot; tainted may grow during propagation.
                    for t in tuple(tainted):
                        if re.search(rf"\b{re.escape(t)}\b", rhs):
                            tainted.add(lhs)

        # Find LDAP filter strings with tainted data and conn.search calls.
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for LDAP search call or filter construction.
            if _LDAP_SINKS.search(line) or _FILTER_PATTERN.search(line):
                # Look in a region around this line for tainted variables.
                region_start = max(0, line_num - 8)
                region_end = min(len(lines), line_num + 2)
                region = "\n".join(lines[region_start:region_end])

                for t in tainted:
                    if re.search(rf"\b{re.escape(t)}\b", region):
                        snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                        findings.append(Finding(
                            detector_name=self.name,
                            vulnerability_type="LDAP Injection",
                            severity="CRITICAL",
                            line_number=line_num,
                            code_snippet=snippet,
                            description=(
                                f"User-controlled variable '{t}' is used in an LDAP "
                                f"filter/search. An attacker can modify the LDAP query "
                                f"to bypass authentication or extract data. Use "
                                f"ldap3.utils.dn.escape_rdn or parameterised filters."
                            ),
                            confidence=0.90,
                            cwe_id="CWE-90",
                            owasp_category="A03:2021 – Injection",
                            metadata={"tainted_var": t},
                        ))
                        break

        self.findings = findings
        return findings
