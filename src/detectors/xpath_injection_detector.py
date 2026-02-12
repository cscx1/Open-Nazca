"""
XPath Injection Detector (CWE-643).

Detects user input interpolated into XPath expressions, enabling
attackers to modify the query logic.

Sinks: ``lxml.etree.XPath()``, ``elementpath.select()``, ``tree.xpath()``
"""

import ast
import re
from typing import List, Set
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# XPath sink patterns.
_XPATH_SINKS = re.compile(
    r"(?:lxml\.etree\.XPath|elementpath\.select|\.xpath)\s*\(",
    re.IGNORECASE,
)

# Input source patterns – variables assigned from request/input.
_SOURCE_PATTERN = re.compile(
    r"(\w+)\s*=\s*(?:urllib\.parse\.unquote_plus\s*\()?(?:request\."
    r"(?:cookies|form|args|json|headers|data)(?:\.get(?:list)?)?|"
    r"input\s*\(|params\[|sys\.argv)",
)


class XPathInjectionDetector(BaseDetector):
    """Detect XPath injection via unsanitised user input."""

    def __init__(self, enabled: bool = True):
        super().__init__("XPathInjectionDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if language not in ("python", "javascript", "typescript"):
            return findings

        lines = code.split("\n")

        # Pass 1: find tainted variables (names assigned from user input).
        tainted: Set[str] = set()
        for line in lines:
            m = _SOURCE_PATTERN.search(line)
            if m:
                tainted.add(m.group(1))

        # Track simple propagation: bar = param | bar = <something involving param>
        for _pass in range(3):  # iterate to propagate
            for line in lines:
                m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
                if m:
                    lhs, rhs = m.group(1), m.group(2)
                    # Iterate over a snapshot so tainted can be safely expanded.
                    for t in tuple(tainted):
                        if re.search(rf"\b{re.escape(t)}\b", rhs):
                            tainted.add(lhs)

        # Pass 2: find XPath sinks that use tainted variables.
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if _XPATH_SINKS.search(line):
                # Check if any tainted variable appears in this line or the
                # few preceding lines (the query is often built just above).
                region_start = max(0, line_num - 6)
                region = "\n".join(lines[region_start:line_num])
                for t in tainted:
                    if re.search(rf"\b{re.escape(t)}\b", region):
                        snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                        findings.append(Finding(
                            detector_name=self.name,
                            vulnerability_type="XPath Injection",
                            severity="CRITICAL",
                            line_number=line_num,
                            code_snippet=snippet,
                            description=(
                                f"User-controlled variable '{t}' is interpolated into "
                                f"an XPath expression. This allows attackers to modify "
                                f"the query logic and extract unauthorised data."
                            ),
                            confidence=0.90,
                            cwe_id="CWE-643",
                            owasp_category="A03:2021 – Injection",
                            metadata={"tainted_var": t},
                        ))
                        break

        self.findings = findings
        return findings
