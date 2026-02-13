"""
SQL Injection Detector (CWE-89).

Pattern-based detection of user input or f-strings used in SQL execution
without parameterisation. Sinks: cursor.execute(), connection.execute(),
engine.execute(), etc.
"""

import re
from typing import List, Set
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# SQL execution sink patterns (single-argument or f-string).
_SQL_EXECUTE = re.compile(
    r"\.(?:execute|executemany)\s*\(",
    re.IGNORECASE,
)

# F-string or format in execute call: execute(f"..."), execute("...".format())
_EXECUTE_FSTRING = re.compile(
    r"\.(?:execute|executemany)\s*\(\s*f['\"]",
    re.IGNORECASE,
)
_EXECUTE_SQL_VAR = re.compile(
    r"\.(?:execute|executemany)\s*\(\s*(\w+)\s*\)",
    re.IGNORECASE,
)

# Query built with f-string or % or + (in same or previous lines).
_QUERY_FSTRING = re.compile(
    r"(?:query|sql|stmt)\s*=\s*f['\"]",
    re.IGNORECASE,
)
_QUERY_CONCAT = re.compile(
    r"(?:query|sql|stmt)\s*=\s*['\"].*?(?:\+|\%s|\%d|\%)",
    re.IGNORECASE,
)

# Parameterised = second argument is tuple/list of params (safe).
_PARAMETERISED = re.compile(
    r"\.(?:execute|executemany)\s*\([^,]+,\s*[\(\[]",
    re.IGNORECASE,
)

# Input source patterns.
_SOURCE_PATTERN = re.compile(
    r"(\w+)\s*=\s*(?:request\.(?:cookies|form|args|json|headers|data)(?:\.get(?:list)?)?|"
    r"input\s*\(|params\[|sys\.argv|get\(|post\s*\()",
    re.IGNORECASE,
)


class SQLInjectionDetector(BaseDetector):
    """Detect SQL injection via unparameterised execute with user input or f-strings."""

    def __init__(self, enabled: bool = True):
        super().__init__("SQLInjectionDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if language != "python":
            return findings

        lines = code.split("\n")
        tainted = self._track_taint(lines)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Skip if this line is clearly parameterised.
            if _PARAMETERISED.search(line):
                continue

            if not _SQL_EXECUTE.search(line):
                continue

            # Case 1: execute(f"...") or execute("...".format(...))
            if _EXECUTE_FSTRING.search(line):
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="SQL Injection",
                    severity="CRITICAL",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "SQL is built with an f-string or format. Use parameterised "
                        "queries: execute(sql, (param1, param2)) and build sql with "
                        "placeholders (?, %s, :name) only."
                    ),
                    confidence=0.92,
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 – Injection",
                ))
                continue

            # Case 2: execute(sql_var) — check if sql_var was built from tainted data
            m = _EXECUTE_SQL_VAR.search(line)
            if m:
                var = m.group(1)
                region_start = max(0, line_num - 12)
                region = "\n".join(lines[region_start:line_num + 1])
                if var in tainted or _QUERY_FSTRING.search(region) or _QUERY_CONCAT.search(region):
                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="SQL Injection",
                        severity="CRITICAL",
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            f"Variable '{var}' (or a query built with f-string/concatenation) "
                            "reaches execute() without parameterisation. Use execute(sql, (params,)) "
                            "and build sql with placeholders only."
                        ),
                        confidence=0.88,
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 – Injection",
                        metadata={"sql_var": var},
                    ))

        self.findings = findings
        return findings

    def _track_taint(self, lines: List[str]) -> Set[str]:
        tainted: Set[str] = set()
        for line in lines:
            m = _SOURCE_PATTERN.search(line)
            if m:
                tainted.add(m.group(1))
        for _ in range(3):
            for line in lines:
                m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
                if m:
                    lhs, rhs = m.group(1), m.group(2)
                    for t in tuple(tainted):
                        if re.search(rf"\b{re.escape(t)}\b", rhs):
                            tainted.add(lhs)
        return tainted
