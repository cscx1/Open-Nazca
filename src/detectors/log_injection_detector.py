"""
Log Injection Detector (CWE-117).

Detects when user-controlled data is written to log files or logging
functions without sanitization of newline/control characters, allowing
attackers to forge log entries.
"""

import re
from typing import List, Set
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# Log sink patterns - functions that write to logs.
_LOG_SINKS = re.compile(
    r"(?:"
    r"logging\.(?:info|warning|error|debug|critical)\s*\(|"
    r"logger\.(?:info|warning|error|debug|critical)\s*\(|"
    r"log\.(?:info|warning|error|debug|critical)\s*\(|"
    r"\.write\s*\(\s*(?:log_entry|f['\"])"
    r")"
)

# Patterns indicating user input being formatted into log strings.
_LOG_FORMAT_PATTERNS = [
    # f-string with user variable in log context
    re.compile(r"f['\"].*\{(\w+)\}.*['\"]"),
    # % formatting
    re.compile(r"['\"].*%s.*['\"].*%\s*(\w+)"),
    # .format()
    re.compile(r"\.format\s*\(.*?(\w+)"),
]

# Input source patterns.
_SOURCE_PATTERN = re.compile(
    r"(\w+)\s*=\s*(?:request\.|input\s*\(|params\[|sys\.argv)"
)


class LogInjectionDetector(BaseDetector):
    """Detect log injection via unsanitized user input in log entries."""

    def __init__(self, enabled: bool = True):
        super().__init__("LogInjectionDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        # Collect user input variable names from function parameters
        # and explicit input sources.
        user_vars: Set[str] = set()
        for line in lines:
            m = _SOURCE_PATTERN.search(line)
            if m:
                user_vars.add(m.group(1))

        # Also treat function parameters as potential user input.
        for line in lines:
            m = re.match(r"\s*def\s+\w+\s*\(self,?\s*(.*?)\)\s*:", line)
            if m:
                params = m.group(1)
                for p in params.split(","):
                    pname = p.strip().split(":")[0].split("=")[0].strip()
                    if pname and pname != "self":
                        user_vars.add(pname)

        if not user_vars:
            return findings

        # Propagate taint through simple assignments (track f-strings etc.).
        tainted = set(user_vars)
        for _pass in range(3):
            for line in lines:
                m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
                if m:
                    lhs, rhs = m.group(1), m.group(2)
                    for t in list(tainted):
                        if re.search(rf"\b{re.escape(t)}\b", rhs):
                            tainted.add(lhs)

        # Look for log writes that include tainted variables.
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for file.write() or logging calls.
            is_log_write = bool(_LOG_SINKS.search(line))
            # Also check: any .write() call with a tainted argument.
            is_file_write = bool(re.search(r"\.write\s*\(", line))

            if not is_log_write and not is_file_write:
                continue

            # Check if any tainted variable appears in the write call.
            for var in tainted:
                if re.search(rf"\b{re.escape(var)}\b", line):
                    # Check for sanitization.
                    has_sanitization = bool(re.search(
                        rf"{re.escape(var)}\.replace\s*\(\s*['\"]\\n",
                        line,
                    ))
                    if has_sanitization:
                        continue

                    # For .write() calls, check if the file handle has
                    # 'log' in its name or the variable being written
                    # contains 'log' in its name.
                    if is_file_write and not is_log_write:
                        # Check if the variable or context is log-related.
                        region_start = max(0, line_num - 10)
                        region = "\n".join(lines[region_start:line_num])
                        if not re.search(r"log", region, re.IGNORECASE):
                            continue

                    snippet = self.extract_code_snippet(
                        code, line_num, context_lines=3
                    )
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="Log Injection",
                        severity="MEDIUM",
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            f"User-controlled data (via '{var}') is written to "
                            f"log output without sanitization. An attacker can "
                            f"inject newline characters to forge log entries, "
                            f"hide malicious activity, or corrupt log analysis. "
                            f"Sanitize by stripping control characters."
                        ),
                        confidence=0.85,
                        cwe_id="CWE-117",
                        owasp_category="A09:2021 – Security Logging and Monitoring Failures",
                        metadata={"tainted_var": var},
                    ))
                    break

        self.findings = findings
        return findings
