"""
Cross-Site Scripting (XSS) Detector (CWE-79).

Detects reflected XSS where user input from HTTP request parameters,
headers, or cookies is included in HTTP responses without escaping.

Focuses on:
  - BaseHTTPRequestHandler do_GET/do_POST with user input in response
  - Flask/Django template rendering with unescaped variables
  - Direct response.write() with user data
"""

import re
from typing import List, Set
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class XSSDetector(BaseDetector):
    """Detect reflected XSS in HTTP response handlers."""

    def __init__(self, enabled: bool = True):
        super().__init__("XSSDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if language not in ("python", "javascript", "typescript"):
            return findings

        lines = code.split("\n")

        # Collect user input sources.
        user_vars: Set[str] = set()
        for line in lines:
            # parse_qs, query params
            m = re.search(r"(\w+)\s*=\s*(?:parse_qs|request\.(?:args|form|json|cookies|headers))", line)
            if m:
                user_vars.add(m.group(1))
            # query.get('param')
            m = re.search(r"(\w+)\s*=\s*\w+\.get\s*\(\s*['\"]", line)
            if m:
                user_vars.add(m.group(1))
            # self.headers.get(...)
            m = re.search(r"self\.headers\.get\s*\(", line)
            if m:
                # The whole expression is user-controlled
                pass

        # Propagate through simple assignments.
        for _pass in range(3):
            for line in lines:
                m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
                if m:
                    lhs, rhs = m.group(1), m.group(2)
                    for uv in list(user_vars):
                        if re.search(rf"\b{re.escape(uv)}\b", rhs):
                            user_vars.add(lhs)

        if not user_vars:
            return findings

        # ── Identify which functions are route handlers ──
        # A route handler is the function immediately following @app.route / @blueprint.route.
        route_handler_lines: set = set()  # line numbers of `def ...` that are route handlers
        _pending_route = False
        for line_num, line in enumerate(lines, 1):
            if re.search(r"@(?:app|blueprint)\.route\b", line):
                _pending_route = True
                continue
            if _pending_route:
                if re.match(r"\s*def\s+(\w+)\s*\(", line):
                    route_handler_lines.add(line_num)
                    _pending_route = False
                elif line.strip().startswith("@"):
                    pass  # stacked decorators
                else:
                    _pending_route = False

        # Also include BaseHTTPRequestHandler do_* methods.
        for line_num, line in enumerate(lines, 1):
            if re.match(r"\s*def\s+do_(GET|POST|PUT|DELETE)\s*\(", line):
                route_handler_lines.add(line_num)

        if not route_handler_lines:
            return findings

        # ── Build (start, end) ranges for each handler body ──
        handler_ranges: list[tuple[int, int]] = []
        for h_start in sorted(route_handler_lines):
            h_indent = len(lines[h_start - 1]) - len(lines[h_start - 1].lstrip())
            h_end = h_start
            for j in range(h_start, len(lines)):
                jline = lines[j]
                if not jline.strip():
                    continue
                j_indent = len(jline) - len(jline.lstrip())
                if j > h_start and j_indent <= h_indent and jline.strip():
                    break
                h_end = j + 1
            handler_ranges.append((h_start, h_end))

        def _in_handler(ln: int) -> bool:
            return any(s <= ln <= e for s, e in handler_ranges)

        # ── Scan for XSS only within handler bodies ──
        for line_num, line in enumerate(lines, 1):
            if not _in_handler(line_num):
                continue

            # Must be a response-producing statement with HTML content.
            is_response_write = bool(re.search(
                r"(?:wfile\.write|send_response|response\.write|"
                r"return\s+f['\"]|RESPONSE\s*\+=|response\s*=\s*f['\"])",
                line,
            ))
            if not is_response_write:
                continue

            # Skip plain-text returns (no HTML tags → not XSS-exploitable).
            if re.search(r"return\s+f['\"]", line):
                if not re.search(r"<\w+[>\s/]", line):
                    continue

            # Check if user-controlled data appears in the response line.
            for var in user_vars:
                if not re.search(rf"\b{re.escape(var)}\b", line):
                    continue
                # Check if html.escape or similar wraps it.
                region_start = max(0, line_num - 4)
                region_end = min(len(lines), line_num + 4)
                region = "\n".join(lines[region_start:region_end])
                if re.search(
                    rf"(?:html\.escape|escape|cgi\.escape|markupsafe\.escape)"
                    rf"\s*\(\s*{re.escape(var)}",
                    region,
                ):
                    continue

                snippet = self.extract_code_snippet(code, line_num, context_lines=4)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Reflected XSS",
                    severity="HIGH",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        f"User-controlled variable '{var}' is included in "
                        f"an HTML response without escaping. Use html.escape() "
                        f"or a template engine with auto-escaping."
                    ),
                    confidence=0.88,
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 – Injection",
                    metadata={"user_var": var},
                ))
                break

        self.findings = findings
        return findings
