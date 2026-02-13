"""
Operational Security Misconfiguration Detector.

Catches high-impact patterns that are often missed by pure taint-to-sink logic:
  - Unsafe file uploads
  - Information disclosure endpoints
  - Open redirect (including meta refresh)
  - Memory exhaustion / unbounded allocation
  - Format string misuse with user-controlled templates
  - Debug mode enabled in app runtime
  - Missing security headers
  - Missing CSRF protection in form handlers
  - Missing rate limiting on HTTP endpoints
"""

import re
from typing import List, Set

from .base_detector import BaseDetector, Finding


_SOURCE_PATTERN = re.compile(
    r"(\w+)\s*=\s*(?:request\."
    r"(?:files|form|args|json|headers|cookies|data)(?:\.get(?:list)?)?|"
    r"input\s*\(|params\[|sys\.argv)",
    re.IGNORECASE,
)

_SAFE_UPLOAD_HINTS = re.compile(
    r"secure_filename|allowed_(?:file|ext|extension|extensions)|"
    r"content_type|mimetype|magic\.from_buffer|MAX_CONTENT_LENGTH",
    re.IGNORECASE,
)

_SAFE_REDIRECT_HINTS = re.compile(
    r"is_safe_url|url_has_allowed_host_and_scheme|allowed_hosts|"
    r"urlparse|startswith\s*\(\s*['\"]/['\"]\s*\)",
    re.IGNORECASE,
)

_BOUND_CHECK_HINTS = re.compile(
    r"\bmin\s*\(|\bmax\s*\(|clamp|MAX_SIZE|MAX_LEN|MAX_BYTES|"
    r"if\s+\w+\s*[<>]=?\s*\d+|if\s+\d+\s*[<>]=?\s*\w+",
    re.IGNORECASE,
)

_ROUTE_DECORATOR = re.compile(r"^\s*@(?:\w+\.)?route\s*\(", re.IGNORECASE)
_RATE_LIMIT_DECORATOR = re.compile(r"^\s*@(?:\w+\.)?(?:limit|limiter\.limit|rate_limit)\s*\(", re.IGNORECASE)
_CSRF_HINTS = re.compile(r"csrf|flask_wtf|csrfprotect|validate_csrf|WTF_CSRF_ENABLED", re.IGNORECASE)
_HEADER_HINTS = re.compile(
    r"Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|"
    r"X-Content-Type-Options|Referrer-Policy|Permissions-Policy",
    re.IGNORECASE,
)


class OperationalSecurityDetector(BaseDetector):
    """Detect operational security anti-patterns and misconfigurations."""

    def __init__(self, enabled: bool = True):
        super().__init__("OperationalSecurityDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if language != "python":
            return findings

        lines = code.split("\n")
        tainted = self._track_taint(lines)

        findings.extend(self._detect_unsafe_file_upload(lines, code, tainted))
        findings.extend(self._detect_information_disclosure(lines, code))
        findings.extend(self._detect_open_redirect(lines, code, tainted))
        findings.extend(self._detect_memory_exhaustion(lines, code, tainted))
        findings.extend(self._detect_format_string(lines, code, tainted))
        findings.extend(self._detect_debug_mode(lines, code))
        findings.extend(self._detect_missing_security_headers(lines, code))
        findings.extend(self._detect_missing_csrf(lines, code))
        findings.extend(self._detect_missing_rate_limit(lines, code))

        self.findings = findings
        return findings

    def _track_taint(self, lines: List[str]) -> Set[str]:
        tainted: Set[str] = set()
        for line in lines:
            m = _SOURCE_PATTERN.search(line)
            if m:
                tainted.add(m.group(1))

        # lightweight propagation
        for _ in range(3):
            for line in lines:
                m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
                if not m:
                    continue
                lhs, rhs = m.group(1), m.group(2)
                for t in tuple(tainted):
                    if re.search(rf"\b{re.escape(t)}\b", rhs):
                        tainted.add(lhs)
                        break
        return tainted

    def _detect_unsafe_file_upload(self, lines: List[str], code: str, tainted: Set[str]) -> List[Finding]:
        findings: List[Finding] = []
        for line_num, line in enumerate(lines, 1):
            if ".save(" not in line:
                continue
            if not re.search(r"\.save\s*\(", line):
                continue

            region_start = max(0, line_num - 8)
            region = "\n".join(lines[region_start:line_num])
            if _SAFE_UPLOAD_HINTS.search(region):
                continue

            # Flag when filename/path appears user-controlled or dynamically constructed.
            if re.search(r"filename|request\.files|f['\"].*\{", line, re.IGNORECASE):
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Unsafe File Upload",
                    severity="HIGH",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "Uploaded file is saved without robust filename/content validation. "
                        "Use secure_filename(), extension allowlists, MIME checks, and size limits."
                    ),
                    confidence=0.90,
                    cwe_id="CWE-434",
                    owasp_category="A01:2021 – Broken Access Control",
                    metadata={"pattern": "file_save_without_validation"},
                ))
        return findings

    def _detect_information_disclosure(self, lines: List[str], code: str) -> List[Finding]:
        findings: List[Finding] = []
        disclosure = re.compile(
            r"os\.environ|dict\s*\(\s*os\.environ\s*\)|sys\.version|platform\."
            r"|traceback\.format_exc|__file__|SECRET_KEY|API_KEY",
            re.IGNORECASE,
        )
        for line_num, line in enumerate(lines, 1):
            if not disclosure.search(line):
                continue
            # Focus on outward-facing flows.
            region_start = max(0, line_num - 4)
            region_end = min(len(lines), line_num + 3)
            region = "\n".join(lines[region_start:region_end])
            if not re.search(r"return|jsonify|Response|make_response", region):
                continue
            # FP suppression: skip when disclosure is behind debug-only guard.
            if re.search(r"if\s+.*(?:app\.debug|DEBUG|current_app\.debug)\s*:", region):
                continue

            snippet = self.extract_code_snippet(code, line_num, context_lines=3)
            findings.append(Finding(
                detector_name=self.name,
                vulnerability_type="Information Disclosure",
                severity="MEDIUM",
                line_number=line_num,
                code_snippet=snippet,
                description=(
                    "Sensitive runtime or system details are exposed to output. "
                    "Avoid returning environment variables, version/build internals, or stack traces."
                ),
                confidence=0.88,
                cwe_id="CWE-200",
                owasp_category="A05:2021 – Security Misconfiguration",
                metadata={"pattern": "sensitive_runtime_disclosure"},
            ))
        return findings

    def _detect_open_redirect(self, lines: List[str], code: str, tainted: Set[str]) -> List[Finding]:
        findings: List[Finding] = []
        redirect_pattern = re.compile(r"\bredirect\s*\(|meta\s+refresh|window\.location", re.IGNORECASE)
        for line_num, line in enumerate(lines, 1):
            if not redirect_pattern.search(line):
                continue
            region_start = max(0, line_num - 8)
            region_end = min(len(lines), line_num + 2)
            region = "\n".join(lines[region_start:region_end])
            if _SAFE_REDIRECT_HINTS.search(region):
                continue
            if any(re.search(rf"\b{re.escape(t)}\b", region) for t in tainted) or re.search(
                r"request\.(?:args|form|values)\.get", region
            ):
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Open Redirect",
                    severity="HIGH",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "Redirect target appears user-controlled without an allowlist/host validation check."
                    ),
                    confidence=0.90,
                    cwe_id="CWE-601",
                    owasp_category="A01:2021 – Broken Access Control",
                    metadata={"pattern": "unvalidated_redirect"},
                ))
        return findings

    def _detect_memory_exhaustion(self, lines: List[str], code: str, tainted: Set[str]) -> List[Finding]:
        findings: List[Finding] = []
        # Also treat function params as potentially attacker-controlled.
        param_vars: Set[str] = set(tainted)
        for line in lines:
            m = re.match(r"\s*def\s+\w+\s*\(([^)]*)\)", line)
            if m:
                for p in m.group(1).split(","):
                    pname = p.strip().split(":")[0].split("=")[0].strip()
                    if pname and pname != "self":
                        param_vars.add(pname)

        alloc_pattern = re.compile(
            r"['\"].*['\"]\s*\*\s*int\s*\(|"
            r"\[[^\]]*\]\s*\*\s*int\s*\(|"
            r"bytearray\s*\(\s*int\s*\(|"
            r"['\"].*['\"]\s*\*\s*(\w+)|"       # 'A' * size_var
            r"\brange\s*\(\s*int\s*\(",          # range(int(user_input))
            re.IGNORECASE,
        )
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not alloc_pattern.search(line):
                continue
            if not any(re.search(rf"\b{re.escape(t)}\b", line) for t in param_vars) and "request" not in line:
                continue
            region_start = max(0, line_num - 6)
            region = "\n".join(lines[region_start:line_num + 1])
            if _BOUND_CHECK_HINTS.search(region):
                continue
            snippet = self.extract_code_snippet(code, line_num, context_lines=3)
            findings.append(Finding(
                detector_name=self.name,
                vulnerability_type="Memory Exhaustion",
                severity="HIGH",
                line_number=line_num,
                code_snippet=snippet,
                description=(
                    "User-influenced size is used for allocation without an upper bound. "
                    "This can cause denial-of-service via memory exhaustion."
                ),
                confidence=0.91,
                cwe_id="CWE-400",
                owasp_category="A04:2021 – Insecure Design",
                metadata={"pattern": "unbounded_allocation"},
            ))
        return findings

    def _detect_format_string(self, lines: List[str], code: str, tainted: Set[str]) -> List[Finding]:
        findings: List[Finding] = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # tainted_template.format(...)
            m = re.search(r"(\w+)\.format\s*\(", line)
            if m and m.group(1) in tainted:
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Format String Injection",
                    severity="MEDIUM",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "User-controlled format template used with .format(). "
                        "This can expose internals or alter rendered output."
                    ),
                    confidence=0.86,
                    cwe_id="CWE-134",
                    owasp_category="A03:2021 – Injection",
                    metadata={"pattern": "tainted_format_template"},
                ))
                continue

            # request-controlled format call in-line
            if re.search(
                r"request\.(?:args|form|values)\.get\s*\(.+?\)\s*\.format\s*\(",
                line,
                re.IGNORECASE,
            ):
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Format String Injection",
                    severity="MEDIUM",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "Request-controlled format template is used with .format(). "
                        "Use a static format string and treat user input as data only."
                    ),
                    confidence=0.89,
                    cwe_id="CWE-134",
                    owasp_category="A03:2021 – Injection",
                    metadata={"pattern": "request_template_format"},
                ))
                continue

            # tainted % values
            m2 = re.search(r"(\w+)\s*%\s*[\(\w\[]", line)
            if m2 and m2.group(1) in tainted:
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Format String Injection",
                    severity="MEDIUM",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "User-controlled format template used with %-formatting."
                    ),
                    confidence=0.86,
                    cwe_id="CWE-134",
                    owasp_category="A03:2021 – Injection",
                    metadata={"pattern": "tainted_percent_template"},
                ))
        return findings

    def _detect_debug_mode(self, lines: List[str], code: str) -> List[Finding]:
        findings: List[Finding] = []
        for line_num, line in enumerate(lines, 1):
            if re.search(r"\bapp\.run\s*\(.*debug\s*=\s*True", line):
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Debug Mode Enabled",
                    severity="HIGH",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "Application is started with debug=True. In production this can expose "
                        "interactive debugger and sensitive internals."
                    ),
                    confidence=0.95,
                    cwe_id="CWE-489",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    metadata={"pattern": "runtime_debug_true"},
                ))
        return findings

    def _detect_missing_security_headers(self, lines: List[str], code: str) -> List[Finding]:
        findings: List[Finding] = []
        has_http_handler = any(_ROUTE_DECORATOR.search(l) for l in lines) or "Flask(" in code
        if not has_http_handler:
            return findings
        if _HEADER_HINTS.search(code):
            return findings

        line_no = 1
        for idx, line in enumerate(lines, 1):
            if "Flask(" in line:
                line_no = idx
                break
        snippet = self.extract_code_snippet(code, line_no, context_lines=3)
        findings.append(Finding(
            detector_name=self.name,
            vulnerability_type="Missing Security Headers",
            severity="MEDIUM",
            line_number=line_no,
            code_snippet=snippet,
            description=(
                "Web application does not appear to set key security headers "
                "(CSP, HSTS, X-Frame-Options, X-Content-Type-Options). "
                "Possible FP if headers are injected by reverse proxy/CDN."
            ),
            confidence=0.60,
            cwe_id="CWE-693",
            owasp_category="A05:2021 – Security Misconfiguration",
            metadata={"pattern": "missing_security_headers"},
        ))
        return findings

    def _detect_missing_csrf(self, lines: List[str], code: str) -> List[Finding]:
        findings: List[Finding] = []
        if _CSRF_HINTS.search(code):
            return findings

        for idx, line in enumerate(lines, 1):
            if not _ROUTE_DECORATOR.search(line):
                continue
            # Look ahead to associated function for state-changing methods.
            region = "\n".join(lines[idx - 1:min(len(lines), idx + 7)])
            if re.search(r"methods\s*=\s*\[[^\]]*(POST|PUT|PATCH|DELETE)", region, re.IGNORECASE):
                snippet = self.extract_code_snippet(code, idx, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Missing CSRF Protection",
                    severity="HIGH",
                    line_number=idx,
                    code_snippet=snippet,
                    description=(
                        "State-changing Flask endpoint is defined without visible CSRF protections. "
                        "Possible FP if API-only or token-based auth."
                    ),
                    confidence=0.62,
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 – Broken Access Control",
                    metadata={"pattern": "missing_csrf"},
                ))
                break
        return findings

    def _detect_missing_rate_limit(self, lines: List[str], code: str) -> List[Finding]:
        findings: List[Finding] = []
        for idx, line in enumerate(lines, 1):
            if not _ROUTE_DECORATOR.search(line):
                continue
            # Route found; ensure a nearby limiter decorator exists.
            prev_region = "\n".join(lines[max(0, idx - 4):idx + 1])
            if _RATE_LIMIT_DECORATOR.search(prev_region):
                continue
            # Prioritize auth/high-risk endpoints only to reduce FPs.
            route_region = "\n".join(lines[idx - 1:min(len(lines), idx + 5)])
            if not re.search(r"login|auth|token|upload|search|api", route_region, re.IGNORECASE):
                continue
            snippet = self.extract_code_snippet(code, idx, context_lines=3)
            findings.append(Finding(
                detector_name=self.name,
                vulnerability_type="Missing Rate Limiting",
                severity="MEDIUM",
                line_number=idx,
                code_snippet=snippet,
                description=(
                    "Potentially sensitive/high-risk endpoint has no visible rate limiting decorator. "
                    "Possible FP if enforced at gateway/WAF."
                ),
                confidence=0.58,
                cwe_id="CWE-770",
                owasp_category="A04:2021 – Insecure Design",
                metadata={"pattern": "missing_rate_limit"},
            ))
        return findings
