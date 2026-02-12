"""
Unsafe Reflection / Dynamic Import Detector (CWE-470).

Detects dangerous dynamic code loading patterns:
  - __import__(user_input)
  - importlib.import_module(user_input)
  - getattr(module, user_input) for arbitrary attribute access
  - globals()[user_input] / locals()[user_input]
  - setattr(obj, user_key, user_value) for attribute injection

Based on Bandit blacklisting and Semgrep non-literal-import rules.
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class UnsafeReflectionDetector(BaseDetector):
    """Detect unsafe dynamic imports, reflection, and attribute injection."""

    def __init__(self, enabled: bool = True):
        super().__init__("UnsafeReflectionDetector", enabled)

        self._patterns = [
            # ── SSTI / Template Injection ─────────────────────────
            # Custom template engine using eval/exec on template strings
            {
                "pattern": re.compile(
                    r"""eval\s*\(\s*\w+\s*,\s*\{[^}]*__builtins__"""
                ),
                "vuln_type": "Server-Side Template Injection",
                "severity": "CRITICAL",
                "cwe": "CWE-1336",
                "desc": (
                    "eval() used as a template rendering engine with "
                    "restricted builtins. This is a Server-Side Template "
                    "Injection (SSTI) vulnerability. Attackers can escape "
                    "the sandbox using __class__.__mro__ chains to achieve "
                    "arbitrary code execution."
                ),
            },
            # Incomplete blocklist bypass for imports
            {
                "pattern": re.compile(
                    r"""(?:blocked|blacklist|blocklist|deny)\s*=\s*\[.*?\]""",
                ),
                "vuln_type": "Incomplete Blocklist",
                "severity": "HIGH",
                "cwe": "CWE-184",
                "desc": (
                    "Module/function blocklist detected. Blocklists are "
                    "inherently incomplete — attackers can bypass by using "
                    "submodules (os.path vs os), aliases, or __import__. "
                    "Use an allowlist of permitted modules instead."
                ),
                # Only fire if __import__ or importlib is also used
                "context_pattern": re.compile(
                    r"__import__|importlib|getattr"
                ),
            },
            # __import__(variable) - arbitrary module loading
            {
                "pattern": re.compile(r"__import__\s*\(\s*(?![\'\"])(\w+)"),
                "vuln_type": "Unsafe Dynamic Import",
                "severity": "CRITICAL",
                "cwe": "CWE-470",
                "desc": (
                    "__import__() called with a non-literal argument. "
                    "An attacker controlling the module name can import "
                    "dangerous modules (os, subprocess, ctypes) and execute "
                    "arbitrary code. Use an allowlist of permitted modules."
                ),
            },
            # importlib.import_module(variable)
            {
                "pattern": re.compile(
                    r"importlib\.import_module\s*\(\s*(?![\'\"])(\w+)"
                ),
                "vuln_type": "Unsafe Dynamic Import",
                "severity": "HIGH",
                "cwe": "CWE-470",
                "desc": (
                    "importlib.import_module() called with a non-literal "
                    "argument. If the module name comes from user input, "
                    "an attacker can load arbitrary modules."
                ),
            },
            # getattr(obj, user_var) — when used to call functions dynamically
            {
                "pattern": re.compile(
                    r"getattr\s*\(\s*\w+\s*,\s*(?![\'\"])(\w+)"
                ),
                "vuln_type": "Unsafe Reflection",
                "severity": "HIGH",
                "cwe": "CWE-470",
                "desc": (
                    "getattr() called with a non-literal attribute name. "
                    "If the attribute name comes from user input, an "
                    "attacker can access arbitrary attributes including "
                    "private methods and dunder methods."
                ),
            },
            # setattr(obj, user_key, user_value) — NOT in a for/items loop
            # (for-loop mass assignment is handled by TypeConfusionDetector)
            {
                "pattern": re.compile(
                    r"setattr\s*\(\s*\w+\s*,\s*(?![\'\"])(\w+)"
                ),
                "vuln_type": "Attribute Injection",
                "severity": "HIGH",
                "cwe": "CWE-915",
                "desc": (
                    "setattr() called with a non-literal attribute name. "
                    "An attacker controlling the attribute name can overwrite "
                    "critical object attributes (is_admin, __class__, etc.) "
                    "leading to privilege escalation or code execution."
                ),
                # Skip when inside a dict-iteration loop (handled as Mass Assignment).
                "skip_context": re.compile(
                    r"for\s+\w+(?:\s*,\s*\w+)?\s+in\s+\w+\.items\(\)"
                ),
            },
            # globals()[var] or locals()[var]
            {
                "pattern": re.compile(
                    r"(?:globals|locals)\s*\(\s*\)\s*\[\s*(?![\'\"])(\w+)"
                ),
                "vuln_type": "Unsafe Reflection",
                "severity": "CRITICAL",
                "cwe": "CWE-470",
                "desc": (
                    "globals() or locals() accessed with a dynamic key. "
                    "This allows arbitrary access to or modification of "
                    "the execution namespace."
                ),
            },
            # builtins access: builtins.__dict__[var] or getattr(builtins, var)
            {
                "pattern": re.compile(
                    r"(?:builtins|__builtins__)\s*(?:\.__dict__\s*\[|\.)\s*(?![\'\"])(\w+)"
                ),
                "vuln_type": "Unsafe Reflection",
                "severity": "CRITICAL",
                "cwe": "CWE-470",
                "desc": (
                    "Dynamic access to builtins namespace. An attacker can "
                    "access dangerous built-in functions like exec, eval, "
                    "compile, __import__."
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
                m = pat_info["pattern"].search(line)
                if m:
                    # If a context_pattern is required, check the whole file.
                    ctx_pat = pat_info.get("context_pattern")
                    if ctx_pat and not ctx_pat.search(code):
                        continue

                    # If skip_context is set, suppress when nearby code matches.
                    skip_ctx = pat_info.get("skip_context")
                    if skip_ctx:
                        region_start = max(0, line_num - 4)
                        region_end = min(len(lines), line_num + 2)
                        nearby = "\n".join(lines[region_start:region_end])
                        if skip_ctx.search(nearby):
                            continue

                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type=pat_info["vuln_type"],
                        severity=pat_info["severity"],
                        line_number=line_num,
                        code_snippet=snippet,
                        description=pat_info["desc"],
                        confidence=0.90,
                        cwe_id=pat_info["cwe"],
                        owasp_category="A03:2021 – Injection",
                        metadata={"matched_var": m.group(1) if m.groups() else ""},
                    ))
                    break  # one finding per line

        self.findings = findings
        return findings
