"""
Evasion and Bypass Pattern Detector.

Detects high-risk patterns that often bypass simplistic security checks:
  1) Signature-check gate followed by unsafe deserialization.
  2) ASCII-only ".." path traversal filtering without Unicode/encoding normalization.
  3) shlex.quote() used together with shell execution.
"""

import ast
import re
from typing import List, Optional, Set

from .base_detector import BaseDetector, Finding


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _call_name(node: ast.Call) -> str:
    return _dotted_name(node.func)


class EvasionPatternsDetector(BaseDetector):
    """Detect targeted evasion patterns with low false positives."""

    _UNSAFE_DESER_CALLS = {"pickle.loads", "pickle.load", "yaml.load", "marshal.loads"}
    _VERIFY_NAME_HINTS = ("verify", "signature", "hmac", "digest", "authentic")
    _UNICODE_NORMALIZE_HINTS = ("unicodedata.normalize", "urllib.parse.unquote", "unquote", "NFKC", "NFKD")

    def __init__(self, enabled: bool = True):
        super().__init__("EvasionPatternsDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if language != "python":
            return findings

        lines = code.split("\n")
        findings.extend(self._detect_signature_gate_deserialization(code, lines))
        findings.extend(self._detect_unicode_path_bypass(lines, code))
        findings.extend(self._detect_shlex_shell_bypass(lines, code))
        self.findings = findings
        return findings

    def _detect_signature_gate_deserialization(self, code: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            if not self._looks_like_signature_check(node.test):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                name = _call_name(child)
                if name not in self._UNSAFE_DESER_CALLS:
                    continue
                line_no = getattr(child, "lineno", getattr(node, "lineno", 1))
                snippet = self.extract_code_snippet(code, line_no, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Unsafe Deserialization",
                    severity="CRITICAL",
                    line_number=line_no,
                    code_snippet=snippet,
                    description=(
                        "Unsafe deserialization occurs after a signature/auth check. "
                        "Authentication of bytes does not make pickle/yaml object "
                        "construction safe; attacker-controlled signed payloads can still "
                        "trigger gadget-based code execution."
                    ),
                    confidence=0.96,
                    cwe_id="CWE-502",
                    owasp_category="A08:2021 – Software and Data Integrity Failures",
                    metadata={"pattern": "signature_gate_then_unsafe_deserialization", "sink": name},
                ))
                break
        return findings

    def _detect_unicode_path_bypass(self, lines: List[str], code: str) -> List[Finding]:
        findings: List[Finding] = []
        ascii_guard = re.compile(
            r"(?:if|elif)\s+['\"]\.\.['\"]\s+in\s+(\w+)\s*:"
            r"|(?:if|elif)\s+(\w+)\.find\(\s*['\"]\.\.['\"]\s*\)\s*!=\s*-?1\s*:"
        )

        for idx, line in enumerate(lines):
            m = ascii_guard.search(line)
            if not m:
                continue
            path_var = m.group(1) or m.group(2)
            region = "\n".join(lines[idx:min(len(lines), idx + 30)])
            # Skip if robust normalization/decoding is already present.
            if any(hint in region for hint in self._UNICODE_NORMALIZE_HINTS):
                continue

            sink_line: Optional[int] = None
            for j in range(idx, min(len(lines), idx + 30)):
                if re.search(rf"\bopen\s*\(.*\b{re.escape(path_var)}\b", lines[j]):
                    sink_line = j + 1
                    break
                if re.search(rf"\bos\.path\.join\s*\(.*\b{re.escape(path_var)}\b", lines[j]):
                    sink_line = j + 1
                    break
            if sink_line is None:
                continue

            snippet = self.extract_code_snippet(code, sink_line, context_lines=3)
            findings.append(Finding(
                detector_name=self.name,
                vulnerability_type="Path Traversal",
                severity="HIGH",
                line_number=sink_line,
                code_snippet=snippet,
                description=(
                    "Path validation uses ASCII-only '..' checks without unicode/encoding "
                    "normalization. Encoded separators or homoglyphs can bypass this guard."
                ),
                confidence=0.93,
                cwe_id="CWE-22",
                owasp_category="A01:2021 – Broken Access Control",
                metadata={"pattern": "unicode_traversal_bypass", "path_var": path_var},
            ))
        return findings

    def _detect_shlex_shell_bypass(self, lines: List[str], code: str) -> List[Finding]:
        findings: List[Finding] = []
        quote_assign = re.compile(r"\b(\w+)\s*=\s*shlex\.quote\s*\(")

        for idx, line in enumerate(lines):
            m = quote_assign.search(line)
            if not m:
                continue
            quoted_var = m.group(1)
            for j in range(idx, min(len(lines), idx + 15)):
                sink_line = lines[j]
                if re.search(rf"\bos\.system\s*\(.*\b{re.escape(quoted_var)}\b", sink_line):
                    line_no = j + 1
                    snippet = self.extract_code_snippet(code, line_no, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="Command Injection",
                        severity="CRITICAL",
                        line_number=line_no,
                        code_snippet=snippet,
                        description=(
                            "shlex.quote() is used, but command is executed through a shell. "
                            "Quoting is not a complete defense for shell-based execution paths; "
                            "use argument lists with subprocess.run(..., shell=False)."
                        ),
                        confidence=0.95,
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 – Injection",
                        metadata={"pattern": "shlex_quote_with_shell_execution", "quoted_var": quoted_var},
                    ))
                    break
                if (
                    re.search(r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(", sink_line)
                    and "shell=True" in sink_line
                    and re.search(rf"\b{re.escape(quoted_var)}\b", sink_line)
                ):
                    line_no = j + 1
                    snippet = self.extract_code_snippet(code, line_no, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="Command Injection",
                        severity="CRITICAL",
                        line_number=line_no,
                        code_snippet=snippet,
                        description=(
                            "Input is quoted with shlex.quote() but still passed to "
                            "subprocess with shell=True. This remains command-injection-prone."
                        ),
                        confidence=0.95,
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 – Injection",
                        metadata={"pattern": "shlex_quote_with_shell_true", "quoted_var": quoted_var},
                    ))
                    break
        return findings

    def _looks_like_signature_check(self, node: ast.AST) -> bool:
        check_names: Set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = _call_name(child).lower()
                if name:
                    check_names.add(name)
            elif isinstance(child, ast.Name):
                check_names.add(child.id.lower())
        return any(any(hint in name for hint in self._VERIFY_NAME_HINTS) for name in check_names)
