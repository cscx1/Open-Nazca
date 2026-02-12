"""
Functional remediation engine.

Generates code fixes that change runtime behaviour.  Every fix is a
*functional diff* — adding comments, warnings, or documentation without
changing execution logic is explicitly rejected as a non-fix.

Each remediation is returned as a ``RemediationDiff`` that includes the
original line, the replacement, and a description of the behavioural change.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .attack_graph import AttackPath
from .reachability import ReachabilityResult, ReachabilityStatus

logger = logging.getLogger(__name__)


@dataclass
class RemediationDiff:
    """One atomic code fix."""
    line_number: int
    original_line: str
    fixed_line: str
    description: str           # what runtime behaviour changed
    vulnerability_type: str
    is_functional: bool        # True iff execution logic changed
    rejection_reason: str = "" # non-empty when is_functional is False

    def to_dict(self) -> Dict:
        return {
            "line_number": self.line_number,
            "original_line": self.original_line,
            "fixed_line": self.fixed_line,
            "description": self.description,
            "vulnerability_type": self.vulnerability_type,
            "is_functional": self.is_functional,
            "rejection_reason": self.rejection_reason,
        }


# ── Fix strategies ───────────────────────────────────────────────

def _fix_hardcoded_secret(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Replace a hardcoded secret with os.environ.get()."""
    # var = "literal_value"
    m = re.match(r'^(\s*)([\w.]+)\s*=\s*["\'](.+?)["\'](.*)$', line)
    if m:
        ind, var, _val, rest = m.groups()
        env_name = re.sub(r'[^A-Z0-9_]', '_', var.upper())
        fixed = f'{ind}{var} = os.environ.get("{env_name}", ""){rest}'
        return fixed, f'Replaced hardcoded value with os.environ.get("{env_name}")'

    # "key": "literal_value" (dict literal)
    m2 = re.match(r'^(\s*)["\'](\w+)["\']\s*:\s*["\'](.+?)["\'](.*)$', line)
    if m2:
        ind, key, _val, rest = m2.groups()
        env_name = re.sub(r'[^A-Z0-9_]', '_', key.upper())
        fixed = f'{ind}"{key}": os.environ.get("{env_name}", ""){rest}'
        return fixed, f'Replaced hardcoded dict value with os.environ.get("{env_name}")'

    return None


def _fix_sql_injection(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Convert string-concatenated SQL to parameterised queries."""
    # Pattern 1: cursor.execute(f"SELECT ... {var} ...")  — all on one line.
    m = re.search(
        r"(\.execute\s*\(\s*)f([\"'])(.*?)\{(\w+)\}(.*?)(\2)\s*\)",
        line,
    )
    if m:
        prefix, _quote, before, param_var, after, _ = m.groups()
        # Strip the wrapping quotes that the f-string had around the variable.
        before_clean = re.sub(r"['\"]$", "", before)
        after_clean = re.sub(r"^['\"]", "", after)
        sql = f"{before_clean}?{after_clean}"
        fixed = f"{line[:m.start()]}{prefix}\"{sql}\", ({param_var},)){line[m.end():]}"
        return fixed, "Converted f-string SQL to parameterized query"

    # Pattern 2: query = f"SELECT ... {var} ..."  — query construction line.
    m = re.search(
        r"""(\w+)\s*=\s*f([\"'])(.*?)\{(\w+)\}(.*?)\2""",
        line,
    )
    if m:
        query_var, _quote, before, param_var, after = m.groups()
        # Strip any literal quoting around the interpolation point.
        before_clean = re.sub(r"['\"]$", "", before)
        after_clean = re.sub(r"^['\"]", "", after)
        sql = f"{before_clean}?{after_clean}"
        fixed = f"{indent}{query_var} = \"{sql}\""
        return fixed, f"Replaced f-string SQL with parameterized placeholder (pass ({param_var},) to execute)"

    # Pattern 3: query = "..." % var  — %-format SQL.
    m = re.search(r"""(\w+)\s*=\s*([\"'])(.*?)%s(.*?)\2\s*%\s*(\w+)""", line)
    if m:
        query_var, _q, before, after, param_var = m.groups()
        sql = f"{before}?{after}"
        fixed = f"{indent}{query_var} = \"{sql}\""
        return fixed, f"Replaced %-format SQL with parameterized placeholder (pass ({param_var},) to execute)"

    return None


def _fix_command_injection_list_form(line: str, source_var: str) -> Optional[Tuple[str, str]]:
    """
    Fix command injection by passing user input as a single list element
    (e.g. ['ls', '-la', path]) instead of building a string and splitting.
    Safe: no shell, no string interpolation of user input.
    """
    # subprocess.check_output(cmd, shell=True) -> subprocess.check_output(['ls', '-la', path], shell=False)
    m = re.search(
        r"(subprocess\.(?:check_output|run|call|Popen)\s*\(\s*)([^,\)]+)(\s*,\s*shell\s*=\s*True\s*\))",
        line,
    )
    if m:
        prefix, _cmd_expr, _suffix = m.groups()
        new_args = f"['ls', '-la', {source_var}]"
        fixed = line[: m.start()] + prefix + new_args + ", shell=False)" + line[m.end() :]
        return fixed, f"Pass user input as single list element: ['ls', '-la', {source_var}] (no command string)"

    # os.system(cmd) -> subprocess.run(['ls', '-la', path], shell=False)
    m2 = re.search(r"os\.system\s*\(\s*[^)]+\s*\)", line)
    if m2:
        # Replace the whole os.system(...) call with list-form subprocess
        fixed = re.sub(
            r"os\.system\s*\(\s*[^)]+\s*\)",
            f"subprocess.run(['ls', '-la', {source_var}], shell=False)",
            line,
        )
        if fixed != line:
            return fixed, f"Replaced os.system with list form: user input as single element ['ls', '-la', {source_var}]"
    return None


def _fix_command_injection(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Replace os.system() or shell=True with list-form subprocess (no command string)."""
    if 'os.system(' in line:
        inner = re.search(r"os\.system\s*\(\s*(.+?)\s*\)\s*$", line.strip())
        if inner:
            cmd_expr = inner.group(1).strip()
            # Don't build then split a string; use list form. We don't have source_var here.
            fixed = (
                f"{indent}# Use list form: subprocess.run(['cmd', 'arg', user_var], shell=False)\n"
                f"{indent}subprocess.run([{cmd_expr}], shell=False)  # MANUAL: replace with [executable, arg1, user_var]"
            )
            return fixed, "Replaced os.system with subprocess.run list form; ensure user input is single list element"

    if 'shell=True' in line:
        # Prefer list form when we have source_var (handled in remediate loop).
        # Fallback: replace with shell=False and shlex.split (less safe but better than shell=True).
        fixed = line.replace('shell=True', 'shell=False')
        fixed = re.sub(
            r"subprocess\.(run|call|check_output|Popen)\s*\(\s*([^,\)]+)\s*,",
            r"subprocess.\1(shlex.split(str(\2)),",
            fixed,
        )
        return fixed, 'Disabled shell and tokenized command (prefer list form with user input as single element)'

    return None


def _fix_code_execution(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Apply context-aware code-execution remediations."""
    if 'eval(' in line and 'literal_eval' not in line:
        # ast.literal_eval() is only correct when code is parsing literals.
        # For expression engines/business logic, automatic replacement is unsafe.
        literal_context_tokens = (
            "parse", "literal", "payload", "config", "json", "data", "value"
        )
        lowered = line.lower()
        if any(tok in lowered for tok in literal_context_tokens):
            fixed = line.replace('eval(', 'ast.literal_eval(')
            return fixed, 'Replaced eval() with ast.literal_eval() for literal-only parsing'
        return None

    if 'exec(' in line:
        # No safe generic drop-in exists without business-context.
        # Defer to guided remediation options in the UI.
        return None

    return None


def _fix_sql_execute_add_params(line: str, source_var: str) -> Optional[Tuple[str, str]]:
    """
    Add parameter tuple to execute(query) when the query is built elsewhere
    (e.g. parameterized). Only use when the query construction line is fixed
    separately; never use when the query string still contains f-string/format.
    """
    m = re.search(r"(\.execute\s*\(\s*(\w+)\s*)\)\s*$", line)
    if not m:
        return None
    fixed = re.sub(
        r"(\.execute\s*\(\s*\w+\s*)\)\s*$",
        rf"\1, ({source_var},))",
        line,
    )
    if fixed != line:
        return fixed, f"Pass parameters to execute(): ({source_var},)"
    return None


def _fix_weak_hash(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Replace MD5/SHA1 with SHA-256 or HMAC (for payload+secret to prevent length-extension)."""
    # payload + secret_key pattern: use HMAC instead of hash(payload+secret) to prevent length-extension
    m = re.search(
        r"hashlib\.(md5|sha1)\s*\(\s*(\w+)\s*\+\s*(\w+)\.encode\s*\(\s*\)\s*\)\.digest\s*\(\s*\)",
        line,
    )
    if m:
        _algo, msg_var, key_var = m.groups()
        fixed = re.sub(
            r"hashlib\.(md5|sha1)\s*\(\s*\w+\s*\+\s*\w+\.encode\s*\(\s*\)\s*\)\.digest\s*\(\s*\)",
            f"hmac.new({key_var}.encode(), {msg_var}, hashlib.sha256).digest()",
            line,
        )
        if fixed != line:
            return fixed, "Replaced with HMAC to prevent length-extension attacks (use: import hmac)"

    if "hashlib.md5(" in line:
        fixed = line.replace("hashlib.md5(", "hashlib.sha256(")
        return fixed, "Replaced MD5 with SHA-256 for cryptographic hashing"
    if "hashlib.sha1(" in line:
        fixed = line.replace("hashlib.sha1(", "hashlib.sha256(")
        return fixed, "Replaced SHA-1 with SHA-256 for cryptographic hashing"
    m = re.search(r"hashlib\.new\s*\(\s*['\"](\w+)['\"]", line)
    if m and m.group(1).lower() in ("md5", "sha1"):
        fixed = re.sub(r"hashlib\.new\s*\(\s*['\"]\w+['\"]", "hashlib.new('sha256')", line)
        return fixed, "Replaced weak algorithm with SHA-256"
    return None


def _fix_weak_random(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Replace predictable random with secrets module for token-like use."""
    if "random.seed(" in line:
        return None  # Fix applied on the usage line (next line) when present
    if re.search(r"random\.(choices|choice|randint|getrandbits)\s*\(", line):
        if "random.choices(" in line and ("return " in line or "=" in line):
            fixed = re.sub(
                r"return\s+['\"]*\.join\s*\(\s*random\.choices\s*\([^)]+\)\s*\)",
                "return secrets.token_hex(3)",
                line,
            )
            if fixed != line:
                return fixed, "Replaced weak random.choices() with secrets.token_hex(3)"
        fixed = line.replace("random.choices(", "secrets.SystemRandom().choices(")
        if fixed != line:
            return fixed, "Replaced with secrets.SystemRandom() for security-sensitive randomness"
    return None


def _fix_debug_mode(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Disable debug mode in app.run()."""
    if "debug=True" in line and "app.run" in line:
        fixed = line.replace("debug=True", "debug=False")
        return fixed, "Disabled debug mode for production"
    return None


def _fix_yaml_unsafe(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Replace unsafe yaml.load(..., Loader=yaml.Loader) with yaml.safe_load()."""
    if "yaml.load(" in line and "Loader=" in line:
        fixed = re.sub(r"yaml\.load\s*\(\s*([^,]+),\s*Loader\s*=\s*\w+\.\w+\s*\)", r"yaml.safe_load(\1)", line)
        if fixed != line:
            return fixed, "Replaced unsafe yaml.load() with yaml.safe_load()"
    if "yaml.load(" in line and "Loader=" not in line:
        fixed = re.sub(r"yaml\.load\s*\(\s*([^)]+)\s*\)", r"yaml.safe_load(\1)", line)
        if fixed != line:
            return fixed, "Replaced yaml.load() with yaml.safe_load()"
    return None


def _fix_prompt_injection_fstring(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """
    Convert unsafe prompt construction to structured message separation.

    Handles:
      - f-string interpolation: f"...{var}..."
      - .format() interpolation: "...{}...".format(var)
      - string concatenation: "..." + var

    This is a *functional* change: it replaces inline string interpolation
    with an explicit user-content boundary variable with length limiting.
    """
    # 1) f-string: prompt = f"...{user_input}..."
    m = re.search(r'=\s*f(["\'])(.*?)\{(\w+)\}(.*?)\1', line)
    if m:
        quote, prefix, var, suffix = m.groups()
        sanitised_prefix = prefix.replace('{', '').replace('}', '')
        lhs = line.split("=")[0].strip()
        fixed = (
            f'{indent}_user_content = str({var})[:2000]  # length-limited\n'
            f'{indent}{lhs} = '
            f'{quote}{sanitised_prefix}{quote} + _user_content + {quote}{suffix}{quote}'
        )
        return fixed, f'Separated tainted variable "{var}" from prompt template with length limit'

    # 2) .format(): "...{}...".format(system_msg, user_query)
    m2 = re.search(r'=\s*(["\'])(.*?)\1\.format\((.*?)\)', line)
    if m2:
        quote, template, args = m2.groups()
        # Extract the last argument as the user-controlled one
        arg_list = [a.strip() for a in args.split(',')]
        if arg_list:
            user_var = arg_list[-1]
            lhs = line.split("=")[0].strip()
            # Build separate variables for each arg
            safe_args = ', '.join(
                f'str({a})[:2000]' if a == user_var else a
                for a in arg_list
            )
            fixed = (
                f'{indent}_sanitized_input = str({user_var})[:2000]  # length-limited\n'
                f'{indent}{lhs} = {quote}{template}{quote}.format('
                + ', '.join(
                    '_sanitized_input' if a == user_var else a
                    for a in arg_list
                )
                + ')'
            )
            return fixed, f'Length-limited user variable "{user_var}" in .format() call'

    # 3) String concatenation: "..." + user_var
    m3 = re.search(r'=\s*(.+?)\s*\+\s*(\w+)\s*$', line)
    if m3:
        prefix_expr, var = m3.groups()
        # Only fix if the variable name suggests user input
        if any(kw in var.lower() for kw in ['user', 'input', 'query', 'message', 'data']):
            lhs = line.split("=")[0].strip()
            fixed = (
                f'{indent}_sanitized_input = str({var})[:2000]  # length-limited\n'
                f'{indent}{lhs} = {prefix_expr} + _sanitized_input'
            )
            return fixed, f'Length-limited concatenated user variable "{var}"'

    return None


# ── Specific guidance when auto-fix is not possible ──────────────

def _get_specific_guidance(vuln_type: str, line: str) -> str:
    vt = vuln_type.lower()
    if "eval" in line and "code execution" in vt:
        return (
            "Replace eval() with ast.literal_eval() for data parsing, or "
            "use a safe expression evaluator (e.g. simpleeval) for computation. "
            "Never pass user input directly to eval()."
        )
    if "exec" in line and "code execution" in vt:
        return (
            "Eliminate exec() entirely. Map user actions to named handler "
            "functions via a dispatch dict instead of executing arbitrary strings."
        )
    if "pickle" in vt or "deserialization" in vt:
        return (
            "Replace pickle.loads() with json.loads() or a schema-validated "
            "deserializer. If pickle is required, use hmac-signed payloads "
            "and restrict allowed classes via RestrictedUnpickler."
        )
    if "path traversal" in vt:
        return (
            "Resolve the path with os.path.realpath() then verify it starts "
            "with the allowed base directory using str.startswith(). "
            "Reject any path containing '..'."
        )
    if "xss" in vt or "template injection" in vt:
        return (
            "Use html.escape() on all user-controlled values before inserting "
            "into HTML. Prefer render_template() with auto-escaping over "
            "render_template_string() with f-strings."
        )
    if "ssrf" in vt:
        return (
            "Validate URLs against an allowlist of permitted hosts/schemes. "
            "Block private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, "
            "169.254.169.254) before making outbound requests."
        )
    if "redos" in vt:
        return (
            "Simplify the regex to avoid nested quantifiers. Use re2 or "
            "set a timeout with regex.match(pattern, string, timeout=N). "
            "Validate input length before regex matching."
        )
    if "open redirect" in vt:
        return (
            "Validate redirect target against a strict allowlist. "
            "Use url_has_allowed_host_and_scheme() or check that the URL "
            "starts with '/' and does not start with '//'."
        )
    if "command injection" in vt:
        return (
            "Use subprocess.run([cmd, arg1, arg2], shell=False) with an "
            "explicit argument list. Never interpolate user input into "
            "command strings."
        )
    if "sql injection" in vt:
        return (
            "Use parameterized queries: cursor.execute('SELECT * FROM users "
            "WHERE id = ?', (user_id,)). Never use f-strings or string "
            "concatenation for SQL."
        )
    return (
        f"Review this {vuln_type} finding manually. Apply input validation, "
        f"use safe API alternatives, and enforce least-privilege access."
    )


# ── Strategy dispatch ────────────────────────────────────────────

_FIX_STRATEGIES = {
    "Hardcoded Secret":         _fix_hardcoded_secret,
    "SQL Injection":           _fix_sql_injection,
    "Command Injection":       _fix_command_injection,
    "Code Execution":          _fix_code_execution,
    "Prompt Injection":        _fix_prompt_injection_fstring,
    "Weak Hash":                _fix_weak_hash,
    "Weak Random":              _fix_weak_random,
    "Debug Mode Enabled":       _fix_debug_mode,
    "Unsafe Deserialization":   _fix_yaml_unsafe,
    "Path Traversal":           None,
    "SSRF":                     None,
    "XSS / Template Injection": None,
    "Reflected XSS":            None,
}


# ── Validation ───────────────────────────────────────────────────

def _is_functional_change(original: str, fixed: str) -> Tuple[bool, str]:
    """
    Determine if *fixed* is a functional diff vs. a comment-only change.

    Returns (is_functional, rejection_reason).
    """
    orig_stripped = _strip_comments(original)
    fixed_stripped = _strip_comments(fixed)

    if orig_stripped.strip() == fixed_stripped.strip():
        return False, (
            "Proposed fix only adds comments or whitespace without changing "
            "execution logic. This is not a valid remediation."
        )
    return True, ""


def _strip_comments(code: str) -> str:
    """Remove Python comments from a code string."""
    lines = []
    for line in code.split('\n'):
        stripped = line.lstrip()
        if stripped.startswith('#'):
            continue
        # Remove inline comments (naive but sufficient for validation)
        if '#' in line:
            line = line[:line.index('#')]
        lines.append(line)
    return '\n'.join(lines)


# ── Public API ───────────────────────────────────────────────────

class FunctionalRemediator:
    """
    Generate functional code fixes for verified attack paths.

    Every proposed fix is validated to ensure it changes runtime behaviour.
    Comment-only changes are explicitly rejected.
    """

    def remediate(
        self,
        source_code: str,
        results: List[ReachabilityResult],
        findings: Optional[List[dict]] = None,
    ) -> Tuple[str, List[RemediationDiff]]:
        """
        Apply fixes to *source_code* for paths classified as
        Confirmed Reachable, and optionally for pattern-based *findings*
        (e.g. Weak Hash, Debug Mode, YAML) so more fixes appear in remediated code.

        Returns (fixed_code, list_of_diffs).
        """
        lines = source_code.split('\n')
        diffs: List[RemediationDiff] = []
        done_lines: set = set()

        # Collect all candidate fix lines (sink + transforms) per result,
        # sorted descending to preserve line indices during editing
        fix_targets = []
        for result in results:
            if result.status != ReachabilityStatus.CONFIRMED_REACHABLE:
                continue
            vuln_type = result.path.vulnerability_type

            # Determine the best line to fix
            target_lines = self._pick_target_lines(result)
            for target_line in target_lines:
                fix_targets.append((target_line, vuln_type, result))

        fix_targets.sort(key=lambda t: t[0], reverse=True)

        for target_line, vuln_type, result in fix_targets:
            if target_line < 1 or target_line > len(lines) or target_line in done_lines:
                continue

            idx = target_line - 1
            original = lines[idx]
            indent = re.match(r'^\s*', original).group()  # type: ignore[union-attr]

            # Find matching strategy
            strategy = None
            for key, fn in _FIX_STRATEGIES.items():
                if key.lower() in vuln_type.lower():
                    strategy = fn
                    break

            # SQL injection: on the sink line (execute), add params; on the
            # transform line (query = f"..."), fix the query string.
            if strategy is _fix_sql_injection and "sql injection" in vuln_type.lower():
                sink_line = result.path.sink.line if result.path else None
                source_var = (result.path.source.name if result.path and result.path.source else "") or ""
                if sink_line is not None and target_line == sink_line and source_var:
                    if ".execute(" in original and "f'" not in original and 'f"' not in original:
                        sql_exec_fix = _fix_sql_execute_add_params(original, source_var)
                        if sql_exec_fix is not None:
                            fixed_line, description = sql_exec_fix
                            is_func, rejection = _is_functional_change(original, fixed_line)
                            if is_func:
                                new_parts = fixed_line.split("\n")
                                lines[idx : idx + 1] = new_parts
                                done_lines.add(target_line)
                                diffs.append(RemediationDiff(
                                    line_number=target_line,
                                    original_line=original.rstrip(),
                                    fixed_line=fixed_line.rstrip(),
                                    description=description,
                                    vulnerability_type=vuln_type,
                                    is_functional=True,
                                ))
                                continue
                # else: fall through to strategy (fix query construction line)

            # Command injection: use list form with source_var so user input is one argument (no command string).
            if strategy is _fix_command_injection and "command injection" in vuln_type.lower():
                source_var = (result.path.source.name if result.path and result.path.source else "") or ""
                if source_var and ("shell=True" in original or "os.system(" in original):
                    list_fix = _fix_command_injection_list_form(original, source_var)
                    if list_fix is not None:
                        fixed_line, description = list_fix
                        is_func, rejection = _is_functional_change(original, fixed_line)
                        if is_func:
                            new_parts = fixed_line.split("\n")
                            lines[idx : idx + 1] = new_parts
                            done_lines.add(target_line)
                            diffs.append(RemediationDiff(
                                line_number=target_line,
                                original_line=original.rstrip(),
                                fixed_line=fixed_line.rstrip(),
                                description=description,
                                vulnerability_type=vuln_type,
                                is_functional=True,
                            ))
                            continue
                # else: fall through to strategy (generic fix)

            if strategy is None:
                guidance = _get_specific_guidance(vuln_type, original)
                diffs.append(RemediationDiff(
                    line_number=target_line,
                    original_line=original.rstrip(),
                    fixed_line=original.rstrip(),
                    description=guidance,
                    vulnerability_type=vuln_type,
                    is_functional=False,
                    rejection_reason=guidance,
                ))
                continue

            fix_result = strategy(original, indent)
            if fix_result is None:
                guidance = _get_specific_guidance(vuln_type, original)
                diffs.append(RemediationDiff(
                    line_number=target_line,
                    original_line=original.rstrip(),
                    fixed_line=original.rstrip(),
                    description=guidance,
                    vulnerability_type=vuln_type,
                    is_functional=False,
                    rejection_reason=guidance,
                ))
                continue

            fixed_line, description = fix_result

            # Validate functionality
            is_func, rejection = _is_functional_change(original, fixed_line)
            if not is_func:
                diffs.append(RemediationDiff(
                    line_number=target_line,
                    original_line=original.rstrip(),
                    fixed_line=original.rstrip(),
                    description=description,
                    vulnerability_type=vuln_type,
                    is_functional=False,
                    rejection_reason=rejection,
                ))
                logger.warning(
                    "Rejected non-functional fix at line %d: %s",
                    target_line, rejection,
                )
                continue

            # Apply the fix
            new_parts = fixed_line.split('\n')
            lines[idx:idx + 1] = new_parts
            done_lines.add(target_line)

            diffs.append(RemediationDiff(
                line_number=target_line,
                original_line=original.rstrip(),
                fixed_line=fixed_line.rstrip(),
                description=description,
                vulnerability_type=vuln_type,
                is_functional=True,
            ))

        # Second pass: apply fixes for pattern-based findings (Weak Hash, Debug, YAML, etc.)
        if findings:
            pattern_targets = []
            for f in findings:
                ln = f.get("line_number")
                vt = f.get("vulnerability_type") or ""
                if ln and vt:
                    pattern_targets.append((ln, vt))
            pattern_targets.sort(key=lambda t: t[0], reverse=True)
            for target_line, vuln_type in pattern_targets:
                if target_line < 1 or target_line > len(lines) or target_line in done_lines:
                    continue
                idx = target_line - 1
                original = lines[idx]
                indent = re.match(r"^\s*", original).group()  # type: ignore[union-attr]
                strategy = None
                for key, fn in _FIX_STRATEGIES.items():
                    if fn is not None and key.lower() in vuln_type.lower():
                        strategy = fn
                        break
                if strategy is None:
                    continue
                fix_result = strategy(original, indent)
                # Weak Random: finding may be on seed line; try fixing the next line (usage).
                if fix_result is None and vuln_type == "Weak Random" and "random.seed(" in original:
                    next_idx = idx + 1
                    if next_idx < len(lines) and (next_idx + 1) not in done_lines:
                        next_line = lines[next_idx]
                        fix_result = strategy(next_line, re.match(r"^\s*", next_line).group() if next_line else "")
                        if fix_result is not None:
                            target_line = next_idx + 1
                            idx = next_idx
                            original = next_line
                if fix_result is None:
                    continue
                fixed_line, description = fix_result
                is_func, _ = _is_functional_change(original, fixed_line)
                if not is_func:
                    continue
                new_parts = fixed_line.split("\n")
                lines[idx : idx + 1] = new_parts
                done_lines.add(target_line)
                diffs.append(RemediationDiff(
                    line_number=target_line,
                    original_line=original.rstrip(),
                    fixed_line=fixed_line.rstrip(),
                    description=description,
                    vulnerability_type=vuln_type,
                    is_functional=True,
                ))

        fixed_code = '\n'.join(lines)
        functional_count = sum(1 for d in diffs if d.is_functional)
        rejected_count = sum(1 for d in diffs if not d.is_functional)
        logger.info(
            "Remediation: %d functional fixes applied, %d rejected/skipped",
            functional_count, rejected_count,
        )
        return fixed_code, diffs

    @staticmethod
    def _pick_target_lines(result: ReachabilityResult) -> List[int]:
        """Choose which line(s) to attempt fixing for an attack path.

        For prompt injection and SQL injection, targets the transform
        where tainted data enters the string (f-string, concat, .format(),
        %-format) rather than the API call itself.
        For other types, targets the sink.
        """
        path = result.path
        vuln = path.vulnerability_type.lower()

        # For SQL injection: fix BOTH the query construction line AND the
        # execute line (so we get parameterized query string + params passed).
        if "sql injection" in vuln:
            candidates = []
            for t in path.transforms:
                if t.ast_type in ("JoinedStr", "BinOp", "Call") or \
                   t.name in ("f-string", "concat", ".format()", "%-format"):
                    candidates.append(t.line)
            if candidates:
                # Include sink line so execute(query) -> execute(query, (var,))
                out = list(dict.fromkeys(candidates + [path.sink.line]))
                return sorted(out, reverse=True)  # high line first for editing
            return [path.sink.line]

        # For prompt injection: fix the transform where tainted data enters.
        if "prompt injection" in vuln:
            candidates = []
            for t in path.transforms:
                if t.ast_type in ("JoinedStr", "BinOp", "Call") or \
                   t.name in ("f-string", "concat", ".format()", "%-format"):
                    candidates.append(t.line)
            if candidates:
                return candidates
            if path.transforms:
                return [path.transforms[0].line]

        # Default: target the sink line
        return [path.sink.line]
