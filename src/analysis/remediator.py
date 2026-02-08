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
    # Pattern: cursor.execute(f"SELECT ... {var} ...")
    # or:      cursor.execute("SELECT ... " + var)
    m = re.search(r'\.execute\(\s*f["\']', line)
    if m:
        # Replace f-string with parameterised query placeholder
        # This is a best-effort transformation
        fixed = re.sub(
            r'\.execute\(\s*f(["\'])(.*?)\{(\w+)\}(.*?)\1',
            r'.execute(\1\2?\4\1, (\3,)',
            line,
        )
        if fixed != line:
            return fixed, 'Converted f-string SQL to parameterised query with ? placeholder'

    # Pattern: execute("... " + var + " ...")
    if '.execute(' in line and '+' in line:
        # Cannot safely auto-fix arbitrary concatenation — mark for manual review
        return None

    return None


def _fix_command_injection(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Replace os.system() with subprocess.run(shell=False)."""
    if 'os.system(' in line:
        fixed = line.replace('os.system(', 'subprocess.run(')
        # Ensure shell=False
        if 'shell=' not in fixed:
            fixed = fixed.rstrip('\n').rstrip(')')
            fixed += ', shell=False)\n'
        return fixed, 'Replaced os.system() with subprocess.run(shell=False)'

    if 'shell=True' in line:
        fixed = line.replace('shell=True', 'shell=False')
        return fixed, 'Changed shell=True to shell=False'

    return None


def _fix_code_execution(line: str, indent: str) -> Optional[Tuple[str, str]]:
    """Replace eval() with ast.literal_eval(), disable exec()."""
    if 'eval(' in line and 'literal_eval' not in line:
        fixed = line.replace('eval(', 'ast.literal_eval(')
        return fixed, 'Replaced eval() with ast.literal_eval() (safe for literals)'

    if 'exec(' in line:
        # exec() has no safe drop-in replacement — disable the call
        fixed = f'{indent}raise RuntimeError("exec() call disabled for security")\n'
        return fixed, 'Replaced exec() with RuntimeError — no safe alternative'

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


# ── Strategy dispatch ────────────────────────────────────────────

_FIX_STRATEGIES = {
    "Hardcoded Secret":        _fix_hardcoded_secret,
    "SQL Injection":           _fix_sql_injection,
    "Command Injection":       _fix_command_injection,
    "Code Execution":          _fix_code_execution,
    "Prompt Injection":        _fix_prompt_injection_fstring,
    "Path Traversal":          None,  # requires context — manual
    "SSRF":                    None,  # requires allowlist — manual
    "XSS / Template Injection": None,  # requires escaping logic — manual
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
    ) -> Tuple[str, List[RemediationDiff]]:
        """
        Apply fixes to *source_code* for paths classified as
        Confirmed Reachable.

        For each attack path the fixer identifies the best line to modify:
        - For most vulnerabilities: the **sink** line
        - For prompt injection: the **transform** line where tainted data
          is interpolated into the prompt (f-string, concat, .format())

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

            if strategy is None:
                diffs.append(RemediationDiff(
                    line_number=target_line,
                    original_line=original.rstrip(),
                    fixed_line=original.rstrip(),
                    description="No automated fix available — requires manual remediation",
                    vulnerability_type=vuln_type,
                    is_functional=False,
                    rejection_reason="No safe automated fix strategy for this vulnerability type",
                ))
                continue

            fix_result = strategy(original, indent)
            if fix_result is None:
                diffs.append(RemediationDiff(
                    line_number=target_line,
                    original_line=original.rstrip(),
                    fixed_line=original.rstrip(),
                    description="Fix strategy could not be applied to this code pattern",
                    vulnerability_type=vuln_type,
                    is_functional=False,
                    rejection_reason="Code pattern not recognised by automated fixer",
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

        For prompt injection, targets the transform where tainted data
        enters the prompt (f-string, concat, .format()) rather than the
        API call itself.  For other types, targets the sink.
        """
        path = result.path
        vuln = path.vulnerability_type.lower()

        if "prompt injection" in vuln:
            # Fix the transform where interpolation happens
            candidates = []
            for t in path.transforms:
                if t.ast_type in ("JoinedStr", "BinOp", "Call") or \
                   t.name in ("f-string", "concat", ".format()", "%-format"):
                    candidates.append(t.line)
            if candidates:
                return candidates
            # Fallback: try the first transform or the sink
            if path.transforms:
                return [path.transforms[0].line]

        # Default: target the sink line
        return [path.sink.line]
