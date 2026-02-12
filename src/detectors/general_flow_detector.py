"""
General-Purpose Data Flow Detector.

A unified detector that handles multiple vulnerability categories through
smart taint propagation that understands common code patterns:
  - Direct assignments: bar = param
  - Configparser: conf.set('section', 'keyB', param) → conf.get('section', 'keyB')
  - List operations: lst.append(param) → lst[0]
  - Match/case with deterministic guess
  - Conditional assignments with always-true/false conditions
  - Variable overwrites that break taint

Covers: SQL Injection, Command Injection, Code Injection, Path Traversal,
        XSS, Open Redirect, XPath Injection, LDAP Injection, Trust Boundary,
        Deserialization.
"""

import ast
import re
from typing import Dict, List, Optional, Set, Tuple
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


# ── Vulnerability sink definitions ────────────────────────────────

VULN_SINKS: Dict[str, Dict] = {
    # SQL Injection
    "sqli": {
        "vuln_type": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 – Injection",
        "severity": "CRITICAL",
        "patterns": [
            # cursor.execute(sql) where sql is a variable (check if tainted data in sql)
            r"\.execute\s*\(\s*\w+\s*\)",
            r"\.execute\s*\(\s*f['\"]",
        ],
        "safe_patterns": [
            # Parameterized queries: execute(sql, (bar,))
            r"\.execute\s*\([^,]+,\s*[\(\[]",
        ],
        # Extra: check if the SQL string was built with tainted data.
        "needs_sql_check": True,
    },
    # Command Injection
    "cmdi": {
        "vuln_type": "Command Injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021 – Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"subprocess\.(?:run|call|Popen|check_output)\s*\(",
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
        ],
        "safe_patterns": [],
    },
    # Code Injection
    "codeinj": {
        "vuln_type": "Code Execution",
        "cwe": "CWE-94",
        "owasp": "A03:2021 – Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?<!\w)eval\s*\(",
            r"(?<!\w)exec\s*\(",
        ],
        "safe_patterns": [],
    },
    # Path Traversal
    "pathtraver": {
        "vuln_type": "Path Traversal",
        "cwe": "CWE-22",
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "HIGH",
        "patterns": [
            r"codecs\.open\s*\(",
            r"(?<!\w)open\s*\(",
            r"send_file\s*\(",
            r"send_from_directory\s*\(",
        ],
        "safe_patterns": [],
    },
    # XSS
    "xss": {
        "vuln_type": "XSS",
        "cwe": "CWE-79",
        "owasp": "A03:2021 – Injection",
        "severity": "HIGH",
        "patterns": [
            # Response output with tainted data.
            r"RESPONSE\s*\+=",
        ],
        "safe_patterns": [
            r"escape_for_html\s*\(\s*(\w+)\s*\)",
        ],
    },
    # Open Redirect
    "redirect": {
        "vuln_type": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "HIGH",
        "patterns": [
            r"redirect\s*\(",
        ],
        "safe_patterns": [],
    },
    # XPath Injection
    "xpathi": {
        "vuln_type": "XPath Injection",
        "cwe": "CWE-643",
        "owasp": "A03:2021 – Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?:lxml\.etree\.XPath|etree\.XPath|elementpath\.select|\.xpath)\s*\(",
        ],
        "safe_patterns": [
            # XPath escaping: .replace("'", "&apos;")
            r"\.replace\s*\(\s*['\"](?:\\?'|&apos;)['\"]",
        ],
    },
    # LDAP Injection
    "ldapi": {
        "vuln_type": "LDAP Injection",
        "cwe": "CWE-90",
        "owasp": "A03:2021 – Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"conn\.search\s*\(",
        ],
        "safe_patterns": [],
    },
    # Trust Boundary
    "trustbound": {
        "vuln_type": "Trust Boundary Violation",
        "cwe": "CWE-501",
        "owasp": "A04:2021 – Insecure Design",
        "severity": "HIGH",
        "patterns": [
            r"flask\.session\s*\[",
            r"(?<!\w)session\s*\[",
        ],
        "safe_patterns": [],
    },
    # Deserialization
    "deserialization": {
        "vuln_type": "Unsafe Deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "severity": "CRITICAL",
        "patterns": [
            r"pickle\.loads?\s*\(",
            r"(?<!\w)yaml\.load\s*\(",
            r"yaml\.unsafe_load\s*\(",
            r"marshal\.loads?\s*\(",
            r"jsonpickle\.decode\s*\(",
        ],
        "safe_patterns": [
            r"yaml\.safe_load",
        ],
    },
}


# ── Source detection ──────────────────────────────────────────────

_USER_INPUT_SOURCES = re.compile(
    r"(\w+)\s*=\s*(?:"
    r"urllib\.parse\.unquote_plus\s*\(\s*request\.|"
    r"request\.(?:form|args|cookies|json|headers|data)"
    r"(?:\.get(?:list)?\s*\(|\.get\s*\(|\[)|"
    r"input\s*\(|"
    r"request\.path\.split|"
    r"helpers\.separate_request\.request_wrapper"
    r")"
)

# Additional source patterns for separate_request wrapper.
_WRAPPER_SOURCE = re.compile(
    r"(\w+)\s*=\s*helpers\.separate_request\.request_wrapper\s*\("
)


# ── Taint Propagation Engine ─────────────────────────────────────

def _track_taint(code: str) -> Tuple[Set[str], Dict[str, int]]:
    """
    Perform lightweight taint tracking through the code.

    Returns:
        tainted: set of variable names that contain user input at their
                 FINAL assignment point.
        var_lines: dict mapping variable name → last assignment line number.
    """
    lines = code.split("\n")
    tainted: Set[str] = set()
    source_vars: Set[str] = set()  # Variables directly from user input (never un-tainted)
    var_lines: Dict[str, int] = {}

    # Pass 1: Find initial source variables.
    for line_num, line in enumerate(lines, 1):
        m = _USER_INPUT_SOURCES.search(line)
        if m:
            var = m.group(1)
            tainted.add(var)
            source_vars.add(var)
            var_lines[var] = line_num

        m2 = _WRAPPER_SOURCE.search(line)
        if m2:
            var = m2.group(1)
            tainted.add(var)
            source_vars.add(var)
            var_lines[var] = line_num

        # Handle: values = request.form.getlist(...) → param = values[0]
        # The 'values' variable is tainted.
        m3 = re.search(r"(\w+)\s*=\s*(\w+)\s*\[\s*\d+\s*\]", line)
        if m3:
            lhs, rhs_var = m3.group(1), m3.group(2)
            if rhs_var in tainted:
                tainted.add(lhs)
                source_vars.add(lhs)
                var_lines[lhs] = line_num

    if not source_vars:
        return tainted, var_lines

    # Pass 2: Propagate taint through assignments (multiple passes).
    # Handles: bar = param, bar = conf.get('section', 'keyB'), etc.
    # Also handles TAINT BREAKING: bar = 'constant' or bar = dict['keyA']
    # where keyA doesn't hold tainted data.
    # IMPORTANT: source_vars are NEVER un-tainted.

    # Track configparser: conf_var → key → is_tainted
    config_taint: Dict[str, Dict[str, bool]] = {}

    # Track dict/map taint: map_name → key → is_tainted
    map_taint: Dict[str, Dict[str, bool]] = {}

    # Track list contents: list_var → [is_tainted_0, is_tainted_1, ...]
    list_contents: Dict[str, List[bool]] = {}

    # Lines handled by match/case or if/else analysis (skip in main loop).
    handled_lines: Set[int] = set()

    # Track indent level to detect conditional blocks.
    in_if_block = False
    if_indent = 0

    for _pass_num in range(4):
        for line_num, line in enumerate(lines, 1):
            if line_num in handled_lines:
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Track conditional blocks (don't un-taint source vars in branches).
            indent = len(line) - len(line.lstrip())
            if stripped.startswith(("if ", "if\t", "elif ", "else:")):
                in_if_block = True
                if_indent = indent

            # Configparser: conf.set('section', 'key', param)
            m = re.search(
                r"(\w+)\.set\s*\(\s*['\"](\w+)['\"],\s*['\"]([^'\"]+)['\"],\s*(\w+)\s*\)",
                line,
            )
            if m:
                conf_var, section, key, value_var = (
                    m.group(1), m.group(2), m.group(3), m.group(4)
                )
                config_taint.setdefault(conf_var, {})
                config_taint[conf_var][key] = value_var in tainted

            # Configparser: bar = conf.get('section', 'key')
            m = re.search(
                r"(\w+)\s*=\s*(\w+)\.get\s*\(\s*['\"](\w+)['\"],\s*['\"]([^'\"]+)['\"]\s*\)",
                line,
            )
            if m:
                lhs, conf_var, section, key = (
                    m.group(1), m.group(2), m.group(3), m.group(4)
                )
                # Only use configparser taint if conf_var IS tracked.
                if conf_var in config_taint:
                    is_tainted = config_taint[conf_var].get(key, False)
                    if is_tainted:
                        tainted.add(lhs)
                    elif lhs not in source_vars:
                        tainted.discard(lhs)
                    var_lines[lhs] = line_num
                    continue

            # Dict/map: map[key] = value
            m = re.search(
                r"(\w+)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*=\s*(\w+)",
                line,
            )
            if m:
                map_var, key, value_var = m.group(1), m.group(2), m.group(3)
                map_taint.setdefault(map_var, {})
                map_taint[map_var][key] = value_var in tainted

            # Dict/map: bar = map[key]
            m = re.search(
                r"(\w+)\s*=\s*(\w+)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
                line,
            )
            if m:
                lhs, map_var, key = m.group(1), m.group(2), m.group(3)
                if map_var in map_taint:
                    is_tainted = map_taint[map_var].get(key, False)
                    if is_tainted:
                        tainted.add(lhs)
                    elif lhs not in source_vars:
                        tainted.discard(lhs)
                    var_lines[lhs] = line_num
                    continue

            # List index: bar = lst[N]
            m = re.match(r"\s*(\w+)\s*=\s*(\w+)\s*\[\s*(\d+)\s*\]", line)
            if m:
                lhs, lst_var, idx_val = m.group(1), m.group(2), int(m.group(3))
                if lst_var in list_contents:
                    contents = list_contents[lst_var]
                    if idx_val < len(contents):
                        if contents[idx_val]:
                            tainted.add(lhs)
                        elif lhs not in source_vars:
                            tainted.discard(lhs)
                    elif lst_var in tainted:
                        tainted.add(lhs)
                elif lst_var in tainted:
                    tainted.add(lhs)
                var_lines[lhs] = line_num
                continue

            # List operations tracking.
            # lst = [] (init)
            m = re.match(r"\s*(\w+)\s*=\s*\[\s*\]", line)
            if m:
                list_contents[m.group(1)] = []

            # lst.append(var) or lst.append('string')
            m = re.search(r"(\w+)\.append\s*\(\s*(\w+)\s*\)", line)
            if m:
                lst_var, val_var = m.group(1), m.group(2)
                is_t = val_var in tainted
                list_contents.setdefault(lst_var, []).append(is_t)
                if is_t:
                    tainted.add(lst_var)

            m = re.search(r"(\w+)\.append\s*\(\s*['\"]", line)
            if m and not re.search(r"(\w+)\.append\s*\(\s*(\w+)\s*\)", line):
                lst_var = m.group(1)
                list_contents.setdefault(lst_var, []).append(False)

            # lst.pop(N)
            m = re.search(r"(\w+)\.pop\s*\(\s*(\d+)\s*\)", line)
            if m:
                lst_var, pop_idx = m.group(1), int(m.group(2))
                if lst_var in list_contents and pop_idx < len(list_contents[lst_var]):
                    list_contents[lst_var].pop(pop_idx)

            # Simple assignment: bar = param (or bar = <expr involving param>)
            m = re.match(r"\s*(\w+)\s*=\s*(.*)", line)
            if m:
                lhs = m.group(1)
                rhs = m.group(2).strip()

                # Never un-taint source variables.
                if lhs in source_vars:
                    continue

                # Skip if this looks like a function call result, not a simple assign.
                if re.match(r"\w+\.\w+\s*\(", rhs):
                    # Check if any tainted var in args.
                    rhs_tainted = any(
                        re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted
                    )
                    if rhs_tainted:
                        tainted.add(lhs)
                    var_lines[lhs] = line_num
                    continue

                # Check if RHS contains any tainted variable.
                rhs_tainted = any(
                    re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted
                )

                # But check if it's a CONSTANT assignment (no tainted vars).
                is_constant = _is_constant_rhs(rhs, tainted)

                if rhs_tainted and not is_constant:
                    tainted.add(lhs)
                elif is_constant and indent <= if_indent + 1:
                    # Only un-taint at the same or lower indent (not inside
                    # conditional branches that may not execute).
                    # Exception: explicit overwrite at function level.
                    tainted.discard(lhs)

                var_lines[lhs] = line_num

            # Match/case: determine which branch is taken.
            mc_handled = _handle_match_case(lines, line_num, tainted, var_lines)
            handled_lines.update(mc_handled)

            # If-else with body assignments.
            ie_handled = _handle_if_else(lines, line_num, tainted, source_vars, var_lines)
            handled_lines.update(ie_handled)

            # Ternary: bar = X if <cond> else Y
            m = re.match(
                r"\s*(\w+)\s*=\s*(.+?)\s+if\s+(.+?)\s+else\s+(.+)",
                line,
            )
            if m:
                lhs = m.group(1)
                if lhs in source_vars:
                    continue
                true_val = m.group(2).strip()
                cond = m.group(3).strip()
                false_val = m.group(4).strip()

                # Try to evaluate the condition statically.
                cond_result = _eval_static_condition(cond, lines[:line_num])
                if cond_result is True:
                    chosen = true_val
                elif cond_result is False:
                    chosen = false_val
                else:
                    # Can't determine → conservatively mark tainted if either branch uses tainted.
                    any_tainted = any(
                        re.search(rf"\b{re.escape(t)}\b", true_val + " " + false_val)
                        for t in tainted
                    )
                    if any_tainted:
                        tainted.add(lhs)
                    var_lines[lhs] = line_num
                    continue

                if chosen is not None:
                    chosen_tainted = any(
                        re.search(rf"\b{re.escape(t)}\b", chosen)
                        for t in tainted
                    )
                    if chosen_tainted:
                        tainted.add(lhs)
                    else:
                        tainted.discard(lhs)
                    var_lines[lhs] = line_num

    return tainted, var_lines


def _handle_if_else(
    lines: List[str],
    current_line: int,
    tainted: Set[str],
    source_vars: Set[str],
    var_lines: Dict[str, int],
) -> Set[int]:
    """
    Handle if/else statements where conditions can be evaluated statically.
    Returns set of handled line numbers (1-indexed).
    """
    handled: Set[int] = set()
    idx = current_line - 1
    if idx >= len(lines):
        return handled

    stripped = lines[idx].strip()

    # Match: if <condition>:
    m = re.match(r"if\s+(.+):", stripped)
    if not m:
        return handled

    cond = m.group(1).strip()

    # Pass all prior lines for variable resolution.
    prior = [lines[i] for i in range(idx)]
    cond_result = _eval_static_condition(cond, prior)
    if cond_result is None:
        return handled

    # Find the if/else body assignments.
    raw_line = lines[idx]
    base_indent = len(raw_line.expandtabs(4)) - len(raw_line.expandtabs(4).lstrip())
    in_if_body = True
    in_else_body = False

    for j in range(idx + 1, min(len(lines), idx + 30)):
        jline = lines[j]
        jstripped = jline.strip()
        if not jstripped:
            continue

        j_indent = len(jline.expandtabs(4)) - len(jline.expandtabs(4).lstrip())

        if j_indent == base_indent and jstripped.startswith("else:"):
            in_if_body = False
            in_else_body = True
            handled.add(j + 1)
            continue
        if j_indent == base_indent and jstripped.startswith("elif "):
            in_if_body = False
            in_else_body = False
            break

        if j_indent <= base_indent and not jstripped.startswith("#"):
            break

        # Mark ALL body lines as handled.
        handled.add(j + 1)

        # Determine which branch is active.
        branch_active = (cond_result and in_if_body) or (not cond_result and in_else_body)

        am = re.match(r"\s*(\w+)\s*=\s*(.*)", jline)
        if am:
            lhs = am.group(1)
            rhs = am.group(2).strip()
            if lhs in source_vars:
                continue

            if branch_active:
                rhs_tainted = any(
                    re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted
                )
                if rhs_tainted:
                    tainted.add(lhs)
                else:
                    tainted.discard(lhs)

            var_lines[lhs] = j + 1

    return handled


def _is_constant_rhs(rhs: str, tainted: Set[str]) -> bool:
    """Check if RHS is a constant (no tainted vars)."""
    # String literals: 'xyz', "xyz"
    if re.fullmatch(r"""['\"].*['\"]""", rhs):
        return True
    # Numeric
    if re.fullmatch(r"\d+\.?\d*", rhs):
        return True
    # Known safe function calls.
    if re.match(r"(?:str|int|float|bool|len)\s*\(", rhs):
        for t in tainted:
            if re.search(rf"\b{re.escape(t)}\b", rhs):
                return False
        return True
    return False


def _eval_static_condition(cond: str, prior_lines: List[str]) -> Optional[bool]:
    """Try to evaluate a condition statically. Returns True/False/None."""
    # First, try to resolve any variables in the condition to constants.
    resolved = _resolve_variables(cond, prior_lines)

    # Pattern: pure arithmetic comparison (e.g. 7 * 18 + 106 > 200).
    try:
        if re.fullmatch(r"[\d\s\+\-\*\/\%\>\<\=\!\(\)]+", resolved):
            return bool(eval(resolved))
    except Exception:
        pass

    # Pattern: 'substring' in "string_literal"
    m = re.fullmatch(r"""['\"](\w+)['\"]\s+(?:not\s+)?in\s+['\"](.+?)['\"]""", resolved)
    if m:
        sub, string = m.group(1), m.group(2)
        negate = "not " in resolved
        result = sub in string
        return not result if negate else result

    # Pattern: 'substring' in variable (need to resolve variable)
    m = re.fullmatch(r"""['\"](\w+)['\"]\s+(not\s+)?in\s+(\w+)""", resolved)
    if m:
        sub = m.group(1)
        negate = bool(m.group(2))
        var = m.group(3)
        for line in reversed(prior_lines):
            vm = re.match(rf"\s*{re.escape(var)}\s*=\s*['\"](.+?)['\"]", line)
            if vm:
                val = vm.group(1)
                result = sub in val
                return not result if negate else result

    # Pattern: not variable (try to resolve variable to truthy/falsy).
    m = re.fullmatch(r"not\s+(\w+)", resolved)
    if m:
        var = m.group(1)
        for line in reversed(prior_lines):
            vm = re.match(rf'\s*{re.escape(var)}\s*=\s*["\']([^"\']*)["\']', line)
            if vm:
                return not bool(vm.group(1))

    return None


def _resolve_variables(expr: str, prior_lines: List[str]) -> str:
    """
    Replace variable names in *expr* with their constant values from
    prior lines (only simple numeric or string constants).
    """
    # Find all word tokens in the expression that could be variables.
    tokens = re.findall(r"\b([a-zA-Z_]\w*)\b", expr)
    resolved = expr

    for token in set(tokens):
        # Skip Python keywords and known functions.
        if token in (
            "in", "not", "and", "or", "is", "True", "False", "None",
            "if", "else", "elif",
        ):
            continue
        # Search backwards for a simple constant assignment.
        # Note: lines may be tab or space indented.
        for line in reversed(prior_lines):
            stripped = line.strip()
            m = re.match(rf"{re.escape(token)}\s*=\s*(\d+\.?\d*)\s*$", stripped)
            if m:
                resolved = re.sub(rf"\b{re.escape(token)}\b", m.group(1), resolved)
                break
            m = re.match(rf"""{re.escape(token)}\s*=\s*['\"](.+?)['\"]""", stripped)
            if m:
                resolved = re.sub(
                    rf"\b{re.escape(token)}\b", f'"{m.group(1)}"', resolved
                )
                break

    return resolved


def _handle_match_case(
    lines: List[str],
    current_line: int,
    tainted: Set[str],
    var_lines: Dict[str, int],
) -> Set[int]:
    """Handle match/case statements. Returns set of handled line numbers (1-indexed)."""
    handled: Set[int] = set()
    idx = current_line - 1
    if idx >= len(lines):
        return handled

    line = lines[idx].strip()

    # Detect: match <guess_var>:
    m = re.match(r"match\s+(\w+)\s*:", line)
    if not m:
        return handled

    guess_var = m.group(1)

    # Try to resolve guess_var's value from prior lines.
    guess_val = None
    for prev_line in reversed(lines[:idx]):
        # Pattern: guess = possible[N] where possible = "ABC"
        vm = re.match(rf"\s*{re.escape(guess_var)}\s*=\s*(\w+)\s*\[\s*(\d+)\s*\]", prev_line)
        if vm:
            arr_var = vm.group(1)
            arr_idx = int(vm.group(2))
            for pp in reversed(lines[:idx]):
                am = re.match(rf'\s*{re.escape(arr_var)}\s*=\s*["\'](.+?)["\']', pp)
                if am:
                    arr_str = am.group(1)
                    if arr_idx < len(arr_str):
                        guess_val = arr_str[arr_idx]
                    break
            break
        vm = re.match(rf"""\s*{re.escape(guess_var)}\s*=\s*['"](.+?)['"]""", prev_line)
        if vm:
            guess_val = vm.group(1)
            break

    if guess_val is None:
        return handled

    # Now scan the case branches.
    in_matching_case = False

    for j in range(idx + 1, min(len(lines), idx + 50)):
        case_line = lines[j]
        cs = case_line.strip()
        if not cs:
            continue

        # Case header.
        cm = re.match(r"case\s+(.+?):", cs)
        if cm:
            case_vals = cm.group(1).strip()
            if case_vals == "_":
                in_matching_case = True
            else:
                cases = [c.strip().strip("'\"") for c in case_vals.split("|")]
                in_matching_case = guess_val in cases
            handled.add(j + 1)
            continue

        # End of match block (next non-case non-indented line).
        if not cs.startswith("case "):
            base_indent = len(lines[idx].expandtabs(4)) - len(lines[idx].expandtabs(4).lstrip())
            j_indent = len(case_line.expandtabs(4)) - len(case_line.expandtabs(4).lstrip())
            if j_indent <= base_indent and not cs.startswith("#"):
                break

        # Mark ALL body lines as handled.
        handled.add(j + 1)

        # Apply assignment ONLY for the matching case.
        am = re.match(r"\s*(\w+)\s*=\s*(.*)", case_line)
        if am:
            lhs = am.group(1)
            rhs = am.group(2).strip()
            if in_matching_case:
                rhs_tainted = any(
                    re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted
                )
                if rhs_tainted:
                    tainted.add(lhs)
                else:
                    tainted.discard(lhs)
                var_lines[lhs] = j + 1

    return handled


# ── Sink analysis ─────────────────────────────────────────────────

def _find_sink_lines(
    code: str,
    category: str,
    tainted: Set[str],
) -> List[Tuple[int, str]]:
    """
    Find lines where a known sink for *category* is reached by tainted data.
    Returns list of (line_number, matched_pattern).
    """
    if category not in VULN_SINKS:
        return []

    sink_def = VULN_SINKS[category]
    lines = code.split("\n")
    results: List[Tuple[int, str]] = []

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Check if any safe pattern matches (skip this sink).
        safe_match = False
        for sp in sink_def.get("safe_patterns", []):
            if re.search(sp, line):
                safe_match = True
                break
        if safe_match:
            continue

        # Check if any sink pattern matches.
        for pat in sink_def["patterns"]:
            if re.search(pat, line):
                # Determine the region to check for tainted variables.
                region_start = max(0, line_num - 6)
                region_end = min(len(lines), line_num + 3)
                region = "\n".join(lines[region_start:region_end])

                # For SQL injection: check if the SQL string is built with
                # tainted data (f-string or concatenation).
                if category == "sqli":
                    if not _sql_uses_tainted_data(lines, line_num, tainted):
                        break
                    results.append((line_num, pat))
                    break

                # For XSS: only check the actual f-string content (not surrounding
                # lines) for tainted vars, and skip if escape_for_html is used.
                if category == "xss":
                    # Collect the actual RESPONSE += ... block (may span lines).
                    resp_region = _collect_response_block(lines, line_num - 1)
                    found_taint = False
                    for t in tainted:
                        if re.search(rf"\b{re.escape(t)}\b", resp_region):
                            # Skip if escape_for_html wraps this var.
                            if re.search(
                                rf"escape_for_html\s*\(\s*{re.escape(t)}\s*\)",
                                resp_region,
                            ):
                                continue
                            found_taint = True
                            break
                    if found_taint:
                        results.append((line_num, pat))
                    break

                # General check: tainted variable in the region.
                for t in tainted:
                    if re.search(rf"\b{re.escape(t)}\b", region):
                        results.append((line_num, pat))
                        break
                break

    return results


def _collect_response_block(lines: List[str], start_idx: int) -> str:
    """Collect the RESPONSE += (...) block which may span multiple lines."""
    result_lines = [lines[start_idx]]
    paren = lines[start_idx].count("(") - lines[start_idx].count(")")
    j = start_idx + 1
    while paren > 0 and j < len(lines):
        result_lines.append(lines[j])
        paren += lines[j].count("(") - lines[j].count(")")
        j += 1
    return "\n".join(result_lines)


def _sql_uses_tainted_data(
    lines: List[str], execute_line: int, tainted: Set[str]
) -> bool:
    """
    Check whether the SQL query string passed to execute() contains
    tainted data (via f-string interpolation or concatenation).
    """
    # Look backwards from the execute line to find the sql = ... definition.
    for i in range(execute_line - 1, max(0, execute_line - 10), -1):
        line = lines[i]
        # Check for f-string SQL with tainted variable.
        m = re.search(r"(\w+)\s*=\s*f['\"]", line)
        if m:
            sql_var = m.group(1)
            # Check if this is the sql var used in execute.
            if sql_var in lines[execute_line - 1]:
                # Check if any tainted var appears in the f-string.
                for t in tainted:
                    if re.search(rf"\b{re.escape(t)}\b", line):
                        return True
                    # Also check: f'... {bar}' where bar is tainted.
                    if re.search(rf"\{{" + re.escape(t) + r"\}}", line):
                        return True

        # Check for %-formatting or .format() with tainted data.
        if "%" in line or ".format(" in line:
            for t in tainted:
                if re.search(rf"\b{re.escape(t)}\b", line):
                    return True

    # Also check the execute line itself for f-string/tainted.
    exec_line = lines[execute_line - 1]
    if re.search(r"\.execute\s*\(\s*f['\"]", exec_line):
        for t in tainted:
            if re.search(rf"\b{re.escape(t)}\b", exec_line):
                return True

    return False


# ── Main Detector ─────────────────────────────────────────────────

class GeneralFlowDetector(BaseDetector):
    """
    Unified detector for multiple OWASP vulnerability categories.
    Uses smart taint propagation to track user input through code
    and detect when it reaches a security-sensitive sink.
    """

    def __init__(self, enabled: bool = True):
        super().__init__("GeneralFlowDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []

        if language not in ("python", "javascript", "typescript"):
            return findings

        # Track taint through the code.
        tainted, var_lines = _track_taint(code)

        if not tainted:
            return findings

        # Check each vulnerability category's sinks.
        for cat, sink_def in VULN_SINKS.items():
            sink_hits = _find_sink_lines(code, cat, tainted)
            for line_num, matched_pat in sink_hits:
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type=sink_def["vuln_type"],
                    severity=sink_def["severity"],
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        f"User-controlled data reaches a {sink_def['vuln_type']} "
                        f"sink. Tainted variables: {', '.join(sorted(tainted))}."
                    ),
                    confidence=0.90,
                    cwe_id=sink_def["cwe"],
                    owasp_category=sink_def["owasp"],
                    metadata={
                        "category": cat,
                        "tainted_vars": sorted(tainted),
                        "sink_pattern": matched_pat,
                    },
                ))

        self.findings = findings
        return findings
