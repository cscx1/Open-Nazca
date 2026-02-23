"""
Diff-aware scanning: scope findings to changed regions only.

Parses unified diffs and filters findings by line number. No persistence —
pure functions for use by scanner and PR workflow.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Any


def parse_unified_diff(diff_text: str) -> Dict[str, Set[int]]:
    """
    Parse unified diff text and return changed line numbers per file (new file side).

    Keys are file paths as they appear in the diff (e.g. "b/src/foo.py" is normalized
    to "src/foo.py"). Values are 1-based line numbers in the *new* file that were
    added or changed (lines after a +++ line, from the + side of @@ -x,y +a,b @@).

    Returns empty dict if parsing fails or diff is empty.
    """
    result: Dict[str, Set[int]] = {}
    current_file: str | None = None
    new_line_offset = 0   # 1-based line in new file
    in_hunk = False

    for raw_line in diff_text.splitlines():
        line = raw_line
        if line.startswith("+++ "):
            # New file path: strip "b/" prefix if present
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            current_file = path
            result.setdefault(current_file, set())
            in_hunk = False
            continue
        if line.startswith("--- "):
            continue
        if line.startswith("@@ "):
            # @@ -old_start,old_count +new_start,new_count @@
            match = re.search(r"\+(\d+),?\d*", line)
            if match:
                new_line_offset = int(match.group(1))
                in_hunk = True
            continue
        if not in_hunk or current_file is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            result[current_file].add(new_line_offset)
            new_line_offset += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass  # old file line, don't advance new
        else:
            # context line
            new_line_offset += 1

    return result


def filter_findings_by_diff(
    findings: List[Dict[str, Any]],
    path_for_lookup: str,
    changed_lines_by_file: Dict[str, Set[int]],
) -> List[Dict[str, Any]]:
    """
    Return only findings whose line_number is in the changed region for this file.

    path_for_lookup: the path of the file these findings refer to (e.g. as in the diff).
    changed_lines_by_file: from parse_unified_diff(); keys are diff paths.

    If changed_lines_by_file is empty, returns all findings (no filtering).
    Lookup tries exact path then basename so "src/foo.py" and "/abs/src/foo.py" can match.
    """
    if not changed_lines_by_file:
        return list(findings)

    # Resolve which set of lines to use
    changed = changed_lines_by_file.get(path_for_lookup)
    if changed is None:
        # Try basename for single-file or when diff uses relative path
        import os
        base = os.path.basename(path_for_lookup)
        for k, v in changed_lines_by_file.items():
            if k.endswith(base) or os.path.basename(k) == base:
                changed = v
                break
    if changed is None:
        return []  # file not in diff, no findings in scope

    return [f for f in findings if f.get("line_number") in changed]
