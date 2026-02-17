"""
XSS: Out-of-scope if no web framework and no routing. Confirmed only when
reachable, entry point, AND sink outputs to HTML/JS context (template, DOM, etc.).
"""

import re
from typing import Any, Optional

from ..models import Verdict
from .base_rule import BaseVerdictRule

# Sink or context that outputs to HTML/JS (templates, DOM, response body)
OUTPUT_CONTEXT = re.compile(
    r"render_template|\.html|innerHTML|document\.write|Markup|\.safe|\|safe|"
    r"Response\s*\(|make_response|escape\s*\(|html\.escape",
    re.IGNORECASE,
)


def _has_output_context(line_content: Optional[str], file_context: Any) -> bool:
    if line_content and OUTPUT_CONTEXT.search(line_content):
        return True
    line_map = getattr(file_context, "line_to_content", None) or {}
    for line in line_map.values():
        if OUTPUT_CONTEXT.search(line):
            return True
    return False


class XSSContextRule(BaseVerdictRule):
    """Applies only to XSS / template injection; requires HTML/JS output context for Confirmed."""

    def evaluate(
        self,
        finding: Any,
        file_context: Any,
        project_context: Any,
        line_content: Optional[str] = None,
    ) -> Optional[Verdict]:
        vuln_type = (getattr(finding, "vulnerability_type", "") or "").lower()
        if "xss" not in vuln_type and "template injection" not in vuln_type:
            return None

        is_web = getattr(project_context, "is_web_app", False)
        imports = getattr(file_context, "imports", []) or []
        has_web_in_file = any(
            x in imports for x in ("flask", "django", "fastapi", "starlette")
        )
        is_entry = getattr(file_context, "is_entry_point", False)
        reach = getattr(finding, "reachability_status", None) or ""
        has_output = _has_output_context(line_content, file_context)

        if reach == "Confirmed Reachable" and is_entry and has_output:
            return Verdict.confirmed(
                "Verified attack path from source to sink; entry point and HTML/JS output context."
            )
        if not is_web and not has_web_in_file and not is_entry:
            return Verdict.out_of_scope(
                "No web framework in project and no routing decorators in file."
            )
        if reach == "Confirmed Reachable" and is_entry and not has_output:
            return Verdict.unverified(
                "Reachable at entry point but no HTML/JS output context on line or in file."
            )
        return None
