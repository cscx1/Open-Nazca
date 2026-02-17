"""
SQL Injection: if the finding's line has parameterized query markers, Out-of-scope.
"""

import re
from typing import Any, Optional

from ..models import Verdict
from .base_rule import BaseVerdictRule

# Parameterized placeholders: ?, %s, %(name)s, :name
_PARAM_MARKERS = re.compile(
    r"\?|%s|%\s*\(\s*\w+\s*\)\s*s|:\w+"
)


class SQLSanitizerRule(BaseVerdictRule):
    """Risk mitigated by parameterized query on same line."""

    def evaluate(
        self,
        finding: Any,
        file_context: Any,
        project_context: Any,
        line_content: Optional[str] = None,
    ) -> Optional[Verdict]:
        vuln_type = (getattr(finding, "vulnerability_type", "") or "").lower()
        if "sql injection" not in vuln_type:
            return None
        if not line_content:
            return None
        if _PARAM_MARKERS.search(line_content):
            return Verdict.out_of_scope(
                "Risk mitigated by parameterized query."
            )
        return None
