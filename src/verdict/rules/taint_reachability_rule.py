"""
If reachability_status == Confirmed Reachable, mark as Confirmed.
"""

from typing import Any, Optional

from ..models import Verdict
from .base_rule import BaseVerdictRule


class TaintReachabilityRule(BaseVerdictRule):
    """Confirmed Reachable → Confirmed verdict (any vuln type)."""

    def evaluate(
        self,
        finding: Any,
        file_context: Any,
        project_context: Any,
        line_content: Optional[str] = None,
    ) -> Optional[Verdict]:
        reach = getattr(finding, "reachability_status", None) or ""
        if reach == "Confirmed Reachable":
            return Verdict.confirmed(
                "Verified attack path from source to sink."
            )
        return None
