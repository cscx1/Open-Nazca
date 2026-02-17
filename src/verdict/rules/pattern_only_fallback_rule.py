"""
No attack_path and reachability None or Unverifiable → Unverified.
"""

from typing import Any, Optional

from ..models import Verdict
from .base_rule import BaseVerdictRule


class PatternOnlyFallbackRule(BaseVerdictRule):
    """Static match only; no verified data flow."""

    def evaluate(
        self,
        finding: Any,
        file_context: Any,
        project_context: Any,
        line_content: Optional[str] = None,
    ) -> Optional[Verdict]:
        attack_path = getattr(finding, "attack_path", None)
        reach = getattr(finding, "reachability_status", None)
        if attack_path is not None:
            return None
        if reach is None or reach == "Unverifiable":
            return Verdict.unverified(
                "Static match only; no verified data flow."
            )
        return None
