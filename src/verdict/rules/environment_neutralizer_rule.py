"""
If the file path contains /tests/ or /examples/, mark as Unverified.
"""

from typing import Any, Optional

from ..models import Verdict
from .base_rule import BaseVerdictRule


class EnvironmentNeutralizerRule(BaseVerdictRule):
    """Finding in non-production code."""

    def evaluate(
        self,
        finding: Any,
        file_context: Any,
        project_context: Any,
        line_content: Optional[str] = None,
    ) -> Optional[Verdict]:
        if getattr(file_context, "is_test_file", False):
            return Verdict.unverified("Finding in non-production code.")
        return None
