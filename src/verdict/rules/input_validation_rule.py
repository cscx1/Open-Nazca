"""
Out-of-scope when the finding line shows allowlist/sanitization/validation
on the same line as the sink (beyond SQL parameterization, which has its own rule).
"""

import re
from typing import Any, Optional

from ..models import Verdict
from .base_rule import BaseVerdictRule

# Heuristic: common validation/sanitization on same line
_VALIDATION_PATTERNS = re.compile(
    r"\b(allowlist|whitelist|blacklist|sanitize|escape|validate|strip|"
    r"isalnum|isalpha|isdigit|encode\s*\(|escape\s*\()",
    re.IGNORECASE,
)


class InputValidationRule(BaseVerdictRule):
    """Risk mitigated by input validation/sanitization on same line."""

    def evaluate(
        self,
        finding: Any,
        file_context: Any,
        project_context: Any,
        line_content: Optional[str] = None,
    ) -> Optional[Verdict]:
        if not line_content:
            return None
        if _VALIDATION_PATTERNS.search(line_content):
            return Verdict.out_of_scope(
                "Input validation or sanitization present on same line."
            )
        return None