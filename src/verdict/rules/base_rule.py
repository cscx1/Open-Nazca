"""
Abstract base for verdict rules.

Semantics:
  - Return None: rule does not apply (engine continues to next rule).
  - Return Verdict: rule applies. Engine uses precedence: Confirmed/Out-of-scope
    terminate; Unverified does not (a later rule can still override).
  - Errors: let them propagate; the engine does not catch. Prefer stateless
    rules (no per-finding cache) so evaluation is deterministic.
"""

from abc import ABC, abstractmethod
from typing import Optional, Any

from ..models import Verdict


class BaseVerdictRule(ABC):
    """
    Override evaluate(). Return a Verdict when this rule applies, else None.
    None means "does not apply", not "could not determine". Keep rules stateless.
    """

    @abstractmethod
    def evaluate(
        self,
        finding: Any,
        file_context: Any,
        project_context: Any,
        line_content: Optional[str] = None,
    ) -> Optional[Verdict]:
        """If this rule applies, return the Verdict; else None."""
        pass
