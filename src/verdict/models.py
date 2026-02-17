"""
Verdict layer data models.
"""

from dataclasses import dataclass
from typing import Optional

# Avoid circular import: we accept "Any" finding-like object in FindingWithVerdict
# and the scanner passes detectors.Finding
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class VerdictStatus:
    """Verdict outcomes for a finding."""
    CONFIRMED = "Confirmed"
    OUT_OF_SCOPE = "Out-of-scope"
    UNVERIFIED = "Unverified"


@dataclass(frozen=True)
class Verdict:
    """Final classification for a finding: status and human-readable reason."""
    status: str  # Confirmed | Out-of-scope | Unverified
    reason: str

    @classmethod
    def confirmed(cls, reason: str) -> "Verdict":
        return cls(status=VerdictStatus.CONFIRMED, reason=reason)

    @classmethod
    def out_of_scope(cls, reason: str) -> "Verdict":
        return cls(status=VerdictStatus.OUT_OF_SCOPE, reason=reason)

    @classmethod
    def unverified(cls, reason: str) -> "Verdict":
        return cls(status=VerdictStatus.UNVERIFIED, reason=reason)


@dataclass
class FindingWithVerdict:
    """A detector Finding plus the verdict layer's classification."""
    finding: object  # detectors.Finding
    verdict: Verdict

    def to_dict(self) -> dict:
        """Serialize for reports; finding must have to_dict()."""
        d = getattr(self.finding, "to_dict", lambda: {})()
        d["verdict_status"] = self.verdict.status
        d["verdict_reason"] = self.verdict.reason
        return d
