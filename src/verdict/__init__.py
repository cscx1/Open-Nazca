"""
Verdict layer for Open Nazca: context-aware classification of findings.
Reduces false positives and prioritizes reachable vulnerabilities.
"""

from .models import Verdict, VerdictStatus, FindingWithVerdict
from .engine import VerdictEngine, ContextAggregator, FileContext, ProjectContext

__all__ = [
    "Verdict",
    "VerdictStatus",
    "FindingWithVerdict",
    "VerdictEngine",
    "ContextAggregator",
    "FileContext",
    "ProjectContext",
]
