"""
Static analysis pipeline for user-uploaded code.

Provides AST-based taint tracking, library-accurate sink classification,
NetworkX attack-path graph construction, reachability verification,
and functional remediation.
"""

from .taint_tracker import TaintTracker, TaintNode, TaintEdge
from .sink_classifier import SinkClassifier, SinkInfo
from .attack_graph import AttackGraph, AttackPath
from .reachability import ReachabilityVerifier, ReachabilityResult
from .remediator import FunctionalRemediator, RemediationDiff

__all__ = [
    "TaintTracker",
    "TaintNode",
    "TaintEdge",
    "SinkClassifier",
    "SinkInfo",
    "AttackGraph",
    "AttackPath",
    "ReachabilityVerifier",
    "ReachabilityResult",
    "FunctionalRemediator",
    "RemediationDiff",
]
