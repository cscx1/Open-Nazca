"""
NetworkX-based attack-path graph construction.

Builds a directed graph whose nodes represent code locations (sources,
transforms, sinks) and whose edges represent data-flow propagation.
Provides methods to enumerate attack paths, compare before/after
remediation, and serialise for reporting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import networkx as nx
except ImportError:  # pragma: no cover – optional dependency
    nx = None  # type: ignore[assignment]

from .taint_tracker import TaintNode, TaintEdge, NodeKind
from .sink_classifier import SinkClassifier, SinkInfo

logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """One complete Source → [Transform …] → Sink path."""
    source: TaintNode
    transforms: List[TaintNode]
    sink: TaintNode
    sink_info: Optional[SinkInfo]  # library-accurate classification
    edges: List[TaintEdge]

    @property
    def vulnerability_type(self) -> str:
        if self.sink_info:
            return self.sink_info.vulnerability_type
        return "Unknown"

    @property
    def severity(self) -> str:
        if self.sink_info:
            return self.sink_info.severity
        return "MEDIUM"

    @property
    def cwe_id(self) -> str:
        if self.sink_info:
            return self.sink_info.cwe_id
        return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": {
                "name": self.source.name,
                "file": self.source.file,
                "line": self.source.line,
                "detail": self.source.detail,
            },
            "transforms": [
                {
                    "name": t.name,
                    "file": t.file,
                    "line": t.line,
                    "detail": t.detail,
                }
                for t in self.transforms
            ],
            "sink": {
                "name": self.sink.name,
                "file": self.sink.file,
                "line": self.sink.line,
                "detail": self.sink.detail,
            },
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
        }


class AttackGraph:
    """
    Directed graph of taint-flow paths derived from user-uploaded code.

    Requires ``networkx``.  If unavailable, methods return empty results
    instead of crashing.
    """

    def __init__(self):
        if nx is None:
            logger.warning("networkx not installed — attack graph disabled")
            self._G: Optional[Any] = None
            return
        self._G = nx.DiGraph()
        self._node_data: Dict[str, TaintNode] = {}
        self._edge_data: Dict[Tuple[str, str], TaintEdge] = {}

    # ── Graph construction ────────────────────────────────────

    def add_nodes_and_edges(
        self,
        nodes: List[TaintNode],
        edges: List[TaintEdge],
    ) -> None:
        """Populate the graph from taint-tracker output."""
        if self._G is None:
            return
        for node in nodes:
            uid = node.uid
            self._G.add_node(uid, kind=node.kind.value, label=node.name)
            self._node_data[uid] = node
        for edge in edges:
            su, du = edge.src.uid, edge.dst.uid
            self._G.add_edge(su, du, transform=edge.transform_type)
            self._edge_data[(su, du)] = edge

    # ── Path enumeration ──────────────────────────────────────

    def enumerate_attack_paths(self) -> List[AttackPath]:
        """
        Find all simple paths from every SOURCE to every SINK.

        Returns a list of ``AttackPath`` objects with library-accurate
        sink classification via ``SinkClassifier``.
        """
        if self._G is None:
            return []

        sources = [
            uid for uid, data in self._G.nodes(data=True)
            if data.get("kind") == NodeKind.SOURCE.value
        ]
        sinks = [
            uid for uid, data in self._G.nodes(data=True)
            if data.get("kind") == NodeKind.SINK.value
        ]

        paths: List[AttackPath] = []
        for src_uid in sources:
            for sink_uid in sinks:
                try:
                    for simple_path in nx.all_simple_paths(
                        self._G, src_uid, sink_uid, cutoff=15
                    ):
                        if len(simple_path) < 2:
                            continue
                        src_node = self._node_data[simple_path[0]]
                        sink_node = self._node_data[simple_path[-1]]
                        transforms = [
                            self._node_data[uid]
                            for uid in simple_path[1:-1]
                        ]
                        edge_list = []
                        for i in range(len(simple_path) - 1):
                            key = (simple_path[i], simple_path[i + 1])
                            if key in self._edge_data:
                                edge_list.append(self._edge_data[key])

                        sink_info = SinkClassifier.classify(sink_node.name)

                        paths.append(AttackPath(
                            source=src_node,
                            transforms=transforms,
                            sink=sink_node,
                            sink_info=sink_info,
                            edges=edge_list,
                        ))
                except nx.NetworkXNoPath:
                    continue
                except nx.NodeNotFound:
                    continue

        logger.info("Enumerated %d attack paths", len(paths))
        return paths

    # ── Comparison ────────────────────────────────────────────

    @staticmethod
    def compare(
        before: List[AttackPath],
        after: List[AttackPath],
    ) -> Dict[str, List[AttackPath]]:
        """
        Compare attack paths before and after remediation.

        Returns::

            {
                "eliminated": [paths removed by the fix],
                "remaining":  [paths still present],
                "introduced": [new paths introduced by the fix],
            }
        """

        def _path_key(p: AttackPath) -> Tuple[str, str, str, int]:
            return (
                p.source.name,
                p.sink.name,
                p.vulnerability_type,
                p.sink.line,
            )

        before_keys = {_path_key(p) for p in before}
        after_keys = {_path_key(p) for p in after}

        eliminated = [p for p in before if _path_key(p) not in after_keys]
        remaining = [p for p in after if _path_key(p) in before_keys]
        introduced = [p for p in after if _path_key(p) not in before_keys]

        return {
            "eliminated": eliminated,
            "remaining": remaining,
            "introduced": introduced,
        }

    # ── Serialisation ─────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the graph for JSON reports."""
        if self._G is None:
            return {"nodes": [], "edges": []}
        nodes = []
        for uid, data in self._G.nodes(data=True):
            tn = self._node_data.get(uid)
            if tn:
                nodes.append({
                    "uid": uid,
                    "kind": tn.kind.value,
                    "name": tn.name,
                    "file": tn.file,
                    "line": tn.line,
                    "detail": tn.detail,
                })
        edges = []
        for su, du in self._G.edges():
            te = self._edge_data.get((su, du))
            edges.append({
                "source": su,
                "target": du,
                "transform": te.transform_type if te else "",
                "detail": te.detail if te else "",
            })
        return {"nodes": nodes, "edges": edges}

    @property
    def node_count(self) -> int:
        return self._G.number_of_nodes() if self._G else 0

    @property
    def edge_count(self) -> int:
        return self._G.number_of_edges() if self._G else 0
