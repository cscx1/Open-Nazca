"""
Unit tests for src/analysis/attack_graph.py.

Covers: graph construction from taint nodes/edges, path enumeration,
to_dict serialisation, and before/after path comparison.
"""
import pytest

from src.analysis.taint_tracker import TaintTracker, NodeKind
from src.analysis.attack_graph import AttackGraph, AttackPath


@pytest.fixture()
def tracker():
    return TaintTracker()


def _build_graph(code: str, file_name: str = "test.py") -> AttackGraph:
    t = TaintTracker()
    nodes, edges = t.analyse(file_name, code)
    g = AttackGraph()
    g.add_nodes_and_edges(nodes, edges)
    return g


# Graph construction


def test_simple_source_to_sink_has_path():
    code = "x = input()\ncursor.execute(x)"
    g = _build_graph(code)
    paths = g.enumerate_attack_paths()
    assert paths, "Direct source → sink should yield at least one attack path"


def test_indirect_path_through_transform():
    code = 'uid = request.args.get("id")\nquery = "SELECT * FROM t WHERE id=" + uid\ncursor.execute(query)'
    g = _build_graph(code)
    paths = g.enumerate_attack_paths()
    assert paths, "Indirect source → transform → sink should yield a path"
    path = paths[0]
    assert path.source is not None
    assert path.sink is not None


def test_empty_code_no_paths():
    g = _build_graph("")
    assert g.enumerate_attack_paths() == []


def test_no_source_no_paths():
    code = "cursor.execute('SELECT * FROM t WHERE active=1')"
    g = _build_graph(code)
    paths = g.enumerate_attack_paths()
    assert paths == [], "Constant-only query has no source → no attack paths"


# Path serialisation


def test_attack_path_to_dict_has_required_keys():
    code = "x = input()\ncursor.execute(x)"
    g = _build_graph(code)
    paths = g.enumerate_attack_paths()
    assert paths
    d = paths[0].to_dict()
    for key in ("source", "sink", "vulnerability_type", "severity", "cwe_id"):
        assert key in d, f"to_dict() missing key: {key}"
    assert "line" in d["source"]
    assert "line" in d["sink"]


def test_attack_path_vulnerability_type_not_unknown():
    code = "x = input()\ncursor.execute(x)"
    g = _build_graph(code)
    paths = g.enumerate_attack_paths()
    for p in paths:
        assert p.vulnerability_type != "Unknown", (
            "cursor.execute should resolve to a known vulnerability type via SinkClassifier"
        )


# Graph statistics


def test_node_and_edge_counts_positive():
    code = "x = input()\ncursor.execute(x)"
    g = _build_graph(code)
    g.enumerate_attack_paths()
    assert g.node_count >= 2
    assert g.edge_count >= 1


# Before / after comparison


def test_compare_eliminated_paths():
    before_code = "x = input()\ncursor.execute(x)"
    after_code = "x = input()\ncursor.execute('SELECT * FROM t WHERE id = %s', (x,))"

    t = TaintTracker()
    before_nodes, before_edges = t.analyse("test.py", before_code)
    g_before = AttackGraph()
    g_before.add_nodes_and_edges(before_nodes, before_edges)
    before_paths = g_before.enumerate_attack_paths()

    after_nodes, after_edges = t.analyse("test.py", after_code)
    g_after = AttackGraph()
    g_after.add_nodes_and_edges(after_nodes, after_edges)
    after_paths = g_after.enumerate_attack_paths()

    comparison = AttackGraph.compare(before_paths, after_paths)
    assert "eliminated" in comparison
    assert "remaining" in comparison
    assert "introduced" in comparison
