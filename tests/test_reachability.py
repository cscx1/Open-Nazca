"""
Unit tests for src/analysis/reachability.py.

Validates that the ReachabilityVerifier correctly classifies attack paths
as Confirmed Reachable, Reachability Eliminated, or Unverifiable.
"""
import pytest

from src.analysis.taint_tracker import TaintTracker
from src.analysis.attack_graph import AttackGraph
from src.analysis.reachability import ReachabilityVerifier, ReachabilityStatus


def _verify(code: str, file_name: str = "test.py"):
    """Run the full taint → graph → reachability pipeline on a code snippet."""
    tracker = TaintTracker()
    nodes, edges = tracker.analyse(file_name, code)
    if not nodes:
        return []
    graph = AttackGraph()
    graph.add_nodes_and_edges(nodes, edges)
    paths = graph.enumerate_attack_paths()
    if not paths:
        return []
    verifier = ReachabilityVerifier()
    return verifier.verify_paths(paths, code, file_name)


# Confirmed Reachable


def test_direct_taint_is_confirmed():
    code = "x = input()\ncursor.execute(x)"
    results = _verify(code)
    assert results
    statuses = {r.status for r in results}
    assert ReachabilityStatus.CONFIRMED_REACHABLE in statuses, (
        f"Expected CONFIRMED_REACHABLE; got {statuses}"
    )


def test_fstring_taint_is_confirmed():
    code = 'uid = request.args.get("id")\nq = f"SELECT * WHERE id={uid}"\ncursor.execute(q)'
    results = _verify(code)
    assert results
    statuses = {r.status for r in results}
    assert ReachabilityStatus.CONFIRMED_REACHABLE in statuses


# Reachability Eliminated


def test_parameterized_sql_is_eliminated():
    code = (
        'uid = request.args.get("id")\n'
        'cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))\n'
    )
    results = _verify(code)
    if results:
        statuses = {r.status for r in results}
        # Parameterized query should not be CONFIRMED_REACHABLE
        assert ReachabilityStatus.CONFIRMED_REACHABLE not in statuses, (
            "Parameterized SQL should not be Confirmed Reachable"
        )


def test_html_escape_is_eliminated():
    code = (
        "import html\n"
        'user = request.args.get("name")\n'
        'safe = html.escape(user)\n'
        'render_template_string(safe)\n'
    )
    results = _verify(code)
    if results:
        statuses = {r.status for r in results}
        assert ReachabilityStatus.CONFIRMED_REACHABLE not in statuses, (
            "html.escape should eliminate XSS reachability"
        )


# Result structure


def test_result_has_to_dict():
    code = "x = input()\ncursor.execute(x)"
    results = _verify(code)
    assert results
    for r in results:
        d = r.to_dict()
        assert "status" in d
        assert "reasoning" in d
        assert "sanitizers_found" in d


def test_reasoning_is_non_empty():
    code = "x = input()\ncursor.execute(x)"
    results = _verify(code)
    for r in results:
        assert r.reasoning, "Every result should have a non-empty reasoning string"


# Edge cases


def test_no_paths_returns_empty_list():
    code = "x = 1\nprint(x)"
    results = _verify(code)
    assert results == []
