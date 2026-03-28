"""
Unit tests for src/analysis/taint_tracker.py.

Covers: source recognition, sink recognition, taint propagation through
assignments and f-strings, clean-code (no-taint) paths, and the public
TaintTracker.analyse() API.
"""
import pytest

from src.analysis.taint_tracker import TaintTracker, TaintNode, TaintEdge, NodeKind


# Fixtures


@pytest.fixture()
def tracker():
    return TaintTracker()


# Source detection


def test_input_call_is_source(tracker):
    code = "x = input('Enter: ')"
    nodes, edges = tracker.analyse("test.py", code)
    sources = [n for n in nodes if n.kind == NodeKind.SOURCE]
    assert sources, "input() should produce a SOURCE node"
    assert any("input" in n.name for n in sources)


def test_request_form_get_is_source(tracker):
    code = "val = request.form.get('user_id')"
    nodes, edges = tracker.analyse("test.py", code)
    sources = [n for n in nodes if n.kind == NodeKind.SOURCE]
    assert sources, "request.form.get should produce a SOURCE node"


def test_sys_argv_is_source(tracker):
    code = "import sys\narg = sys.argv[1]"
    nodes, edges = tracker.analyse("test.py", code)
    sources = [n for n in nodes if n.kind == NodeKind.SOURCE]
    assert sources, "sys.argv subscript should produce a SOURCE node"


# Sink detection


def test_cursor_execute_is_sink(tracker):
    code = "user = input()\ncursor.execute('SELECT * FROM t WHERE id=' + user)"
    nodes, edges = tracker.analyse("test.py", code)
    sinks = [n for n in nodes if n.kind == NodeKind.SINK]
    assert sinks, "cursor.execute should produce a SINK node"


def test_eval_is_sink(tracker):
    code = "data = input()\neval(data)"
    nodes, edges = tracker.analyse("test.py", code)
    sinks = [n for n in nodes if n.kind == NodeKind.SINK]
    assert sinks, "eval() should produce a SINK node"


def test_os_system_is_sink(tracker):
    code = "cmd = input()\nos.system(cmd)"
    nodes, edges = tracker.analyse("test.py", code)
    sinks = [n for n in nodes if n.kind == NodeKind.SINK]
    assert sinks, "os.system should produce a SINK node"


# Taint propagation


def test_assignment_propagates_taint(tracker):
    code = "x = input()\ny = x\ncursor.execute(y)"
    nodes, edges = tracker.analyse("test.py", code)
    assert nodes, "Should have nodes"
    assert edges, "Assignment propagation should produce at least one edge"


def test_fstring_propagates_taint(tracker):
    code = 'user = request.args.get("id")\nquery = f"SELECT * FROM t WHERE id={user}"\ncursor.execute(query)'
    nodes, edges = tracker.analyse("test.py", code)
    sinks = [n for n in nodes if n.kind == NodeKind.SINK]
    assert sinks, "cursor.execute fed by f-string taint should produce a SINK"


def test_concatenation_propagates_taint(tracker):
    code = 'uid = request.form.get("id")\nq = "SELECT * FROM t WHERE id=" + uid\ncursor.execute(q)'
    nodes, edges = tracker.analyse("test.py", code)
    sinks = [n for n in nodes if n.kind == NodeKind.SINK]
    assert sinks, "cursor.execute fed by concatenation should produce a SINK"


# Clean code (no taint)


def test_no_source_no_nodes(tracker):
    code = "x = 42\ny = x + 1\nprint(y)"
    nodes, edges = tracker.analyse("test.py", code)
    sinks = [n for n in nodes if n.kind == NodeKind.SINK]
    assert not sinks, "No user input → no sink nodes expected"


def test_constant_query_no_taint_path(tracker):
    code = 'cursor.execute("SELECT * FROM users WHERE active=1")'
    nodes, edges = tracker.analyse("test.py", code)
    sources = [n for n in nodes if n.kind == NodeKind.SOURCE]
    assert not sources, "Constant-only query should have no source"


# Edge cases


def test_empty_code(tracker):
    nodes, edges = tracker.analyse("empty.py", "")
    assert nodes == []
    assert edges == []


def test_syntax_error_returns_empty(tracker):
    nodes, edges = tracker.analyse("bad.py", "def broken(:\n    pass")
    assert nodes == []
    assert edges == []


def test_node_uids_are_strings(tracker):
    """TaintNode.uid must be a non-empty string (used as graph node key)."""
    code = "a = input()\nb = input()\neval(a)\neval(b)"
    nodes, _ = tracker.analyse("test.py", code)
    assert nodes
    for n in nodes:
        assert isinstance(n.uid, str) and n.uid, (
            f"Node {n} has an invalid uid: {n.uid!r}"
        )


@pytest.mark.parametrize("source_expr,expected_label", [
    ("input('?')", "CLI user input"),
    ("request.form.get('x')", "HTTP form parameter"),
    ("request.args.get('x')", "HTTP query parameter"),
    ("os.environ.get('KEY')", "Environment variable"),
    ("os.getenv('KEY')", "Environment variable"),
])
def test_source_detail_labels(tracker, source_expr, expected_label):
    code = f"val = {source_expr}"
    nodes, _ = tracker.analyse("test.py", code)
    sources = [n for n in nodes if n.kind == NodeKind.SOURCE]
    assert sources, f"{source_expr} should produce a SOURCE"
    details = " ".join(n.detail for n in sources)
    assert expected_label in details, (
        f"Expected detail '{expected_label}' for {source_expr}; got '{details}'"
    )
