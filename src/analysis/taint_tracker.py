"""
AST-based taint tracker for Python source code.

Identifies user-controlled sources, tracks taint propagation through
assignments, concatenation, and function arguments, and locates sinks
where tainted data reaches security-sensitive API calls.

This module analyses user-uploaded code only — the scanner's own
codebase is never a target.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Taxonomy ─────────────────────────────────────────────────────

class NodeKind(str, Enum):
    SOURCE = "source"
    TRANSFORM = "transform"
    SINK = "sink"


@dataclass
class TaintNode:
    """A single location in the taint graph."""
    kind: NodeKind
    name: str                    # e.g. variable name, function call
    file: str
    line: int
    col: int = 0
    ast_type: str = ""           # e.g. "Assign", "Call"
    detail: str = ""             # human-readable context

    @property
    def uid(self) -> str:
        return f"{self.file}:{self.line}:{self.col}:{self.name}"


@dataclass
class TaintEdge:
    """Directed edge in the taint graph (from → to)."""
    src: TaintNode
    dst: TaintNode
    transform_type: str = ""     # "assignment", "concatenation", "arg_pass", …
    detail: str = ""


# ── Known source / sink patterns ────────────────────────────────

# Source patterns: functions / attributes that produce user-controlled data.
SOURCE_CALLS: Dict[str, str] = {
    "input":                   "CLI user input",
    "request.form.get":        "HTTP form parameter",
    "request.args.get":        "HTTP query parameter",
    "request.json.get":        "HTTP JSON body field",
    "request.get_json":        "HTTP JSON body",
    "request.data":            "HTTP raw body",
    "request.form":            "HTTP form data",
    "request.args":            "HTTP query string",
    "request.json":            "HTTP JSON body",
    "request.cookies.get":     "HTTP cookie",
    "request.headers.get":     "HTTP header",
    "sys.argv":                "CLI argument vector",
    "os.environ.get":          "Environment variable",
    "os.getenv":               "Environment variable",
}

# Attribute-level access patterns resolved during AST walk.
SOURCE_SUBSCRIPTS: Set[str] = {
    "request.form",
    "request.args",
    "request.json",
    "request.cookies",
    "request.headers",
    "params",
    "sys.argv",
}

# Sink patterns: module.function → vulnerability class.
# Kept in sink_classifier.py for single source of truth; this set is for
# quick "is this a sink?" checks during the AST walk.
_QUICK_SINK_NAMES: Set[str] = {
    # SQL
    "cursor.execute", "connection.execute", "db.execute",
    "sqlite3.connect", "engine.execute",
    # OS / Shell
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "subprocess.Popen", "subprocess.check_output",
    # Code execution
    "eval", "exec", "compile",
    # File system
    "open", "os.remove", "os.unlink", "shutil.rmtree",
    "send_file", "flask.send_file", "send_from_directory",
    # Network
    "requests.get", "requests.post", "requests.put",
    "urllib.request.urlopen", "httpx.get", "httpx.post",
    # Redirect
    "redirect", "flask.redirect",
    # LLM / AI
    "openai.Completion.create", "openai.ChatCompletion.create",
    "openai.chat.completions.create",
    "anthropic.Anthropic", "anthropic.completions.create",
    # Template / XSS
    "render_template_string", "Markup", "jinja2.Template",
}


# ── Helpers ──────────────────────────────────────────────────────

def _dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted name from an AST node (e.g. ``os.system``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _call_name(node: ast.Call) -> str:
    """Return dotted name of the callee."""
    return _dotted_name(node.func)


def _is_source_call(call_name: str) -> bool:
    """Check if a call is a known source of user-controlled data."""
    if call_name in SOURCE_CALLS:
        return True
    # Match partial suffixes (e.g. self.request.form.get)
    for src in SOURCE_CALLS:
        if call_name.endswith(src):
            return True
    return False


def _is_source_subscript(name: str) -> bool:
    for src in SOURCE_SUBSCRIPTS:
        if name.endswith(src) or name == src:
            return True
    return False


def _is_sink_call(call_name: str) -> bool:
    if call_name in _QUICK_SINK_NAMES:
        return True
    for sink in _QUICK_SINK_NAMES:
        if call_name.endswith(sink):
            return True
    return False


# ── AST Visitor ──────────────────────────────────────────────────

class _TaintVisitor(ast.NodeVisitor):
    """Walk a Python AST and build taint nodes + edges."""

    def __init__(self, file_name: str):
        self.file = file_name
        self.nodes: List[TaintNode] = []
        self.edges: List[TaintEdge] = []
        # tainted_vars: var_name → TaintNode that produced the taint
        self.tainted_vars: Dict[str, TaintNode] = {}
        # Track function parameter names that are user-controlled
        self._func_params: Set[str] = set()
        self._current_func: Optional[str] = None

    # ── function definitions ──────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self._current_func
        prev_params = self._func_params.copy()
        self._current_func = node.name
        # Mark all parameters as potential taint sources
        # (conservative: we treat any external call as potentially tainted)
        self._func_params = set()
        for arg in node.args.args:
            if arg.arg != "self":
                self._func_params.add(arg.arg)
                src_node = TaintNode(
                    kind=NodeKind.SOURCE,
                    name=arg.arg,
                    file=self.file,
                    line=node.lineno,
                    col=arg.col_offset,
                    ast_type="FunctionArg",
                    detail=f"Parameter '{arg.arg}' of function '{node.name}' "
                           f"(treated as untrusted input)",
                )
                self.nodes.append(src_node)
                self.tainted_vars[arg.arg] = src_node
        self.generic_visit(node)
        self._current_func = prev_func
        self._func_params = prev_params

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── assignments ───────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign):
        rhs_taint = self._expr_taint(node.value)
        if rhs_taint is not None:
            for target in node.targets:
                names = self._target_names(target)
                for name in names:
                    xform = TaintNode(
                        kind=NodeKind.TRANSFORM,
                        name=name,
                        file=self.file,
                        line=node.lineno,
                        col=node.col_offset,
                        ast_type="Assign",
                        detail=f"Variable '{name}' receives tainted data",
                    )
                    self.nodes.append(xform)
                    self.edges.append(TaintEdge(
                        src=rhs_taint, dst=xform,
                        transform_type="assignment",
                        detail=f"Taint flows into '{name}' via assignment",
                    ))
                    self.tainted_vars[name] = xform
        self.generic_visit(node)

    # ── calls ─────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call):
        cname = _call_name(node)

        # 1) Source detection
        if _is_source_call(cname):
            src_node = TaintNode(
                kind=NodeKind.SOURCE,
                name=cname,
                file=self.file,
                line=node.lineno,
                col=node.col_offset,
                ast_type="Call",
                detail=SOURCE_CALLS.get(cname, "User-controlled source"),
            )
            self.nodes.append(src_node)
            # If this call is the RHS of an assignment the Assign visitor
            # will link it; store in a transient attribute for that purpose.
            node._taint_node = src_node  # type: ignore[attr-defined]

        # 2) Sink detection: check if any tainted arg flows into a sink
        if _is_sink_call(cname):
            for arg in node.args:
                taint = self._expr_taint(arg)
                if taint is not None:
                    sink_node = TaintNode(
                        kind=NodeKind.SINK,
                        name=cname,
                        file=self.file,
                        line=node.lineno,
                        col=node.col_offset,
                        ast_type="Call",
                        detail=f"Tainted data reaches {cname}()",
                    )
                    self.nodes.append(sink_node)
                    self.edges.append(TaintEdge(
                        src=taint, dst=sink_node,
                        transform_type="arg_pass",
                        detail=f"Tainted data passed as argument to {cname}()",
                    ))
            for kw in node.keywords:
                taint = self._expr_taint(kw.value)
                if taint is not None:
                    sink_node = TaintNode(
                        kind=NodeKind.SINK,
                        name=cname,
                        file=self.file,
                        line=node.lineno,
                        col=node.col_offset,
                        ast_type="Call",
                        detail=f"Tainted data reaches {cname}() via keyword '{kw.arg}'",
                    )
                    self.nodes.append(sink_node)
                    self.edges.append(TaintEdge(
                        src=taint, dst=sink_node,
                        transform_type="kwarg_pass",
                        detail=f"Tainted data passed as '{kw.arg}=' to {cname}()",
                    ))

        self.generic_visit(node)

    # ── expression taint helpers ──────────────────────────────

    def _expr_taint(self, node: ast.AST) -> Optional[TaintNode]:
        """Return the TaintNode that taints *node*, or None."""
        # Direct name reference
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id)

        # Source call
        if isinstance(node, ast.Call):
            cname = _call_name(node)
            if _is_source_call(cname):
                src_node = TaintNode(
                    kind=NodeKind.SOURCE,
                    name=cname,
                    file=self.file,
                    line=node.lineno,
                    col=node.col_offset,
                    ast_type="Call",
                    detail=SOURCE_CALLS.get(cname, "User-controlled source"),
                )
                self.nodes.append(src_node)
                return src_node
            # If any arg is tainted, the return value is tainted
            for arg in node.args:
                t = self._expr_taint(arg)
                if t is not None:
                    return t
            for kw in node.keywords:
                t = self._expr_taint(kw.value)
                if t is not None:
                    return t

        # f-string: any tainted value inside makes the whole string tainted
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    t = self._expr_taint(val.value)
                    if t is not None:
                        xf = TaintNode(
                            kind=NodeKind.TRANSFORM,
                            name="f-string",
                            file=self.file,
                            line=node.lineno,
                            col=node.col_offset,
                            ast_type="JoinedStr",
                            detail="Tainted value interpolated into f-string",
                        )
                        self.nodes.append(xf)
                        self.edges.append(TaintEdge(
                            src=t, dst=xf,
                            transform_type="concatenation",
                            detail="F-string interpolation",
                        ))
                        return xf

        # String concatenation via BinOp (+)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            lt = self._expr_taint(node.left)
            rt = self._expr_taint(node.right)
            t = lt or rt
            if t is not None:
                xf = TaintNode(
                    kind=NodeKind.TRANSFORM,
                    name="concat",
                    file=self.file,
                    line=node.lineno,
                    col=node.col_offset,
                    ast_type="BinOp",
                    detail="Tainted value concatenated via +",
                )
                self.nodes.append(xf)
                self.edges.append(TaintEdge(
                    src=t, dst=xf,
                    transform_type="concatenation",
                    detail="String concatenation (+)",
                ))
                return xf

        # .format() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                for arg in node.args:
                    t = self._expr_taint(arg)
                    if t is not None:
                        xf = TaintNode(
                            kind=NodeKind.TRANSFORM,
                            name=".format()",
                            file=self.file,
                            line=node.lineno,
                            col=node.col_offset,
                            ast_type="Call",
                            detail="Tainted value passed to .format()",
                        )
                        self.nodes.append(xf)
                        self.edges.append(TaintEdge(
                            src=t, dst=xf,
                            transform_type="concatenation",
                            detail=".format() interpolation",
                        ))
                        return xf

        # %-formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            rt = self._expr_taint(node.right)
            if rt is not None:
                xf = TaintNode(
                    kind=NodeKind.TRANSFORM,
                    name="%-format",
                    file=self.file,
                    line=node.lineno,
                    col=node.col_offset,
                    ast_type="BinOp",
                    detail="Tainted value used in %-formatting",
                )
                self.nodes.append(xf)
                self.edges.append(TaintEdge(
                    src=rt, dst=xf,
                    transform_type="concatenation",
                    detail="%-format string interpolation",
                ))
                return xf

        # Subscript: request.form["key"], sys.argv[1], etc.
        if isinstance(node, ast.Subscript):
            base_name = _dotted_name(node.value)
            if _is_source_subscript(base_name):
                src_node = TaintNode(
                    kind=NodeKind.SOURCE,
                    name=base_name,
                    file=self.file,
                    line=node.lineno,
                    col=node.col_offset,
                    ast_type="Subscript",
                    detail=f"User-controlled data from {base_name}[…]",
                )
                self.nodes.append(src_node)
                return src_node

        # Dict literal: if any value is tainted, the dict is tainted
        if isinstance(node, ast.Dict):
            for val in node.values:
                if val is not None:
                    t = self._expr_taint(val)
                    if t is not None:
                        return t

        # List literal: if any element is tainted, the list is tainted
        if isinstance(node, ast.List):
            for elt in node.elts:
                t = self._expr_taint(elt)
                if t is not None:
                    return t

        # Attribute access on tainted object
        if isinstance(node, ast.Attribute):
            t = self._expr_taint(node.value)
            return t

        return None

    @staticmethod
    def _target_names(target: ast.AST) -> List[str]:
        """Extract variable names from an assignment target."""
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Tuple):
            names: List[str] = []
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
            return names
        return []


# ── Public API ───────────────────────────────────────────────────

class TaintTracker:
    """
    Run AST-based taint analysis on a Python source string.

    Usage::

        tracker = TaintTracker()
        nodes, edges = tracker.analyse("example.py", source_code)
    """

    def analyse(
        self, file_name: str, source: str
    ) -> Tuple[List[TaintNode], List[TaintEdge]]:
        """
        Parse *source* and return (nodes, edges) representing taint flow.

        Only Python is supported via ``ast``.  For unsupported languages the
        method returns empty lists (no crash) so callers can fall back to
        pattern-based detection.
        """
        try:
            tree = ast.parse(source, filename=file_name)
        except SyntaxError as exc:
            logger.warning("Cannot parse %s: %s", file_name, exc)
            return [], []

        visitor = _TaintVisitor(file_name)
        visitor.visit(tree)

        logger.info(
            "Taint analysis for %s: %d nodes, %d edges",
            file_name, len(visitor.nodes), len(visitor.edges),
        )
        return visitor.nodes, visitor.edges
