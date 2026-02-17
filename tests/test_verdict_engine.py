"""
Standalone tests for the Verdict Engine.
Mocks various Finding scenarios: naked regex match vs confirmed taint path in a web app.
"""

import sys
import tempfile
from pathlib import Path
from typing import Optional

# Allow importing from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detectors import Finding
from src.verdict import VerdictEngine, VerdictStatus


def _mock_finding(
    vulnerability_type: str = "SQL Injection",
    line_number: int = 10,
    reachability_status: Optional[str] = None,
    attack_path: Optional[dict] = None,
    code_snippet: str = "cursor.execute(query)",
) -> Finding:
    return Finding(
        detector_name="TestDetector",
        vulnerability_type=vulnerability_type,
        severity="HIGH",
        line_number=line_number,
        code_snippet=code_snippet,
        description="Test finding",
        confidence=0.9,
        reachability_status=reachability_status,
        reachability_reasoning=None,
        attack_path=attack_path,
        sink_api=None,
    )


def test_pattern_only_fallback():
    """Naked regex match: no attack_path, no reachability → Unverified."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "x = 1\ncursor.execute('SELECT * FROM t')\ny = 2"
    findings = [
        _mock_finding(
            vulnerability_type="SQL Injection",
            line_number=2,
            reachability_status=None,
            attack_path=None,
        )
    ]
    result = engine.run(findings, "/app/main.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.UNVERIFIED
    assert "Static match only" in result[0].verdict.reason


def test_taint_reachability_confirmed():
    """Confirmed Reachable → Confirmed verdict."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "def foo(): pass\nbad_sink(request.args.get('x'))"
    findings = [
        _mock_finding(
            vulnerability_type="Command Injection",
            line_number=2,
            reachability_status="Confirmed Reachable",
            attack_path={"source": {"line": 2}, "sink": {"line": 2}},
        )
    ]
    result = engine.run(findings, "/app/views.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.CONFIRMED
    assert "attack path" in result[0].verdict.reason.lower()


def test_environment_neutralizer():
    """File under /examples/ with no Confirmed Reachable → Unverified (no later rule overrides)."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "cursor.execute('SELECT ' + user_input)"
    findings = [_mock_finding(line_number=1, reachability_status=None, attack_path=None)]
    result = engine.run(findings, "/project/examples/demo.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.UNVERIFIED
    # Reason can be from Environment ("non-production") or Pattern fallback ("Static match")
    assert "non-production" in result[0].verdict.reason.lower() or "static match" in result[0].verdict.reason.lower()


def test_sql_sanitizer_out_of_scope():
    """SQL Injection with parameterized markers on same line → Out-of-scope."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))"
    findings = [
        _mock_finding(
            vulnerability_type="SQL Injection",
            line_number=1,
            code_snippet="cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))",
        )
    ]
    result = engine.run(findings, "/app/db.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.OUT_OF_SCOPE
    assert "parameterized" in result[0].verdict.reason.lower()


def test_xss_out_of_scope_no_web():
    """XSS in file with no web framework and no routing → Out-of-scope."""
    with tempfile.TemporaryDirectory() as tmp:
        # Empty project root: no requirements.txt, no urls.py → is_web_app False
        engine = VerdictEngine(project_root=tmp)
        code = "print(user_input)"
        findings = [
            _mock_finding(
                vulnerability_type="XSS / Template Injection",
                line_number=1,
                reachability_status=None,
            )
        ]
        result = engine.run(findings, f"{tmp}/utils/helper.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.OUT_OF_SCOPE
    assert "No web framework" in result[0].verdict.reason or "routing" in result[0].verdict.reason.lower()


def test_finding_with_verdict_to_dict():
    """FindingWithVerdict.to_dict() includes verdict_status and verdict_reason."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    findings = [_mock_finding(line_number=1)]
    result = engine.run(findings, "/app/script.py", "x = 1")
    d = result[0].to_dict()
    assert "verdict_status" in d
    assert "verdict_reason" in d
    assert d["verdict_status"] in (VerdictStatus.CONFIRMED, VerdictStatus.UNVERIFIED, VerdictStatus.OUT_OF_SCOPE)


def test_unverified_does_not_override_confirmed():
    """File in /examples/ but Confirmed Reachable → Confirmed (no false negative)."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "bad_sink(request.args.get('x'))"
    findings = [
        _mock_finding(
            line_number=1,
            reachability_status="Confirmed Reachable",
            attack_path={"sink": {"line": 1}},
        )
        ]
    result = engine.run(findings, "/project/examples/demo.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.CONFIRMED


def test_sql_parameterized_overrides_taint():
    """Parameterized SQL + Confirmed Reachable → Out-of-scope (SQL rule before Taint)."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))"
    findings = [
        _mock_finding(
            vulnerability_type="SQL Injection",
            line_number=1,
            reachability_status="Confirmed Reachable",
            attack_path={"sink": {"line": 1}},
        )
    ]
    result = engine.run(findings, "/app/db.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.OUT_OF_SCOPE
    assert "parameterized" in result[0].verdict.reason.lower()


def test_input_validation_out_of_scope():
    """Same-line sanitize/allowlist → Out-of-scope."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "x = sanitize(user_input); render(x)"
    findings = [_mock_finding(line_number=1, vulnerability_type="XSS / Template Injection")]
    result = engine.run(findings, "/app/views.py", code)
    assert len(result) == 1
    assert result[0].verdict.status == VerdictStatus.OUT_OF_SCOPE
    assert "validation" in result[0].verdict.reason.lower() or "sanitization" in result[0].verdict.reason.lower()


def test_xss_confirmed_only_with_output_context():
    """XSS Confirmed only when reachable + entry + HTML/JS output context."""
    engine = VerdictEngine(project_root=str(Path(__file__).resolve().parent.parent))
    code = "from flask import Flask, render_template\napp = Flask(__name__)\n@app.route('/')\ndef index():\n    return render_template('page.html', data=request.args.get('q'))"
    findings = [
        _mock_finding(
            vulnerability_type="XSS / Template Injection",
            line_number=5,
            reachability_status="Confirmed Reachable",
            attack_path={"sink": {"line": 5}},
        )
    ]
    result = engine.run(findings, "/app/views.py", code)
    assert len(result) == 1
    # Should be Confirmed: entry point + render_template (output context)
    assert result[0].verdict.status == VerdictStatus.CONFIRMED


if __name__ == "__main__":
    test_pattern_only_fallback()
    print("  OK pattern_only_fallback")
    test_taint_reachability_confirmed()
    print("  OK taint_reachability_confirmed")
    test_environment_neutralizer()
    print("  OK environment_neutralizer")
    test_sql_sanitizer_out_of_scope()
    print("  OK sql_sanitizer_out_of_scope")
    test_xss_out_of_scope_no_web()
    print("  OK xss_out_of_scope_no_web")
    test_finding_with_verdict_to_dict()
    print("  OK finding_with_verdict_to_dict")
    test_unverified_does_not_override_confirmed()
    print("  OK unverified_does_not_override_confirmed")
    test_sql_parameterized_overrides_taint()
    print("  OK sql_parameterized_overrides_taint")
    test_input_validation_out_of_scope()
    print("  OK input_validation_out_of_scope")
    test_xss_confirmed_only_with_output_context()
    print("  OK xss_confirmed_only_with_output_context")
    print("All verdict engine tests passed.")
