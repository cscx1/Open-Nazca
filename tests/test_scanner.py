"""
Integration-level tests for src/scanner.py (AICodeScanner).

All tests use use_snowflake=False and use_llm_analysis=False to avoid
any external service dependencies.  A real temporary file is used so the
ingestion and analysis pipeline run end-to-end.
"""
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from src.scanner import AICodeScanner


# Shared scanner fixture — one instance per test session (slow to initialise)


@pytest.fixture(scope="session")
def scanner():
    s = AICodeScanner(use_snowflake=False, use_llm_analysis=False)
    yield s
    s.close()


# Helpers


def _scan_code(scanner: AICodeScanner, code: str, suffix: str = ".py") -> Dict[str, Any]:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        tmp_path = f.name
    return scanner.scan_file(
        file_path=tmp_path,
        scanned_by="pytest",
        generate_reports=False,
    )


def _finding_types(result: Dict[str, Any]):
    return [f.get("vulnerability_type", "") for f in result.get("findings", [])]


# Basic smoke tests


def test_scanner_initialises(scanner):
    assert scanner is not None
    assert len(scanner.detectors) > 0


def test_scan_returns_dict(scanner):
    result = _scan_code(scanner, "x = 1\n")
    assert isinstance(result, dict)


def test_scan_result_has_required_keys(scanner):
    result = _scan_code(scanner, "x = 1\n")
    for key in ("findings", "scan_id", "file_name", "language"):
        assert key in result, f"Result dict missing key: {key}"


def test_scan_empty_file_returns_error(scanner):
    """Empty files are rejected at ingestion; the scanner returns an error dict."""
    result = _scan_code(scanner, "")
    assert result.get("success") is False or "error" in result, (
        "Empty file should produce an error result"
    )


# Detector coverage


def test_detects_hardcoded_secret(scanner):
    code = 'api_key = "sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"\n'
    result = _scan_code(scanner, code)
    types = _finding_types(result)
    assert any("secret" in t.lower() or "credential" in t.lower() or "hardcoded" in t.lower()
               for t in types), f"Expected a secrets finding; got: {types}"


def test_detects_sql_injection(scanner):
    code = (
        'user_id = request.form.get("id")\n'
        'query = "SELECT * FROM users WHERE id=" + user_id\n'
        'cursor.execute(query)\n'
    )
    result = _scan_code(scanner, code)
    types = _finding_types(result)
    assert any("sql" in t.lower() for t in types), (
        f"Expected an SQL injection finding; got: {types}"
    )


def test_detects_prompt_injection(scanner):
    code = (
        'user_msg = input("Message: ")\n'
        'prompt = f"System: You are helpful. User: {user_msg}"\n'
    )
    result = _scan_code(scanner, code)
    types = _finding_types(result)
    assert any("prompt" in t.lower() or "injection" in t.lower() for t in types), (
        f"Expected a prompt injection finding; got: {types}"
    )


# Verdict layer integration


def test_findings_have_verdict_status(scanner):
    code = 'key = "sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"\n'
    result = _scan_code(scanner, code)
    for finding in result.get("findings", []):
        assert "verdict_status" in finding, (
            f"Finding missing verdict_status: {finding.get('vulnerability_type')}"
        )


def test_verdict_status_values_are_valid(scanner):
    valid = {"Confirmed", "Out-of-scope", "Unverified"}
    code = (
        'user_id = request.args.get("id")\n'
        'cursor.execute("SELECT * FROM t WHERE id=" + user_id)\n'
    )
    result = _scan_code(scanner, code)
    for finding in result.get("findings", []):
        status = finding.get("verdict_status")
        assert status in valid, f"Unexpected verdict_status '{status}'"


# Language support


def test_non_python_file_runs_pattern_detectors(scanner):
    code = 'const key = "sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH";\n'
    result = _scan_code(scanner, code, suffix=".js")
    assert result["language"] == "javascript"
    assert isinstance(result["findings"], list)


# Scan directory


def test_scan_directory(scanner):
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "a.py").write_text(
            'secret = "sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"\n'
        )
        (Path(tmpdir) / "b.py").write_text("x = 1 + 2\n")
        results = scanner.scan_directory(tmpdir, recursive=False)
    assert len(results) == 2
    all_findings = [f for r in results for f in r.get("findings", [])]
    types = [f.get("vulnerability_type", "") for f in all_findings]
    assert any("secret" in t.lower() or "hardcoded" in t.lower() or "credential" in t.lower()
               for t in types)


# Report format option


def test_generate_reports_false_produces_no_report_file(scanner):
    result = _scan_code(scanner, "x = 1\n")
    # When generate_reports=False, report_paths should be empty or absent
    assert result.get("report_paths", {}) == {} or not result.get("report_paths")
