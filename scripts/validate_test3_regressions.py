#!/usr/bin/env python3
"""
Focused regression validator for Test3-era scanner issues.

This script verifies:
1) False positives are suppressed (format string, static IV via base64, XSS misclassification).
2) Missing detections are present (headers, CSRF, rate limiting).
3) Duplicate mass-assignment style findings are deduplicated in scanner output.
4) Remediation behavior matches expected policy (no brittle exec auto-rewrite, better cmdi fix).

Usage (from repo root):
    python scripts/validate_test3_regressions.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import tempfile

from src.scanner import AICodeScanner
from src.analysis.remediator import _fix_command_injection, _fix_code_execution


def _scan_snippet(code: str, name: str):
    with tempfile.TemporaryDirectory(prefix="llmcheck_reg_") as td:
        p = Path(td) / name
        p.write_text(code, encoding="utf-8")
        with AICodeScanner(use_snowflake=False, use_llm_analysis=False) as scanner:
            res = scanner.scan_file(str(p), generate_reports=False)
        if not res.get("success"):
            raise RuntimeError(f"Scan failed for {name}: {res.get('error')}")
        return res.get("findings", [])


def _types(findings):
    return [f.get("vulnerability_type", "") for f in findings]


def _assert(cond: bool, msg: str):
    if not cond:
        raise AssertionError(msg)


def run():
    # 1) False positive guard: safe f-string + base64 should not trigger format/static-IV.
    safe_code = """
import base64

def safe_fmt(username, action):
    return f"User {username} performed {action}"

def encode_payload(raw):
    iv = base64.b64encode(raw.encode()).decode()
    return iv
"""
    findings = _scan_snippet(safe_code, "safe_fp.py")
    types = _types(findings)
    _assert("Format String Injection" not in types, "False positive: safe f-string flagged as format string")
    _assert("Static IV/Nonce" not in types, "False positive: base64 encoding flagged as static IV")

    # 2) Missing hardening detections: headers / CSRF / rate limit should trigger.
    hardening_gap_code = """
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user")
    return jsonify({"ok": True, "user": user})
"""
    findings = _scan_snippet(hardening_gap_code, "hardening_gap.py")
    types = _types(findings)
    _assert("Missing Security Headers" in types, "Missing detection: security headers not flagged")
    _assert("Missing CSRF Protection" in types, "Missing detection: CSRF not flagged")
    _assert("Missing Rate Limiting" in types, "Missing detection: rate limiting not flagged")

    # 3) XSS context awareness: internal SQL helper should not be classified as XSS.
    xss_context_code = """
from flask import Flask, request
app = Flask(__name__)

@app.route("/ping")
def ping():
    return "ok"

def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
"""
    findings = _scan_snippet(xss_context_code, "xss_context.py")
    types = _types(findings)
    _assert("Reflected XSS" not in types, "False positive: internal SQL helper misclassified as XSS")

    # 4) Duplicate suppression: mass-assignment style overlaps should dedupe in scanner.
    dup_code = """
def update(user, data):
    for k, v in data.items():
        setattr(user, k, v)
"""
    findings = _scan_snippet(dup_code, "dup_mass_assignment.py")
    types = _types(findings)
    # At most one of these aliases should survive dedupe for same line context.
    alias_count = sum(1 for t in types if t in {"Mass Assignment", "Attribute Injection"})
    _assert(alias_count <= 1, "Duplicate mass-assignment findings were not deduplicated")

    # 5) Remediator behavior smoke checks.
    cmd_fix = _fix_command_injection("subprocess.check_output(cmd, shell=True)", "")
    _assert(cmd_fix is not None, "Command injection fixer returned no suggestion")
    _assert("shlex.split" in cmd_fix[0] and "shell=False" in cmd_fix[0], "Command fix did not tokenize + disable shell")

    exec_fix = _fix_code_execution("exec(user_code)", "")
    _assert(exec_fix is None, "exec() should require guided remediation, not brittle auto-rewrite")

    print("PASS: All Test3 regression checks succeeded.")


if __name__ == "__main__":
    run()
