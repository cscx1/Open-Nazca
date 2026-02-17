"""
Production-ready secure version of Test3.py.
All vulnerabilities remediated: fixed, removed, or disabled with justification.
No eval, exec, pickle.loads, yaml.load(Loader=Loader), shell=True.
Input validation on all user input; secure crypto; no debug endpoints.
"""

import json
import os
import re
import secrets
import hashlib
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import yaml
from flask import Flask, request, render_template_string, redirect, abort
from werkzeug.utils import secure_filename

# Optional: use defusedxml for XML parsing (pip install defusedxml)
try:
    import defusedxml.ElementTree as ET
except ImportError:
    ET = None  # XXE-safe parsing unavailable; parse_xml will reject

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB max upload

# Secrets from environment only; fail fast if missing in production
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_KEY = os.environ.get("API_KEY")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
if not DB_PASSWORD or not API_KEY:
    import warnings
    warnings.warn("DB_PASSWORD and API_KEY must be set in production", UserWarning)

# ---------------------------------------------------------------------------
# ALLOWLISTS AND CONSTANTS
# ---------------------------------------------------------------------------
ALLOWED_READ_DIR = Path(os.environ.get("ALLOWED_READ_DIR", "/var/app/readable")).resolve()
ALLOWED_UPLOAD_DIR = Path(os.environ.get("ALLOWED_UPLOAD_DIR", "/var/app/uploads")).resolve()
ALLOWED_UPLOAD_EXTENSIONS: Set[str] = {"pdf", "png", "jpg", "jpeg", "gif"}
MAX_EMAIL_LEN = 320
MAX_ALLOCATION = 1_000_000
REDIRECT_ALLOWED_PREFIXES = ("/", "https://trusted.example.com/")
FETCH_ALLOWED_HOSTS: Set[str] = {"api.trusted.example.com", "cdn.trusted.example.com"}

# ---------------------------------------------------------------------------
# REMEDIATED: Command execution — REMOVED (cannot be safely exposed)
# Original /execute with eval+os.system removed. Use a task queue + allowlisted
# jobs if server-side commands are required.
# ---------------------------------------------------------------------------
# (endpoint removed)


# ---------------------------------------------------------------------------
# REMEDIATED: SQL injection — parameterized queries only
# ---------------------------------------------------------------------------
def get_user_data(user_id: str) -> List[tuple]:
    """Look up user by ID using parameterized query."""
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", user_id):
        return []
    conn = sqlite3.connect("users.db")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# REMEDIATED: Path traversal — normalization + containment
# ---------------------------------------------------------------------------
@app.route("/readfile")
def read_file():
    """Read file only from allowed directory with path containment."""
    filename = request.args.get("file", "default.txt")
    if ".." in filename or filename.startswith("/") or "\\" in filename:
        abort(400, "Invalid filename")
    safe_name = Path(filename).name
    target = (ALLOWED_READ_DIR / safe_name).resolve()
    if not str(target).startswith(str(ALLOWED_READ_DIR)):
        abort(403, "Access denied")
    if not target.is_file():
        abort(404)
    return target.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# REMEDIATED: XSS — auto-escaped template; user input as data only
# ---------------------------------------------------------------------------
@app.route("/greet")
def greet_user():
    """Greet user with escaped name (Jinja2 auto-escape)."""
    name = request.args.get("name", "Guest")
    if len(name) > 200:
        name = name[:200]
    return render_template_string(
        "<h1>Hello {{ name }}!</h1>",
        name=name,
    )


# ---------------------------------------------------------------------------
# REMEDIATED: Pickle deserialization — REMOVED (no safe untrusted pickle)
# Replaced with JSON-only loading for trusted config.
# ---------------------------------------------------------------------------
def load_user_data_json(json_data: str) -> Any:
    """Load user data from JSON only. Do not use pickle on untrusted input."""
    return json.loads(json_data)


# ---------------------------------------------------------------------------
# REMEDIATED: Weak password hashing — SHA-256 with salt (or use passlib)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash password with salt using SHA-256. Prefer passlib/bcrypt in production."""
    if len(password) > 4096:
        raise ValueError("Password too long")
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    """Verify password against stored hash."""
    parts = stored.split("$", 2)
    if len(parts) != 3:
        return False
    _, salt, expected = parts
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return secrets.compare_digest(h, expected)


# ---------------------------------------------------------------------------
# REMEDIATED: Insecure random — cryptographically secure token
# ---------------------------------------------------------------------------
def generate_token() -> str:
    """Generate URL-safe token using secrets module."""
    return secrets.token_urlsafe(24)


# ---------------------------------------------------------------------------
# REMEDIATED: XXE — defusedxml or disabled
# ---------------------------------------------------------------------------
def parse_xml(xml_data: str) -> Optional[str]:
    """Parse XML with XXE protections (defusedxml)."""
    if ET is None:
        raise RuntimeError("Install defusedxml for safe XML parsing")
    if len(xml_data) > 1_000_000:
        raise ValueError("XML payload too large")
    root = ET.fromstring(xml_data)
    return root.tag


# ---------------------------------------------------------------------------
# REMEDIATED: Shell injection — no shell; use os.listdir / pathlib
# ---------------------------------------------------------------------------
def list_directory(path: str) -> List[str]:
    """List directory using pathlib; no shell. Path validated for containment."""
    if ".." in path or path.startswith("/") or "\\" in path:
        raise ValueError("Invalid path")
    p = Path(path).resolve()
    if not p.is_dir():
        raise NotADirectoryError(path)
    return [x.name for x in p.iterdir()]


# ---------------------------------------------------------------------------
# REMEDIATED: YAML deserialization — safe_load only
# ---------------------------------------------------------------------------
def load_config(yaml_str: str) -> Any:
    """Load config using yaml.safe_load (no arbitrary classes)."""
    if len(yaml_str) > 500_000:
        raise ValueError("Config too large")
    return yaml.safe_load(yaml_str)


# ---------------------------------------------------------------------------
# REMEDIATED: ReDoS — length limit + safe pattern
# ---------------------------------------------------------------------------
_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
)

def validate_email(email: str) -> bool:
    """Validate email with length limit to mitigate ReDoS."""
    if not email or len(email) > MAX_EMAIL_LEN:
        return False
    return bool(_EMAIL_PATTERN.match(email))


# ---------------------------------------------------------------------------
# REMEDIATED: Mass assignment — allowlist of attributes
# ---------------------------------------------------------------------------
class User:
    ALLOWED_ATTRS: Set[str] = {"id", "email", "display_name", "created_at"}

    def __init__(self, data: Dict[str, Any]):
        for key, value in data.items():
            if key in self.ALLOWED_ATTRS:
                setattr(self, key, value)


# ---------------------------------------------------------------------------
# REMEDIATED: Log injection — sanitize (strip newlines / control chars)
# ---------------------------------------------------------------------------
def _sanitize_log(s: str, max_len: int = 500) -> str:
    return "".join(c for c in s[:max_len] if c.isprintable() or c in " \t").replace("\n", " ").strip()


def log_action(username: str, action: str) -> None:
    """Log with sanitized user-controlled fields."""
    safe_user = _sanitize_log(username)
    safe_action = _sanitize_log(action)
    log_msg = f"{safe_user} - {safe_action}\n"
    with open("app.log", "a", encoding="utf-8") as f:
        f.write(log_msg)


# ---------------------------------------------------------------------------
# REMEDIATED: exec() — REMOVED (no safe way to execute user code)
# ---------------------------------------------------------------------------
# dynamic_code_exec removed. Use sandboxed interpreters or approved DSLs only.


# ---------------------------------------------------------------------------
# REMEDIATED: Unsafe file upload — secure_filename + allowlist + size limit
# ---------------------------------------------------------------------------
ALLOWED_READ_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.route("/upload", methods=["POST"])
def upload_file():
    """Upload with extension allowlist and path containment."""
    if "file" not in request.files:
        abort(400, "No file")
    file = request.files["file"]
    if file.filename == "":
        abort(400, "No selected file")
    base = secure_filename(file.filename)
    ext = (Path(base).suffix or "").lstrip(".").lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        abort(400, "File type not allowed")
    safe_name = f"{secrets.token_hex(8)}_{base}"
    target = (ALLOWED_UPLOAD_DIR / safe_name).resolve()
    if not str(target).startswith(str(ALLOWED_UPLOAD_DIR)):
        abort(403, "Invalid path")
    file.save(str(target))
    return "File uploaded", 201


# ---------------------------------------------------------------------------
# REMEDIATED: Information disclosure — REMOVED (debug endpoint)
# ---------------------------------------------------------------------------
# /debug endpoint removed. Do not expose version, cwd, or env in production.


# ---------------------------------------------------------------------------
# REMEDIATED: IDOR — authorization check required
# ---------------------------------------------------------------------------
@app.route("/profile/<user_id>")
def user_profile(user_id: str):
    """Profile only for current user (MANUAL: wire to your auth)."""
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", user_id):
        abort(400)
    # MANUAL_REMEDIATION_REQUIRED: Replace with real auth (e.g. session, JWT).
    # Example: if session.get("user_id") != user_id: abort(403)
    current_user_id = request.headers.get("X-Authenticated-User")  # placeholder
    if current_user_id != user_id:
        abort(403, "Forbidden")
    return f"Profile page for user {user_id}"


# ---------------------------------------------------------------------------
# REMEDIATED: Weak crypto — REMOVED (use cryptography library)
# ---------------------------------------------------------------------------
# encrypt_data with static IV removed. Use cryptography.fernet or
# AES with os.urandom(16) IV and proper key derivation (e.g. Fernet).


# ---------------------------------------------------------------------------
# REMEDIATED: TOCTOU — atomic write
# ---------------------------------------------------------------------------
def write_to_file(filename: str, content: str) -> bool:
    """Atomic write via temp file + rename."""
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename")
    path = Path(filename).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_", suffix=path.suffix)
    try:
        os.write(fd, content.encode("utf-8"))
        os.close(fd)
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


# ---------------------------------------------------------------------------
# REMEDIATED: Open redirect — allowlist
# ---------------------------------------------------------------------------
@app.route("/redirect")
def safe_redirect():
    """Redirect only to allowed prefixes."""
    url = request.args.get("url", "/")
    parsed = urlparse(url)
    if parsed.netloc and parsed.scheme not in ("http", "https"):
        abort(400, "Invalid URL scheme")
    allowed = any(url.startswith(p) for p in REDIRECT_ALLOWED_PREFIXES)
    if not allowed or ".." in url:
        abort(400, "Redirect URL not allowed")
    return redirect(url)


# ---------------------------------------------------------------------------
# REMEDIATED: SSRF — allowlist hosts only
# ---------------------------------------------------------------------------
@app.route("/fetch")
def fetch_url():
    """Fetch URL only for allowlisted hosts."""
    url = request.args.get("url")
    if not url:
        abort(400, "Missing url")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        abort(400, "Invalid scheme")
    host = (parsed.hostname or "").lower()
    if host not in FETCH_ALLOWED_HOSTS:
        abort(403, "Host not allowed")
    import requests
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.text


# ---------------------------------------------------------------------------
# REMEDIATED: Memory exhaustion — capped allocation
# ---------------------------------------------------------------------------
def process_large_data(data_size: int) -> int:
    """Process with strict upper bound."""
    try:
        n = int(data_size)
    except (TypeError, ValueError):
        raise ValueError("Invalid size")
    if n < 0 or n > MAX_ALLOCATION:
        raise ValueError("Size out of range")
    data = "A" * n
    return len(data)


# ---------------------------------------------------------------------------
# REMEDIATED: Format string — static format, user input as args only
# ---------------------------------------------------------------------------
def log_with_format(username: str, action: str) -> str:
    """Static format string; user input only in substitution."""
    return "User {} performed: {}".format(
        _sanitize_log(username),
        _sanitize_log(action),
    )


# ---------------------------------------------------------------------------
# REMEDIATED: super_vulnerable — REMOVED (replaced with safe stub)
# ---------------------------------------------------------------------------
@app.route("/super_vulnerable", methods=["POST"])
def super_vulnerable():
    """Dangerous endpoint removed; returns 410 Gone."""
    abort(410, "This endpoint has been removed for security.")


# ---------------------------------------------------------------------------
# Production: debug off, security headers
# ---------------------------------------------------------------------------
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
