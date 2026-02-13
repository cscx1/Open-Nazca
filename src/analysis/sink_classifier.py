"""
Library-accurate sink classifier.

Classifies vulnerabilities based on the *API actually reached* (the sink),
not on string-pattern heuristics.  This is the single source of truth for
mapping ``module.function`` → vulnerability type.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class SinkInfo:
    """Metadata describing a security-sensitive sink."""
    api_name: str               # e.g. "sqlite3.Cursor.execute"
    vulnerability_type: str     # e.g. "SQL Injection"
    cwe_id: str                 # e.g. "CWE-89"
    owasp_category: str         # e.g. "A03:2021 – Injection"
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW
    description: str


# ── Sink registry ────────────────────────────────────────────────
# Key: normalised dotted call name (lowercase).
# Partial suffix matching is used at lookup time so that
# ``self.cursor.execute`` matches ``cursor.execute``.

_SINK_REGISTRY: Dict[str, SinkInfo] = {}


def _reg(api: str, vuln: str, cwe: str, owasp: str, sev: str, desc: str):
    _SINK_REGISTRY[api.lower()] = SinkInfo(
        api_name=api,
        vulnerability_type=vuln,
        cwe_id=cwe,
        owasp_category=owasp,
        severity=sev,
        description=desc,
    )


# ── SQL Injection ────────────────────────────────────────────────
_reg("cursor.execute",            "SQL Injection", "CWE-89",  "A03:2021", "CRITICAL",
     "Tainted data reaches raw SQL execution via cursor.execute()")
_reg("connection.execute",        "SQL Injection", "CWE-89",  "A03:2021", "CRITICAL",
     "Tainted data reaches raw SQL execution via connection.execute()")
_reg("db.execute",                "SQL Injection", "CWE-89",  "A03:2021", "CRITICAL",
     "Tainted data reaches raw SQL execution via db.execute()")
_reg("engine.execute",            "SQL Injection", "CWE-89",  "A03:2021", "CRITICAL",
     "Tainted data reaches raw SQL execution via engine.execute()")
_reg("sqlite3.connect",           "SQL Injection", "CWE-89",  "A03:2021", "HIGH",
     "Tainted data used in sqlite3 connection string")

# ── Command Injection ────────────────────────────────────────────
_reg("os.system",                 "Command Injection", "CWE-78", "A03:2021", "CRITICAL",
     "Tainted data reaches os.system() — arbitrary shell execution")
_reg("os.popen",                  "Command Injection", "CWE-78", "A03:2021", "CRITICAL",
     "Tainted data reaches os.popen() — arbitrary shell execution")
_reg("subprocess.run",            "Command Injection", "CWE-78", "A03:2021", "CRITICAL",
     "Tainted data reaches subprocess.run()")
_reg("subprocess.call",           "Command Injection", "CWE-78", "A03:2021", "CRITICAL",
     "Tainted data reaches subprocess.call()")
_reg("subprocess.Popen",          "Command Injection", "CWE-78", "A03:2021", "CRITICAL",
     "Tainted data reaches subprocess.Popen()")
_reg("subprocess.check_output",   "Command Injection", "CWE-78", "A03:2021", "CRITICAL",
     "Tainted data reaches subprocess.check_output()")

# ── Code Execution ───────────────────────────────────────────────
_reg("eval",                      "Code Execution", "CWE-95", "A03:2021", "CRITICAL",
     "Tainted data reaches eval() — arbitrary code execution")
_reg("exec",                      "Code Execution", "CWE-95", "A03:2021", "CRITICAL",
     "Tainted data reaches exec() — arbitrary code execution")
_reg("compile",                   "Code Execution", "CWE-95", "A03:2021", "HIGH",
     "Tainted data reaches compile() — dynamic code compilation")

# ── ReDoS (Regex Denial of Service) ─────────────────────────────
_reg("re.compile",                "ReDoS", "CWE-1333", "A03:2021", "HIGH",
     "User-controlled regex pattern reaches re.compile() — exponential backtracking possible")
_reg("re.match",                  "ReDoS", "CWE-1333", "A03:2021", "HIGH",
     "User-controlled regex pattern reaches re.match()")
_reg("re.search",                 "ReDoS", "CWE-1333", "A03:2021", "HIGH",
     "User-controlled regex pattern reaches re.search()")
_reg("re.findall",                "ReDoS", "CWE-1333", "A03:2021", "HIGH",
     "User-controlled regex pattern reaches re.findall()")

# ── Path Traversal / File Operations ────────────────────────────
_reg("open",                      "Path Traversal", "CWE-22",  "A01:2021", "HIGH",
     "Tainted data used as file path in open()")
_reg("os.remove",                 "Path Traversal", "CWE-22",  "A01:2021", "HIGH",
     "Tainted data used as file path in os.remove()")
_reg("os.unlink",                 "Path Traversal", "CWE-22",  "A01:2021", "HIGH",
     "Tainted data used as file path in os.unlink()")
_reg("shutil.rmtree",             "Path Traversal", "CWE-22",  "A01:2021", "CRITICAL",
     "Tainted data used as directory path in shutil.rmtree()")

# ── SSRF / Network ──────────────────────────────────────────────
_reg("requests.get",              "SSRF", "CWE-918", "A10:2021", "HIGH",
     "Tainted data used as URL in requests.get()")
_reg("requests.post",             "SSRF", "CWE-918", "A10:2021", "HIGH",
     "Tainted data used as URL in requests.post()")
_reg("requests.put",              "SSRF", "CWE-918", "A10:2021", "HIGH",
     "Tainted data used as URL in requests.put()")
_reg("urllib.request.urlopen",    "SSRF", "CWE-918", "A10:2021", "HIGH",
     "Tainted data used as URL in urlopen()")
_reg("httpx.get",                 "SSRF", "CWE-918", "A10:2021", "HIGH",
     "Tainted data used as URL in httpx.get()")
_reg("httpx.post",                "SSRF", "CWE-918", "A10:2021", "HIGH",
     "Tainted data used as URL in httpx.post()")

# ── Prompt Injection (LLM APIs) ────────────────────────────────
_reg("openai.Completion.create",           "Prompt Injection", "CWE-74", "LLM01", "CRITICAL",
     "Tainted data reaches OpenAI Completion API")
_reg("openai.ChatCompletion.create",       "Prompt Injection", "CWE-74", "LLM01", "CRITICAL",
     "Tainted data reaches OpenAI ChatCompletion API")
_reg("openai.chat.completions.create",     "Prompt Injection", "CWE-74", "LLM01", "CRITICAL",
     "Tainted data reaches OpenAI Chat Completions API")
_reg("anthropic.completions.create",       "Prompt Injection", "CWE-74", "LLM01", "CRITICAL",
     "Tainted data reaches Anthropic Completions API")
_reg("anthropic.messages.create",          "Prompt Injection", "CWE-74", "LLM01", "CRITICAL",
     "Tainted data reaches Anthropic Messages API")

# ── XSS / Template Injection ────────────────────────────────────
_reg("render_template_string",    "XSS / Template Injection", "CWE-79", "A03:2021", "CRITICAL",
     "Tainted data reaches render_template_string() — server-side template injection")
_reg("Markup",                    "XSS / Template Injection", "CWE-79", "A03:2021", "HIGH",
     "Tainted data passed to Markup() without escaping")
_reg("jinja2.Template",           "XSS / Template Injection", "CWE-79", "A03:2021", "HIGH",
     "Tainted data used to construct a Jinja2 Template")

# ── Open Redirect ───────────────────────────────────────────────
_reg("redirect",                  "Open Redirect", "CWE-601", "A01:2021", "HIGH",
     "Tainted data used as redirect target in redirect()")
_reg("flask.redirect",            "Open Redirect", "CWE-601", "A01:2021", "HIGH",
     "Tainted data used as redirect target in flask.redirect()")

# ── File Serving / Arbitrary File Read ──────────────────────────
_reg("send_file",                 "Path Traversal", "CWE-22",  "A01:2021", "HIGH",
     "Tainted data used as file path in send_file()")
_reg("flask.send_file",           "Path Traversal", "CWE-22",  "A01:2021", "HIGH",
     "Tainted data used as file path in flask.send_file()")
_reg("send_from_directory",       "Path Traversal", "CWE-22",  "A01:2021", "MEDIUM",
     "Tainted data used as filename in send_from_directory()")
_reg("codecs.open",               "Path Traversal", "CWE-22",  "A01:2021", "HIGH",
     "Tainted data used as file path in codecs.open()")

# ── XPath Injection ─────────────────────────────────────────────
_reg("lxml.etree.XPath",          "XPath Injection", "CWE-643", "A03:2021", "CRITICAL",
     "Tainted data used in XPath expression via lxml")
_reg("elementpath.select",        "XPath Injection", "CWE-643", "A03:2021", "CRITICAL",
     "Tainted data used in XPath expression via elementpath")

# ── LDAP Injection ──────────────────────────────────────────────
_reg("conn.search",               "LDAP Injection", "CWE-90",  "A03:2021", "CRITICAL",
     "Tainted data used in LDAP search filter")
_reg("connection.search",         "LDAP Injection", "CWE-90",  "A03:2021", "CRITICAL",
     "Tainted data used in LDAP search filter")

# ── Deserialization ─────────────────────────────────────────────
_reg("pickle.loads",              "Unsafe Deserialization", "CWE-502", "A08:2021", "CRITICAL",
     "Tainted data deserialized via pickle.loads()")
_reg("pickle.load",               "Unsafe Deserialization", "CWE-502", "A08:2021", "CRITICAL",
     "Tainted data deserialized via pickle.load()")
_reg("yaml.load",                 "Unsafe Deserialization", "CWE-502", "A08:2021", "CRITICAL",
     "Tainted data deserialized via yaml.load()")


# ── Classifier ───────────────────────────────────────────────────

class SinkClassifier:
    """
    Classify a sink call into a vulnerability type using the registry.

    Lookup uses suffix matching so ``self.cursor.execute`` resolves to
    the ``cursor.execute`` entry.
    """

    @staticmethod
    def classify(call_name: str) -> Optional[SinkInfo]:
        """Return SinkInfo for *call_name*, or ``None`` if not a known sink."""
        lower = call_name.lower()
        # Exact match first
        if lower in _SINK_REGISTRY:
            return _SINK_REGISTRY[lower]
        # Suffix match
        for key, info in _SINK_REGISTRY.items():
            if lower.endswith(key):
                return info
        return None

    @staticmethod
    def is_sink(call_name: str) -> bool:
        return SinkClassifier.classify(call_name) is not None

    @staticmethod
    def all_sinks() -> Dict[str, SinkInfo]:
        """Return a copy of the full sink registry."""
        return dict(_SINK_REGISTRY)
