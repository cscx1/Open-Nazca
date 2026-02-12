"""
XML External Entity (XXE) Detector (CWE-611).

Detects XML parsing that is vulnerable to XXE attacks. Based on
Bandit B313-B319, B405-B411 and Semgrep use-defused-xml patterns.

Vulnerable:
  - Any use of stdlib xml.etree.ElementTree.parse/fromstring/XMLParser
  - xml.sax.parse/parseString/make_parser
  - xml.dom.minidom/pulldom/expatbuilder parse/parseString
  - lxml.etree with resolve_entities=True
  - Explicit feature_external_ges=True

Safe:
  - defusedxml.*
  - lxml with resolve_entities=False (default in modern lxml)
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


# Vulnerable XML module imports (Bandit B405-B411).
_VULN_XML_IMPORTS = {
    "xml.etree.ElementTree",
    "xml.etree.cElementTree",
    "xml.sax",
    "xml.sax.expatreader",
    "xml.dom.minidom",
    "xml.dom.pulldom",
    "xml.dom.expatbuilder",
    "xmlrpc",
}

# Vulnerable XML function calls (Bandit B313-B319).
_VULN_XML_CALLS = re.compile(
    r"(?:"
    r"ET\.(?:parse|fromstring|iterparse|XMLParser)\s*\(|"
    r"ElementTree\.(?:parse|fromstring|iterparse|XMLParser)\s*\(|"
    r"cElementTree\.(?:parse|fromstring|iterparse|XMLParser)\s*\(|"
    r"xml\.etree\.ElementTree\.(?:parse|fromstring|iterparse|XMLParser)\s*\(|"
    r"xml\.etree\.cElementTree\.(?:parse|fromstring|iterparse|XMLParser)\s*\(|"
    r"xml\.sax\.(?:parse|parseString|make_parser)\s*\(|"
    r"xml\.dom\.minidom\.(?:parse|parseString)\s*\(|"
    r"xml\.dom\.pulldom\.(?:parse|parseString)\s*\(|"
    r"xml\.dom\.expatbuilder\.(?:parse|parseString)\s*\(|"
    r"minidom\.(?:parse|parseString)\s*\(|"
    r"pulldom\.(?:parse|parseString)\s*\(|"
    r"sax\.(?:parse|parseString|make_parser)\s*\("
    r")"
)

# Explicit vulnerability enablers.
_VULN_ENABLERS = [
    re.compile(r"setFeature\s*\([^,]*feature_external_ges\s*,\s*True"),
    re.compile(r"resolve_entities\s*=\s*True"),
    re.compile(r"load_dtd\s*=\s*True"),
    re.compile(r"no_network\s*=\s*False"),
]

# Safe patterns that suppress findings.
_SAFE_PATTERNS = re.compile(
    r"defusedxml|defused_xml",
    re.IGNORECASE,
)


class XXEDetector(BaseDetector):
    """Detect XML External Entity (XXE) vulnerabilities."""

    def __init__(self, enabled: bool = True):
        super().__init__("XXEDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        # Collect safe aliases/functions (defusedxml imports).
        safe_aliases: set = set()
        safe_functions: set = set()
        for line in lines:
            stripped = line.strip()
            if "defusedxml" in stripped:
                # import defusedxml.X as alias
                m = re.search(r"import\s+defusedxml\S*\s+as\s+(\w+)", stripped)
                if m:
                    safe_aliases.add(m.group(1))
                # from defusedxml.X import func as alias
                m = re.search(r"from\s+defusedxml\S*\s+import\s+\w+\s+as\s+(\w+)", stripped)
                if m:
                    safe_functions.add(m.group(1))
                # from defusedxml.X import func (no alias)
                m = re.search(r"from\s+defusedxml\S*\s+import\s+(\w+)$", stripped)
                if m:
                    safe_functions.add(m.group(1))

        # Track if we've seen a vulnerable XML import and collect aliases.
        has_vuln_import = False
        # Map: alias → full module (e.g. "badET" → "xml.etree.ElementTree")
        xml_aliases: set = set()

        for line in lines:
            stripped = line.strip()
            for imp in _VULN_XML_IMPORTS:
                if imp in stripped:
                    has_vuln_import = True
                    # Capture "import xml.etree.ElementTree as ALIAS"
                    m = re.search(
                        rf"import\s+{re.escape(imp)}\s+as\s+(\w+)", stripped
                    )
                    if m:
                        xml_aliases.add(m.group(1))
                    # Capture "from xml.X import func as ALIAS"
                    m = re.search(
                        r"from\s+xml\.\S+\s+import\s+(\w+)\s+as\s+(\w+)",
                        stripped,
                    )
                    if m:
                        # m.group(2) is the alias for a FUNCTION, not module
                        xml_aliases.add(m.group(2))

        if not has_vuln_import:
            return findings

        # Build alias-aware call patterns.
        xml_parse_funcs = {"parse", "fromstring", "iterparse", "XMLParser",
                           "parseString", "make_parser", "create_parser"}

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Skip lines that use safe (defusedxml) aliases.
            if _SAFE_PATTERNS.search(line):
                continue
            # Skip if the call uses a safe alias.
            uses_safe_alias = False
            for sa in safe_aliases:
                if re.search(rf"\b{re.escape(sa)}\.", line):
                    uses_safe_alias = True
                    break
            if uses_safe_alias:
                continue

            # Check for explicit vulnerability enablers (highest confidence).
            for pat in _VULN_ENABLERS:
                if pat.search(line):
                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="XML External Entity (XXE)",
                        severity="CRITICAL",
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            "XML parser explicitly enables external entity "
                            "processing. This allows attackers to read files, "
                            "perform SSRF, or cause DoS via entity expansion."
                        ),
                        confidence=0.97,
                        cwe_id="CWE-611",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        metadata={"detection_type": "explicit_enabler"},
                    ))
                    break

            # Check for vulnerable XML parsing calls (full-name patterns).
            if _VULN_XML_CALLS.search(line):
                snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="XML External Entity (XXE)",
                    severity="HIGH",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "Stdlib XML parser used without defusedxml. Python's "
                        "built-in XML parsers do not fully prevent XXE attacks. "
                        "Replace with defusedxml equivalents."
                    ),
                    confidence=0.88,
                    cwe_id="CWE-611",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    metadata={"detection_type": "unsafe_xml_call"},
                ))
                continue

            # Check alias-based calls:
            #   Module alias: badET.fromstring(...)
            #   Function alias: badParseString(...)
            matched_alias = False
            for alias in xml_aliases:
                if alias in safe_functions:
                    continue
                # Module alias: alias.func()
                for func in xml_parse_funcs:
                    pat = rf"\b{re.escape(alias)}\.{func}\s*\("
                    if re.search(pat, line):
                        snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                        findings.append(Finding(
                            detector_name=self.name,
                            vulnerability_type="XML External Entity (XXE)",
                            severity="HIGH",
                            line_number=line_num,
                            code_snippet=snippet,
                            description=(
                                f"Stdlib XML parser '{alias}.{func}()' used. "
                                f"Replace with defusedxml equivalents."
                            ),
                            confidence=0.88,
                            cwe_id="CWE-611",
                            owasp_category="A05:2021 – Security Misconfiguration",
                            metadata={"detection_type": "alias_xml_call",
                                      "alias": alias},
                        ))
                        matched_alias = True
                        break

                # Function alias: badParseString(...)
                if not matched_alias:
                    pat = rf"(?<!\w){re.escape(alias)}\s*\("
                    if re.search(pat, line):
                        snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                        findings.append(Finding(
                            detector_name=self.name,
                            vulnerability_type="XML External Entity (XXE)",
                            severity="HIGH",
                            line_number=line_num,
                            code_snippet=snippet,
                            description=(
                                f"Stdlib XML function '{alias}()' used. "
                                f"Replace with defusedxml equivalents."
                            ),
                            confidence=0.88,
                            cwe_id="CWE-611",
                            owasp_category="A05:2021 – Security Misconfiguration",
                            metadata={"detection_type": "alias_func_call",
                                      "alias": alias},
                        ))

                if matched_alias:
                    break

        self.findings = findings
        return findings
