"""
Canonical ownership of vulnerability types for deduplication.

When multiple detectors (e.g. pattern detector + taint) report the same
vulnerability type at the same line, we keep the finding from the
"owner" detector so each type has one clear source of truth.
"""

from typing import Dict, Optional

# vulnerability_type (normalised for lookup) -> detector name that "owns" it.
# Taint pipeline uses detector_name "TaintAnalysis"; pattern detectors use their class name.
VULN_TYPE_OWNER: Dict[str, str] = {
    "sql injection": "SQLInjectionDetector",
    "command injection": "EvasionPatternsDetector",  # has pattern; GeneralFlow is taint-only
    "code execution": "GeneralFlowDetector",
    "code injection": "GeneralFlowDetector",
    "path traversal": "EvasionPatternsDetector",
    "xss": "XSSDetector",
    "reflected xss": "XSSDetector",
    "xss / template injection": "XSSDetector",
    "open redirect": "OperationalSecurityDetector",
    "xpath injection": "XPathInjectionDetector",
    "ldap injection": "LDAPInjectionDetector",
    "trust boundary violation": "TrustBoundaryDetector",
    "unsafe deserialization": "DeserializationDetector",
    "xml external entity (xxe)": "XXEDetector",
    "weak random": "WeakRandomDetector",
    "weak hash": "WeakHashDetector",
    "insecure cookie": "SecureCookieDetector",
    "prompt injection": "PromptInjectionDetector",
    "hardcoded secret": "HardcodedSecretsDetector",
    "over-privileged ai tool": "OverprivilegedToolsDetector",
    "over-privileged ai agent": "OverprivilegedToolsDetector",
    "crypto misuse": "CryptoMisuseDetector",
    "toctou race condition": "TOCTOUDetector",
    "insecure temp file": "TOCTOUDetector",
    "log injection": "LogInjectionDetector",
    "mass assignment": "TypeConfusionDetector",
    "attribute injection": "TypeConfusionDetector",
    "unsafe reflection": "UnsafeReflectionDetector",
    "debug mode enabled": "OperationalSecurityDetector",
    "missing security headers": "OperationalSecurityDetector",
    "missing csrf protection": "OperationalSecurityDetector",
    "missing rate limiting": "OperationalSecurityDetector",
    "format string injection": "OperationalSecurityDetector",
    "redos": "GeneralFlowDetector",
    "ssrf": "GeneralFlowDetector",
}


def get_owner(vulnerability_type: str) -> Optional[str]:
    """Return the detector name that owns this vulnerability type, or None."""
    if not vulnerability_type:
        return None
    key = vulnerability_type.strip().lower()
    return VULN_TYPE_OWNER.get(key)


def is_owner(detector_name: str, vulnerability_type: str) -> bool:
    """True if this detector is the canonical owner for this vulnerability type."""
    owner = get_owner(vulnerability_type)
    return owner is not None and detector_name == owner
