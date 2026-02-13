"""
Weak Hashing Algorithm Detector (CWE-328).

Detects use of cryptographically broken hash algorithms such as MD5 and
SHA-1 via ``hashlib``.

Safe alternatives: SHA-256, SHA-384, SHA-512, SHA3, BLAKE2.
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# Weak algorithm names (case-insensitive).
_WEAK_ALGOS = {"md5", "sha1", "sha", "md4", "md2", "ripemd160"}
_STRONG_ALGOS = {
    "sha256", "sha224", "sha384", "sha512",
    "sha3_256", "sha3_384", "sha3_512", "sha3_224",
    "blake2b", "blake2s",
}


class WeakHashDetector(BaseDetector):
    """Detect weak hashing algorithms (MD5, SHA-1, etc.)."""

    def __init__(self, enabled: bool = True):
        super().__init__("WeakHashDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            found_weak = self._check_line(line)
            if not found_weak:
                continue

            # FP suppression: skip when used for non-security purposes (checksum, dedup, file id).
            region_start = max(0, line_num - 6)
            region_end = min(len(lines), line_num + 2)
            region = " ".join(lines[region_start:region_end]).lower()
            non_security_hints = (
                "checksum", "dedup", "dedupe", "file_id", "etag", "non-crypto",
                "non-security", "cache_key", "content_hash", "blob_id",
            )
            if any(h in region for h in non_security_hints):
                continue

            snippet = self.extract_code_snippet(code, line_num, context_lines=2)
            findings.append(Finding(
                detector_name=self.name,
                vulnerability_type="Weak Hash",
                severity="HIGH",
                line_number=line_num,
                code_snippet=snippet,
                description=(
                    f"Weak hashing algorithm '{found_weak}' detected. "
                    f"Algorithms like MD5 and SHA-1 are cryptographically "
                    f"broken and vulnerable to collision attacks. Use "
                    f"SHA-256 or stronger for security-sensitive hashing."
                ),
                confidence=0.93,
                cwe_id="CWE-328",
                owasp_category="A02:2021 – Cryptographic Failures",
                metadata={"algorithm": found_weak},
            ))

        self.findings = findings
        return findings

    @staticmethod
    def _check_line(line: str) -> str:
        """Return the weak algorithm name found on *line*, or empty string."""
        # Pattern 1: hashlib.new('md5') / hashlib.new("sha1")
        m = re.search(r"hashlib\.new\s*\(\s*['\"](\w+)['\"]", line)
        if m:
            algo = m.group(1).lower().replace("-", "")
            if algo in _WEAK_ALGOS:
                return algo
            return ""

        # Pattern 2: hashlib.md5() / hashlib.sha1()
        m = re.search(r"hashlib\.(\w+)\s*\(", line)
        if m:
            algo = m.group(1).lower()
            if algo in _WEAK_ALGOS:
                return algo

        return ""
