"""
Cryptography Misuse Detector (CWE-327, CWE-329, CWE-326).

Detects dangerous cryptographic practices:
  - Static / hardcoded IVs (CWE-329)
  - ECB mode usage (CWE-327)
  - Weak cipher algorithms: DES, DES3, Blowfish, ARC2, ARC4, XOR (CWE-327)
  - Weak key sizes for RSA/DSA (CWE-326)
  - Hardcoded encryption keys
  - Use of deprecated pycrypto

Based on Bandit B303-B305, B413, B505 and Semgrep crypto rules.
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class CryptoMisuseDetector(BaseDetector):
    """Detect cryptography misuse: static IVs, weak ciphers, ECB mode, etc."""

    def __init__(self, enabled: bool = True):
        super().__init__("CryptoMisuseDetector", enabled)

        self._checks = [
            # ── Static / hardcoded IV ──────────────────────────────
            {
                "pattern": re.compile(
                    r"""(?:iv|nonce|IV|NONCE)\s*=\s*(?:b?['\"][^'\"]{8,}['\"])"""
                ),
                "vuln_type": "Static IV/Nonce",
                "severity": "HIGH",
                "cwe": "CWE-329",
                "desc": (
                    "Hardcoded IV or nonce detected. Using a static IV "
                    "with CBC mode allows attackers to detect repeated "
                    "plaintexts. IVs must be randomly generated for each "
                    "encryption operation using os.urandom()."
                ),
            },
            # ── ECB mode ──────────────────────────────────────────
            {
                "pattern": re.compile(
                    r"(?:MODE_ECB|modes\.ECB|AES\.MODE_ECB|DES\.MODE_ECB|"
                    r"(?<!\w)ECB\s*\()"
                ),
                "vuln_type": "ECB Mode Usage",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "desc": (
                    "ECB (Electronic Codebook) mode detected. ECB encrypts "
                    "identical plaintext blocks to identical ciphertext "
                    "blocks, leaking data patterns. Use GCM, CTR, or "
                    "CBC with random IVs instead."
                ),
            },
            # ── Weak cipher algorithms ────────────────────────────
            {
                "pattern": re.compile(
                    r"(?:Cipher|algorithms)\s*\.\s*(?:DES|DES3|TripleDES|"
                    r"Blowfish|ARC2|ARC4|RC4|XOR|IDEA|CAST5|SEED)\s*[\.(]"
                ),
                "vuln_type": "Weak Cipher Algorithm",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "desc": (
                    "Weak or deprecated cipher algorithm detected. DES, "
                    "3DES, Blowfish, RC4, and other legacy ciphers have "
                    "known vulnerabilities. Use AES-256-GCM or "
                    "ChaCha20-Poly1305 instead."
                ),
            },
            # ── Hardcoded encryption key ──────────────────────────
            {
                "pattern": re.compile(
                    r"(?:AES|DES|Cipher)\.new\s*\(\s*b?['\"][^'\"]{8,}['\"]"
                ),
                "vuln_type": "Hardcoded Encryption Key",
                "severity": "CRITICAL",
                "cwe": "CWE-321",
                "desc": (
                    "Hardcoded encryption key passed directly to cipher. "
                    "Keys embedded in source code can be extracted by "
                    "anyone with access to the codebase. Use a key "
                    "management system or derive keys from a KDF."
                ),
            },
            # ── Weak RSA key size ─────────────────────────────────
            {
                "pattern": re.compile(
                    r"(?:generate_private_key|RSA\.generate|DSA\.generate)\s*\(\s*(?:key_size\s*=\s*)?(\d+)"
                ),
                "vuln_type": "Weak Key Size",
                "severity": "HIGH",
                "cwe": "CWE-326",
                "desc_fn": "_check_key_size",
            },
            # ── Weak Crypto.Hash imports (Crypto.Hash.MD5, etc.) ──
            {
                "pattern": re.compile(
                    r"(?:Crypto|Cryptodome)\.Hash\.(?:MD2|MD4|MD5|SHA)\b"
                ),
                "vuln_type": "Weak Hash Algorithm",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "desc": (
                    "Weak hash algorithm imported from Crypto/Cryptodome. "
                    "MD2, MD4, MD5, and SHA-1 are cryptographically broken. "
                    "Use SHA-256 or stronger."
                ),
            },
            # ── cryptography.hazmat.primitives.hashes weak ────────
            {
                "pattern": re.compile(
                    r"hashes\.(?:MD5|SHA1)\s*\("
                ),
                "vuln_type": "Weak Hash Algorithm",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "desc": (
                    "Weak hash algorithm from cryptography library. "
                    "MD5 and SHA-1 are cryptographically broken. "
                    "Use hashes.SHA256() or stronger."
                ),
            },
            # ── Deprecated pycrypto import ────────────────────────
            {
                "pattern": re.compile(
                    r"from\s+Crypto\s+import|import\s+Crypto\."
                ),
                "vuln_type": "Deprecated Crypto Library",
                "severity": "MEDIUM",
                "cwe": "CWE-327",
                "desc": (
                    "The pycrypto library (Crypto) is deprecated and has "
                    "known vulnerabilities. Use pycryptodome (Cryptodome) "
                    "or the cryptography library instead."
                ),
                # Only flag if pycryptodome is NOT being used
                "skip_if": re.compile(r"from\s+Cryptodome|import\s+Cryptodome"),
            },
        ]

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for check in self._checks:
                # Skip if exclusion pattern matches the whole file.
                if "skip_if" in check and check["skip_if"].search(code):
                    continue

                m = check["pattern"].search(line)
                if m:
                    # Reduce false positives: base64 encoding/decoding is not encryption.
                    if check["vuln_type"] == "Static IV/Nonce":
                        # Check both the current line AND surrounding lines for base64/encoding.
                        region_start = max(0, line_num - 4)
                        region_end = min(len(lines), line_num + 4)
                        region_text = "\n".join(lines[region_start:region_end]).lower()
                        if re.search(
                            r"base64|b64encode|b64decode|urlsafe_b64|encodebytes",
                            region_text,
                        ):
                            # IV variable is used for encoding, not real crypto.
                            # Only flag if there's ALSO actual cipher context nearby.
                            if not re.search(
                                r"aes\.new|cipher\.new|cipher\.encrypt|fernet|"
                                r"mode_cbc|mode_gcm|mode_ctr|chacha20",
                                region_text,
                            ):
                                continue
                        # No base64 nearby — still require real crypto context.
                        elif not re.search(
                            r"aes|cipher|encrypt|decrypt|mode_|gcm|cbc|ctr|chacha",
                            region_text,
                        ):
                            continue

                    # Handle dynamic description for key size checks.
                    desc = check.get("desc", "")
                    if check.get("desc_fn") == "_check_key_size":
                        try:
                            key_size = int(m.group(1))
                            if key_size >= 2048:
                                continue  # Safe key size
                            desc = (
                                f"Weak key size ({key_size} bits) for asymmetric "
                                f"cryptography. RSA/DSA keys should be at least "
                                f"2048 bits, preferably 4096 bits."
                            )
                        except (ValueError, IndexError):
                            continue

                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type=check["vuln_type"],
                        severity=check["severity"],
                        line_number=line_num,
                        code_snippet=snippet,
                        description=desc,
                        confidence=0.92,
                        cwe_id=check["cwe"],
                        owasp_category="A02:2021 – Cryptographic Failures",
                        metadata={},
                    ))
                    break

        self.findings = findings
        return findings
