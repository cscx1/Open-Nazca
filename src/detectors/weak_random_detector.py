"""
Weak Random Number Generator Detector (CWE-330).

Detects use of non-cryptographic PRNGs (e.g. ``random.randint``) for
security-sensitive values such as session tokens, cookies, or passwords.

Safe alternatives: ``secrets.*``, ``random.SystemRandom().*``
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# Weak random calls from the ``random`` module (Mersenne Twister).
_WEAK_RANDOM_CALLS = {
    "random.random",
    "random.randint",
    "random.randrange",
    "random.uniform",
    "random.choice",
    "random.choices",
    "random.sample",
    "random.shuffle",
    "random.gauss",
    "random.normalvariate",
    "random.lognormvariate",
    "random.expovariate",
    "random.vonmisesvariate",
    "random.gammavariate",
    "random.betavariate",
    "random.paretovariate",
    "random.weibullvariate",
    "random.triangular",
    "random.getrandbits",
    "random.randbytes",
}

# Safe random calls.
_SAFE_RANDOM_PATTERNS = re.compile(
    r"secrets\.|SystemRandom\(\)|os\.urandom|random\.SystemRandom",
    re.IGNORECASE,
)


class WeakRandomDetector(BaseDetector):
    """Detect weak (non-cryptographic) random number generators."""

    def __init__(self, enabled: bool = True):
        super().__init__("WeakRandomDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        # Track whether the file imports secrets or SystemRandom.
        has_safe_import = bool(
            re.search(r"^\s*(?:import\s+secrets|from\s+secrets\s+import)", code, re.MULTILINE)
        )
        uses_system_random = "SystemRandom" in code
        last_predictable_seed_line = None

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Skip lines that use a safe alternative on the same line.
            if _SAFE_RANDOM_PATTERNS.search(line):
                continue

            # Detect predictable seeding; this is often the true root cause.
            if re.search(r"\brandom\.seed\s*\(", line):
                if re.search(r"time\.|datetime|os\.getpid|int\s*\(|str\s*\(", line):
                    last_predictable_seed_line = line_num
                    snippet = self.extract_code_snippet(code, line_num, context_lines=2)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="Weak Random",
                        severity="HIGH",
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            "Predictable random.seed(...) detected. Seed values derived from "
                            "time/process data are guessable and make PRNG output predictable."
                        ),
                        confidence=0.93,
                        cwe_id="CWE-330",
                        owasp_category="A02:2021 – Cryptographic Failures",
                        metadata={"weak_call": "random.seed"},
                    ))
                continue

            # Check for weak random calls.
            for weak_call in _WEAK_RANDOM_CALLS:
                # Build a pattern that matches random.X( but NOT SystemRandom().X(
                func_name = weak_call.split(".")[-1]
                # Match: random.func( but NOT SystemRandom().func(
                pattern = rf'(?<!\w)random\.{re.escape(func_name)}\s*\('
                if re.search(pattern, line):
                    # Double-check it's not SystemRandom().method()
                    sr_pat = rf'SystemRandom\(\)\s*\.{re.escape(func_name)}'
                    if re.search(sr_pat, line):
                        continue

                    # If just seeded predictably nearby, anchor finding at the seed line.
                    report_line = line_num
                    if (
                        last_predictable_seed_line is not None
                        and 0 <= (line_num - last_predictable_seed_line) <= 3
                    ):
                        report_line = last_predictable_seed_line

                    # FP suppression: skip when randomness is clearly non-security (shuffle, demo, game).
                    region_start = max(0, report_line - 8)
                    region_end = min(len(lines), report_line + 3)
                    region = " ".join(lines[region_start:region_end]).lower()
                    security_hints = ("token", "password", "secret", "key", "session", "auth", "nonce", "otp", "csrf")
                    non_security_hints = ("shuffle", "sample", "demo", "game", "random_order", "pick_random")
                    if any(h in region for h in non_security_hints) and not any(s in region for s in security_hints):
                        break

                    snippet = self.extract_code_snippet(code, report_line, context_lines=2)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="Weak Random",
                        severity="HIGH",
                        line_number=report_line,
                        code_snippet=snippet,
                        description=(
                            f"Non-cryptographic PRNG '{weak_call}()' used. "
                            f"The standard `random` module uses Mersenne Twister which "
                            f"is predictable. For security-sensitive values (tokens, "
                            f"cookies, passwords) use `secrets` or `random.SystemRandom()`."
                        ),
                        confidence=0.92,
                        cwe_id="CWE-330",
                        owasp_category="A02:2021 – Cryptographic Failures",
                        metadata={"weak_call": weak_call},
                    ))
                    break  # one finding per line

        self.findings = findings
        return findings
