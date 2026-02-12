"""
Time-of-Check to Time-of-Use (TOCTOU) Race Condition Detector (CWE-367).

Detects check-then-use patterns where a security check on a resource
is followed by a use of that resource, with a window for an attacker
to modify the resource between check and use.

Patterns:
  - os.path.exists(f) → open(f)
  - os.access(f, ...) → open(f)
  - os.stat(f) → open(f)
  - tempfile.mktemp() (Bandit B306)

Based on Bandit B306 and general TOCTOU research.
"""

import re
from typing import Dict, List, Set, Tuple
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# Check functions that inspect file state.
_CHECK_FUNCS = re.compile(
    r"(?:os\.path\.exists|os\.path\.isfile|os\.path\.isdir|"
    r"os\.access|os\.stat|os\.lstat|pathlib\.Path\(\w+\)\.exists|"
    r"pathlib\.Path\(\w+\)\.is_file)\s*\(\s*(\w+)"
)

# Use functions that operate on files.
_USE_FUNCS = re.compile(
    r"(?:open|codecs\.open|os\.remove|os\.unlink|os\.rename|"
    r"os\.chmod|os\.chown|shutil\.rmtree|shutil\.copy|"
    r"shutil\.move)\s*\(\s*(\w+)"
)

# Dangerous tempfile usage.
_MKTEMP = re.compile(r"tempfile\.mktemp\s*\(")


class TOCTOUDetector(BaseDetector):
    """Detect TOCTOU race conditions and unsafe tempfile usage."""

    def __init__(self, enabled: bool = True):
        super().__init__("TOCTOUDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        # Pass 1: Find check-then-use patterns.
        # Track: file_var → (check_line, check_func)
        checked_files: Dict[str, Tuple[int, str]] = {}

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Detect file checks.
            check_m = _CHECK_FUNCS.search(line)
            if check_m:
                file_var = check_m.group(1)
                checked_files[file_var] = (line_num, check_m.group())

            # Detect file uses.
            use_m = _USE_FUNCS.search(line)
            if use_m:
                file_var = use_m.group(1)
                if file_var in checked_files:
                    check_line, check_func = checked_files[file_var]
                    # TOCTOU: check on line N, use on line M (M > N).
                    if line_num > check_line:
                        snippet = self.extract_code_snippet(
                            code, line_num, context_lines=4
                        )
                        findings.append(Finding(
                            detector_name=self.name,
                            vulnerability_type="TOCTOU Race Condition",
                            severity="HIGH",
                            line_number=line_num,
                            code_snippet=snippet,
                            description=(
                                f"Time-of-check to time-of-use (TOCTOU) race "
                                f"condition: file '{file_var}' is checked on "
                                f"line {check_line} then used on line {line_num}. "
                                f"Between check and use, an attacker can replace "
                                f"the file with a symlink to a sensitive resource. "
                                f"Use atomic operations or open-then-check patterns."
                            ),
                            confidence=0.85,
                            cwe_id="CWE-367",
                            owasp_category="A01:2021 – Broken Access Control",
                            metadata={
                                "check_line": check_line,
                                "use_line": line_num,
                                "file_var": file_var,
                            },
                        ))

            # Detect tempfile.mktemp().
            if _MKTEMP.search(line):
                snippet = self.extract_code_snippet(code, line_num, context_lines=2)
                findings.append(Finding(
                    detector_name=self.name,
                    vulnerability_type="Insecure Temp File",
                    severity="HIGH",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        "tempfile.mktemp() is vulnerable to symlink races. "
                        "Between name generation and file creation, an "
                        "attacker can create a symlink at the generated path. "
                        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()."
                    ),
                    confidence=0.95,
                    cwe_id="CWE-377",
                    owasp_category="A01:2021 – Broken Access Control",
                    metadata={},
                ))

        self.findings = findings
        return findings
