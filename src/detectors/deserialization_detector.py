"""
Unsafe Deserialization Detector (CWE-502).

Detects use of unsafe deserialization functions on potentially
user-controlled data (``pickle.loads``, ``yaml.load``, ``marshal.loads``).

Safe alternatives: ``yaml.safe_load``, ``json.loads``.
"""

import re
from typing import List, Set, Tuple
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)

# Unsafe deserialization sinks.
# Format: (regex_pattern, display_name, description)
# IMPORTANT: patterns MUST be specific enough to avoid matching unrelated
# methods like .decode(), open(), etc.
_UNSAFE_DESER: List[Tuple[re.Pattern, str, str]] = [
    # pickle.loads / pickle.load — require "pickle." prefix
    (re.compile(r"\bpickle\.loads?\s*\("),
     "pickle.loads", "pickle deserialization allows arbitrary code execution"),
    # cPickle
    (re.compile(r"\bcPickle\.loads?\s*\("),
     "cPickle.loads", "cPickle deserialization allows arbitrary code execution"),
    # marshal — require "marshal." prefix
    (re.compile(r"\bmarshal\.loads?\s*\("),
     "marshal.loads", "marshal deserialization can execute arbitrary code"),
    # shelve.open — require "shelve." prefix (NOT plain open())
    (re.compile(r"\bshelve\.open\s*\("),
     "shelve.open", "shelve uses pickle internally"),
    # yaml.load — require "yaml." prefix, exclude safe_load
    (re.compile(r"\byaml\.load\s*\("),
     "yaml.load", "yaml.load can instantiate arbitrary Python objects"),
    (re.compile(r"\byaml\.unsafe_load\s*\("),
     "yaml.unsafe_load", "yaml.unsafe_load allows arbitrary object instantiation"),
    # jsonpickle.decode — require "jsonpickle." prefix (NOT .decode())
    (re.compile(r"\bjsonpickle\.decode\s*\("),
     "jsonpickle.decode", "jsonpickle can reconstruct arbitrary objects"),
    # dill
    (re.compile(r"\bdill\.loads?\s*\("),
     "dill.loads", "dill deserialization allows arbitrary code execution"),
]

# Safe patterns that suppress findings on the same line.
_SAFE_PATTERNS = re.compile(
    r"yaml\.safe_load|yaml\.CSafeLoader|SafeLoader|"
    r"defusedxml|ast\.literal_eval",
    re.IGNORECASE,
)


class DeserializationDetector(BaseDetector):
    """Detect unsafe deserialization of user-controlled data."""

    def __init__(self, enabled: bool = True):
        super().__init__("DeserializationDetector", enabled)

    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Skip safe patterns on same line.
            if _SAFE_PATTERNS.search(line):
                continue

            for pattern, sink_name, desc in _UNSAFE_DESER:
                if pattern.search(line):
                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    findings.append(Finding(
                        detector_name=self.name,
                        vulnerability_type="Unsafe Deserialization",
                        severity="CRITICAL",
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            f"Unsafe deserialization via {sink_name}(): {desc}. "
                            f"An attacker controlling the serialized payload "
                            f"can achieve remote code execution."
                        ),
                        confidence=0.92,
                        cwe_id="CWE-502",
                        owasp_category="A08:2021 – Software and Data Integrity Failures",
                        metadata={"sink": sink_name},
                    ))
                    break  # one finding per line

        self.findings = findings
        return findings
