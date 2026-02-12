"""
Reachability verifier with trust-gradient classification.

Given a set of attack paths, determines whether each is:
  - Confirmed Reachable   – source→sink path exists with no sanitizer
  - Reachability Eliminated – all paths broken by a sanitizer or removal
  - Unverifiable           – path exists but sanitisation cannot be proven
  - Requires Manual Review – runtime context or config makes static proof impossible

Verification relies on static reachability analysis, not on executing
exploit payloads.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .attack_graph import AttackPath
from .taint_tracker import TaintNode, NodeKind

logger = logging.getLogger(__name__)


class ReachabilityStatus(str, Enum):
    CONFIRMED_REACHABLE = "Confirmed Reachable"
    REACHABILITY_ELIMINATED = "Reachability Eliminated"
    UNVERIFIABLE = "Unverifiable"
    REQUIRES_MANUAL_REVIEW = "Requires Manual Review"


@dataclass
class ReachabilityResult:
    """Verification result for one attack path."""
    path: AttackPath
    status: ReachabilityStatus
    reasoning: str
    sanitizers_found: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "path": self.path.to_dict(),
            "status": self.status.value,
            "reasoning": self.reasoning,
            "sanitizers_found": self.sanitizers_found,
        }


# ── Known sanitiser patterns ────────────────────────────────────
# Maps vulnerability type → set of function/method names that are
# considered effective sanitisers.

_SANITISERS: Dict[str, Set[str]] = {
    "SQL Injection": {
        "escape_string",
        "sqlalchemy.text", "bindparam",
        # The presence of '?' or '%s' placeholders in the query string
    },
    "Command Injection": {
        "shell=False",
    },
    "Code Execution": {
        "ast.literal_eval",
    },
    "XSS / Template Injection": {
        "markupsafe.escape", "html.escape", "bleach.clean",
        "jinja2.escape",
    },
    "Path Traversal": {
        "os.path.basename", "pathlib.PurePath", "secure_filename",
        "os.path.realpath", "os.path.abspath",
    },
    "Prompt Injection": {
        # There are no universally accepted sanitisers for prompt injection.
        # The presence of structured message arrays is a mitigation but
        # not a sanitiser per se.
    },
    "SSRF": {
        "urllib.parse.urlparse", "ipaddress.ip_address",
        "is_safe_url", "validate_url",
    },
    "Open Redirect": {
        "url_has_allowed_host_and_scheme",
        "is_safe_url", "validate_redirect_url",
        "urlparse",
    },
}

# Patterns indicating runtime-dependent reachability.
_RUNTIME_PATTERNS = re.compile(
    r"(os\.environ|getenv|config\[|settings\.|FLAGS\.|if\s+__name__)",
    re.IGNORECASE,
)


class ReachabilityVerifier:
    """
    Classify each attack path with a trust-gradient status.

    The verifier:
    1. Checks if known sanitisers appear along the path.
    2. Checks for parameterised-query patterns (SQL).
    3. Checks for runtime guards that prevent static proof.
    4. Falls back to Unverifiable when analysis is inconclusive.
    """

    def verify_paths(
        self,
        paths: List[AttackPath],
        source_code: str,
        file_name: str,
    ) -> List[ReachabilityResult]:
        results: List[ReachabilityResult] = []
        for path in paths:
            result = self._verify_one(path, source_code, file_name)
            results.append(result)
        return results

    def _verify_one(
        self,
        path: AttackPath,
        source: str,
        file_name: str,
    ) -> ReachabilityResult:
        vuln_type = path.vulnerability_type
        sanitisers_found: List[str] = []

        lines = source.split("\n")

        # 1) Check for known sanitisers between source and sink
        src_line = path.source.line
        sink_line = path.sink.line
        lo = max(0, min(src_line, sink_line) - 1)
        hi = min(len(lines), max(src_line, sink_line))
        region = "\n".join(lines[lo:hi])

        known = _SANITISERS.get(vuln_type, set())
        for san in known:
            if san.lower() in region.lower():
                sanitisers_found.append(san)

        # 2) SQL-specific: check for parameterised query usage on the sink call.
        #    IMPORTANT: placeholders in earlier query construction are NOT proof
        #    of safety (e.g., "SELECT ... %s" % user_input).
        if vuln_type == "SQL Injection":
            sink_line_text = lines[sink_line - 1] if 1 <= sink_line <= len(lines) else ""
            if re.search(r"\.execute\s*\(\s*[^,\)]+,\s*.+\)", sink_line_text):
                sanitisers_found.append("parameterized_execute_args")

        # 3) Command injection: only treat explicit shell=False as a sanitiser.
        #    shlex.quote() in nearby lines does not make shell=True safe.
        if vuln_type == "Command Injection":
            sink_line_text = lines[sink_line - 1] if 1 <= sink_line <= len(lines) else ""
            if "shell=False" in sink_line_text:
                sanitisers_found.append("shell=False")
            elif "shell=True" in sink_line_text:
                # Explicitly dangerous — no sanitisation
                pass

        # 4) XSS-specific: Jinja2 ``| safe`` is an ANTI-sanitiser.
        #    It explicitly disables Jinja2 auto-escaping, so any
        #    code-level sanitisers (html.escape, etc.) are negated
        #    once the value enters the template.
        if vuln_type in ("XSS / Template Injection",):
            if re.search(r'\|\s*safe\b', source):
                anti = "Jinja2 '| safe' filter disables auto-escaping"
                logger.info("Anti-sanitiser detected: %s", anti)
                sanitisers_found.clear()

        # 5) If sanitisers found → eliminated
        if sanitisers_found:
            return ReachabilityResult(
                path=path,
                status=ReachabilityStatus.REACHABILITY_ELIMINATED,
                reasoning=(
                    f"Sanitiser(s) detected between source (line {src_line}) "
                    f"and sink (line {sink_line}): {', '.join(sanitisers_found)}. "
                    f"Reachability is considered eliminated, though manual "
                    f"confirmation of sanitiser effectiveness is recommended."
                ),
                sanitizers_found=sanitisers_found,
            )

        # 6) Check for runtime-dependent reachability
        if _RUNTIME_PATTERNS.search(region):
            return ReachabilityResult(
                path=path,
                status=ReachabilityStatus.REQUIRES_MANUAL_REVIEW,
                reasoning=(
                    f"Path from source (line {src_line}) to sink "
                    f"(line {sink_line}) depends on runtime configuration "
                    f"or environment variables. Static analysis cannot "
                    f"determine whether the path is exercised at runtime."
                ),
                sanitizers_found=[],
            )

        # 7) Path exists with no sanitiser → Confirmed Reachable
        #    (only if we have concrete source and sink nodes)
        if (path.source.kind == NodeKind.SOURCE
                and path.sink.kind == NodeKind.SINK):
            return ReachabilityResult(
                path=path,
                status=ReachabilityStatus.CONFIRMED_REACHABLE,
                reasoning=(
                    f"Tainted data flows from {path.source.name} "
                    f"(line {src_line}) to {path.sink.name} "
                    f"(line {sink_line}) with no sanitiser detected. "
                    f"The path is considered reachable."
                ),
                sanitizers_found=[],
            )

        # 8) Fallback
        return ReachabilityResult(
            path=path,
            status=ReachabilityStatus.UNVERIFIABLE,
            reasoning=(
                f"A potential path exists from {path.source.name} to "
                f"{path.sink.name}, but static analysis could not "
                f"conclusively prove or disprove reachability."
            ),
            sanitizers_found=[],
        )

    # ── After-remediation reclassification ────────────────────

    def reclassify_after_fix(
        self,
        before_results: List[ReachabilityResult],
        after_paths: List[AttackPath],
        fixed_source: str,
        file_name: str,
    ) -> List[ReachabilityResult]:
        """
        Re-verify paths against the fixed code and return updated statuses.
        """
        after_results = self.verify_paths(after_paths, fixed_source, file_name)

        # Also mark any before-path that no longer appears as Eliminated
        after_keys = {
            (r.path.source.name, r.path.sink.name, r.path.sink.line)
            for r in after_results
        }
        final: List[ReachabilityResult] = []
        for br in before_results:
            key = (br.path.source.name, br.path.sink.name, br.path.sink.line)
            if key not in after_keys:
                final.append(ReachabilityResult(
                    path=br.path,
                    status=ReachabilityStatus.REACHABILITY_ELIMINATED,
                    reasoning=(
                        f"Attack path from {br.path.source.name} to "
                        f"{br.path.sink.name} (line {br.path.sink.line}) "
                        f"no longer exists after remediation."
                    ),
                    sanitizers_found=[],
                ))
            else:
                # Find the matching after-result
                for ar in after_results:
                    arkey = (ar.path.source.name, ar.path.sink.name, ar.path.sink.line)
                    if arkey == key:
                        final.append(ar)
                        break
        return final
