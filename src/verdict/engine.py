"""
Verdict engine: aggregates context and runs rules with precedence.

Rule execution: Rules run in fixed order. Only Confirmed or Out-of-scope
terminates evaluation; Unverified does NOT stop—a later rule can still
return Confirmed/Out-of-scope. This avoids false negatives (e.g. file in
/tests/ marked Unverified when Taint would mark Confirmed).

Order (critical): Environment → XSS → SQL Sanitizer → [Input Validation] →
Taint Reachability → Pattern Fallback. SQL Sanitizer must run before Taint
so parameterized queries get Out-of-scope instead of Confirmed.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Verdict, FindingWithVerdict, VerdictStatus
from .rules import (
    EnvironmentNeutralizerRule,
    XSSContextRule,
    SQLSanitizerRule,
    InputValidationRule,
    TaintReachabilityRule,
    PatternOnlyFallbackRule,
)


@dataclass
class ProjectContext:
    """Project-wide signature: web app vs library; framework hints from deps and file patterns."""
    is_web_app: bool
    is_library: bool
    has_views_or_urls: bool  # urls.py, views.py, routes.py, app.py in root
    has_package_json: bool  # Node.js project


@dataclass
class FileContext:
    """Per-file context for verdict rules."""
    file_path: str
    imports: List[str]
    is_entry_point: bool
    is_test_file: bool  # path contains /tests/ or /examples/
    line_to_content: Dict[int, str]
    project_context: ProjectContext
    route_path: Optional[str] = None  # from @app.route("/path") if parseable

    def get_line(self, line_number: int) -> Optional[str]:
        return self.line_to_content.get(line_number)


class ContextAggregator:
    """Builds project and file context; caches project signature per root (one read per project)."""

    WEB_DEPS = {"flask", "django", "fastapi"}
    FRAMEWORK_FILES = ("urls.py", "views.py", "routes.py", "app.py")
    ENTRY_DECORATORS = re.compile(
        r"@\s*(app\.route|router\.(get|post|put|delete|patch)|api\.(get|post|put|delete|patch))\s*\(",
        re.IGNORECASE,
    )
    ROUTE_PATH = re.compile(r'@\s*app\.route\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
    MAIN_GUARD = re.compile(r'if\s+__name__\s*==\s*["\']__main__["\']', re.IGNORECASE)

    def __init__(self, project_root: str) -> None:
        self._project_root = Path(project_root)
        self._project_context: Optional[ProjectContext] = None

    def get_project_context(self) -> ProjectContext:
        if self._project_context is not None:
            return self._project_context
        is_web = False
        is_lib = False
        has_views = False
        has_pkg = (self._project_root / "package.json").exists()
        req = self._project_root / "requirements.txt"
        if req.exists():
            try:
                text = req.read_text(encoding="utf-8", errors="ignore").lower()
                for dep in self.WEB_DEPS:
                    if dep in text:
                        is_web = True
                        break
            except Exception:
                pass
        pyproject = self._project_root / "pyproject.toml"
        if pyproject.exists():
            try:
                text = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
                for dep in self.WEB_DEPS:
                    if dep in text:
                        is_web = True
                        break
                if "[tool.poetry]" in text or "[project]" in text:
                    is_lib = True
            except Exception:
                pass
        for name in self.FRAMEWORK_FILES:
            if (self._project_root / name).exists():
                has_views = True
                break
        if not is_web and has_views:
            is_web = True
        self._project_context = ProjectContext(
            is_web_app=is_web,
            is_library=is_lib,
            has_views_or_urls=has_views,
            has_package_json=has_pkg,
        )
        return self._project_context

    def build_file_context(self, file_path: str, code_content: str) -> FileContext:
        project_ctx = self.get_project_context()
        path_str = file_path.replace("\\", "/")
        is_test_file = "/tests/" in path_str or "/examples/" in path_str
        lines = code_content.splitlines()
        line_to_content = {i: line for i, line in enumerate(lines, 1)}
        imports: List[str] = []
        route_path: Optional[str] = None
        for line in lines:
            line_stripped = line.strip()
            if line_stripped.startswith("import ") or line_stripped.startswith("from "):
                if line_stripped.startswith("import "):
                    mod = line_stripped.split()[1].split(".")[0].split(",")[0].strip()
                else:
                    mod = line_stripped.split()[1].split(".")[0].strip()
                if mod:
                    imports.append(mod.lower())
            m = self.ROUTE_PATH.search(line)
            if m and route_path is None:
                route_path = m.group(1)
        is_entry = False
        for line in lines:
            if self.ENTRY_DECORATORS.search(line) or self.MAIN_GUARD.search(line):
                is_entry = True
                break
        return FileContext(
            file_path=file_path,
            imports=imports,
            is_entry_point=is_entry,
            is_test_file=is_test_file,
            line_to_content=line_to_content,
            project_context=project_ctx,
            route_path=route_path,
        )


class VerdictEngine:
    """
    Runs rules in fixed order. Unverified does NOT terminate: only
    Confirmed or Out-of-scope stop evaluation (so a later rule can override
    an earlier Unverified). Extensible via extra_rules.
    """

    def __init__(
        self,
        project_root: str,
        extra_rules: Optional[List[Any]] = None,
    ) -> None:
        self._aggregator = ContextAggregator(project_root)
        # Order: SQL and Input Validation before Taint so mitigations override reachability
        self._rules = [
            EnvironmentNeutralizerRule(),
            XSSContextRule(),
            SQLSanitizerRule(),
            InputValidationRule(),
            TaintReachabilityRule(),
            PatternOnlyFallbackRule(),
        ]
        if extra_rules:
            self._rules.extend(extra_rules)

    def run(
        self,
        findings: List[Any],
        file_path: str,
        code_content: str,
    ) -> List[FindingWithVerdict]:
        file_ctx = self._aggregator.build_file_context(file_path, code_content)
        result: List[FindingWithVerdict] = []
        for finding in findings:
            line_num = getattr(finding, "line_number", None)
            line_content = file_ctx.get_line(line_num) if line_num else None
            verdict: Optional[Verdict] = None
            for rule in self._rules:
                v = rule.evaluate(
                    finding, file_ctx, file_ctx.project_context, line_content
                )
                if v is not None:
                    verdict = v
                    # Terminate only on Confirmed or Out-of-scope; Unverified does not stop
                    if verdict.status in (
                        VerdictStatus.CONFIRMED,
                        VerdictStatus.OUT_OF_SCOPE,
                    ):
                        break
            if verdict is None:
                verdict = Verdict.unverified("No rule matched; default unverified.")
            result.append(FindingWithVerdict(finding=finding, verdict=verdict))
        return result
