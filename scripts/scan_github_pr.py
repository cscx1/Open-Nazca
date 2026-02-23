#!/usr/bin/env python3
"""
Scan a GitHub PR: fetch changed files, run Open Nazca with diff scope, post one comment.

Usage:
  GITHUB_TOKEN=xxx python scripts/scan_github_pr.py --repo owner/repo --pr 123

Optional:
  --no-comment   Only run scan and print results (do not post)
  --no-llm       Disable LLM analysis (faster)
  --language py  Only scan these extensions (default: py). Comma-separated.

No persistence; thin layer on scanner + integrations.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

# Add project root for imports
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

from src.integrations.github_pr import (
    get_pr_changed_files,
    post_pr_comment,
    format_findings_for_comment,
)
from src.scanner import AICodeScanner


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan GitHub PR with Open Nazca")
    parser.add_argument("--repo", required=True, help="Repository: owner/repo")
    parser.add_argument("--pr", type=int, required=True, help="Pull request number")
    parser.add_argument(
        "--no-comment",
        action="store_true",
        help="Do not post comment; only print results",
    )
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM analysis")
    parser.add_argument(
        "--language",
        type=str,
        default="py",
        help="Comma-separated file extensions to scan (default: py)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logs")
    args = parser.parse_args()

    if not os.environ.get("GITHUB_TOKEN") and not os.environ.get("GH_TOKEN"):
        print("Set GITHUB_TOKEN or GH_TOKEN to run PR scan.")
        return 1

    extensions = {e.strip().lstrip(".") for e in args.language.split(",")}
    files_with_patches = get_pr_changed_files(args.repo, args.pr)
    if not files_with_patches:
        print("No changed files or failed to fetch PR.")
        return 1

    # Filter to scanable extensions
    to_scan = [
        (fn, patch, content)
        for fn, patch, content in files_with_patches
        if content is not None and Path(fn).suffix.lstrip(".") in extensions
    ]
    if not to_scan:
        print("No scanable files (e.g. .py) in PR.")
        return 0

    scanner = AICodeScanner(use_snowflake=False, use_llm_analysis=not args.no_llm)
    all_results: list[tuple[str, list]] = []  # (file_name, findings_dicts)

    with tempfile.TemporaryDirectory() as tmpdir:
        for filename, patch, content in to_scan:
            if not content:
                continue
            # Write file under tmpdir preserving path (e.g. src/foo.py)
            full_path = Path(tmpdir) / filename
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8", errors="replace")
            try:
                result = scanner.scan_file(
                    str(full_path),
                    generate_reports=False,
                    diff_text=patch if patch else None,
                    path_in_diff=filename,
                )
            except Exception as e:
                print(f"Scan failed for {filename}: {e}", file=sys.stderr)
                continue
            if result.get("success") and result.get("findings"):
                all_results.append((filename, result["findings"]))

    if not all_results:
        body = (
            "## Open Nazca Security Scan\n\n"
            "No findings in changed lines for scanned files."
        )
    else:
        sections = ["## Open Nazca Security Scan", ""]
        for file_name, findings in all_results:
            sections.append(format_findings_for_comment(findings, file_name, include_header=False))
            sections.append("")
        body = "\n".join(sections)

    print(body)
    if not args.no_comment and body:
        url = post_pr_comment(args.repo, args.pr, body)
        if url:
            print(f"Comment posted: {url}")
        else:
            print("Failed to post comment.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
