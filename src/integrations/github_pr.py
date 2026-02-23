"""
GitHub PR integration scaffolding: fetch PR changed files and post comments.

Thin wrapper around GitHub REST API. Requires GITHUB_TOKEN env var.
No persistence or heavy abstractions — intended for scripts and CI.
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

import json as _json
import urllib.error
import urllib.request


def _get_token() -> Optional[str]:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _api_request(
    method: str,
    url: str,
    token: Optional[str] = None,
    body: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Make a GitHub API request. Returns (json_response, error_message).
    Uses urllib only (no extra deps).
    """
    token = token or _get_token()
    if not token:
        return None, "GITHUB_TOKEN or GH_TOKEN not set"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url,
        data=_json.dumps(body).encode() if body else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = resp.read().decode()
            return (_json.loads(data) if data else {}), None
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode()
        except Exception:
            err_body = ""
        return None, f"HTTP {e.code}: {err_body}"
    except Exception as e:
        return None, str(e)


def get_pr_changed_files(
    repo: str,
    pr_number: int,
    token: Optional[str] = None,
) -> List[Tuple[str, str, Optional[str]]]:
    """
    Fetch changed files for a PR. Returns list of (filename, patch, content).

    repo: "owner/repo"
    pr_number: pull request number
    token: optional; otherwise uses GITHUB_TOKEN / GH_TOKEN

    Each patch is the unified diff fragment for that file. Content is the file
    body at the PR head (for scanning); None if not fetched or not text.
    """
    token = token or _get_token()
    if not token:
        logger.warning("No GitHub token; cannot fetch PR files")
        return []

    # Get PR to find head sha
    base = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    pr_data, err = _api_request("GET", base, token=token)
    if err or not pr_data:
        logger.warning("Failed to fetch PR: %s", err)
        return []
    head_sha = pr_data.get("head", {}).get("sha")
    if not head_sha:
        logger.warning("No head sha in PR response")
        return []

    # Get files and patches
    files_url = f"{base}/files"
    files_data, err = _api_request("GET", files_url, token=token)
    if err or not isinstance(files_data, list):
        logger.warning("Failed to fetch PR files: %s", err)
        return []

    result: List[Tuple[str, str, Optional[str]]] = []
    for f in files_data:
        filename = f.get("filename", "")
        patch = f.get("patch") or ""
        status = f.get("status", "")
        # Only include files that have a patch (text diff)
        if not patch:
            result.append((filename, "", None))
            continue
        # Optionally fetch file content at head for scanning
        content = None
        if filename and status != "removed":
            content_url = (
                f"https://api.github.com/repos/{repo}/contents/{filename}?ref={head_sha}"
            )
            content_data, content_err = _api_request("GET", content_url, token=token)
            if not content_err and content_data and "content" in content_data:
                import base64 as _b64
                try:
                    content = _b64.b64decode(content_data["content"]).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    pass
        result.append((filename, patch, content))
    return result


def post_pr_comment(
    repo: str,
    pr_number: int,
    body: str,
    token: Optional[str] = None,
) -> Optional[str]:
    """
    Post a comment on a PR. Returns comment URL on success, None on failure.
    """
    token = token or _get_token()
    if not token:
        logger.warning("No GitHub token; cannot post comment")
        return None
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data, err = _api_request("POST", url, token=token, body={"body": body})
    if err:
        logger.warning("Failed to post PR comment: %s", err)
        return None
    return data.get("html_url")


def format_findings_for_comment(
    findings: List[Dict[str, Any]],
    file_name: str,
    max_items: int = 20,
    include_header: bool = True,
) -> str:
    """
    Format a list of finding dicts (with evidence) as a Markdown PR comment body.
    Thin formatter; no HTML. Caps at max_items.
    include_header: if True, add "## Open Nazca..." and file/findings count.
    """
    lines = []
    if include_header:
        lines.extend([
            "## Open Nazca Security Scan",
            f"**File:** `{file_name}`",
            f"**Findings:** {len(findings)}",
            "",
        ])
    if not findings:
        lines.append("No issues reported." if include_header else f"**{file_name}:** No issues.")
        return "\n".join(lines)
    lines.append(f"### `{file_name}` — {len(findings)} finding(s)")
    lines.append("")

    for i, f in enumerate(findings[:max_items], 1):
        vuln = f.get("vulnerability_type", "Finding")
        severity = f.get("severity", "?")
        line_num = f.get("line_number", "?")
        ev = f.get("evidence", {})
        summary = ev.get("evidence_summary") or (
            f"{f.get('verdict_status', '')} | {f.get('reachability_status', '')}"
        )
        lines.append(f"### {i}. {vuln} (`{severity}`) — Line {line_num}")
        lines.append(f"- {summary}")
        if f.get("description"):
            lines.append(f"- {f['description'][:200]}...")
        lines.append("")
    if len(findings) > max_items:
        lines.append(f"_… and {len(findings) - max_items} more._")
    return "\n".join(lines)
