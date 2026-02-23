"""
Evidence schema for Open Nazca findings.

Provides a single, consistent shape for evidence (reachability, verdict, path)
so that reports, API, and integrations can rely on one structure.
No persistence or storage — pure normalization of finding dicts.
"""

from __future__ import annotations

from typing import Any, Dict

# Canonical keys for the evidence block (single source of truth for outputs)
EVIDENCE_KEYS = (
    "reachability_status",
    "reachability_reasoning",
    "verdict_status",
    "verdict_reason",
    "attack_path",
    "sink_api",
    "evidence_summary",
)


def build_evidence_dict(finding_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a normalized evidence block from a finding dict (e.g. from FindingWithVerdict.to_dict()).

    Every output (JSON, PR comment, API) should use this block for consistency.
    Missing fields are omitted; evidence_summary is a one-line human summary.
    """
    evidence: Dict[str, Any] = {}
    if finding_dict.get("reachability_status") is not None:
        evidence["reachability_status"] = finding_dict["reachability_status"]
    if finding_dict.get("reachability_reasoning") is not None:
        evidence["reachability_reasoning"] = finding_dict["reachability_reasoning"]
    if finding_dict.get("verdict_status") is not None:
        evidence["verdict_status"] = finding_dict["verdict_status"]
    if finding_dict.get("verdict_reason") is not None:
        evidence["verdict_reason"] = finding_dict["verdict_reason"]
    if finding_dict.get("attack_path") is not None:
        evidence["attack_path"] = finding_dict["attack_path"]
    if finding_dict.get("sink_api") is not None:
        evidence["sink_api"] = finding_dict["sink_api"]

    summary = _evidence_summary_one_line(finding_dict)
    if summary:
        evidence["evidence_summary"] = summary

    return evidence


def _evidence_summary_one_line(finding_dict: Dict[str, Any]) -> str:
    """One-line summary for UI/PR: verdict + reachability + path hint."""
    parts = []
    v = finding_dict.get("verdict_status")
    if v:
        parts.append(v)
    r = finding_dict.get("reachability_status")
    if r:
        parts.append(r)
    ap = finding_dict.get("attack_path")
    if ap:
        src = ap.get("source", {})
        sink = ap.get("sink", {})
        parts.append(f"path: {src.get('name', '?')} → {sink.get('name', '?')}")
    return " | ".join(parts) if parts else ""


def with_evidence(finding_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy of the finding dict with an "evidence" key added.
    Use when preparing findings for JSON/reports/API so all outputs are evidence-centric.
    """
    out = dict(finding_dict)
    out["evidence"] = build_evidence_dict(finding_dict)
    return out
