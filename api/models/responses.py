from pydantic import BaseModel
from typing import Any


class ScanJobResponse(BaseModel):
    job_id: str
    status: str


class FindingResponse(BaseModel):
    vulnerability_type: str
    severity: str
    line_number: int | str
    description: str
    detector_name: str
    verdict_status: str | None = None
    verdict_reason: str | None = None
    code_snippet: str | None = None
    risk_explanation: str | None = None
    suggested_fix: str | None = None
    reachability_status: str | None = None
    reachability_reasoning: str | None = None
    attack_path: dict | None = None
    sink_api: str | None = None
    confidence: float | None = None
    cwe_id: str | None = None


class ScanResultsResponse(BaseModel):
    scan_id: str
    total_findings: int
    severity_counts: dict[str, int]
    scan_duration_ms: int
    findings: list[FindingResponse]
    report_paths: dict[str, str] | None = None


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    results: ScanResultsResponse | None = None
    error: str | None = None
