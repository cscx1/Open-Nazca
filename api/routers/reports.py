import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from api.core import job_store

router = APIRouter()
logger = logging.getLogger(__name__)

_ALLOWED_FORMATS = frozenset({"json", "html", "markdown"})
_MIME = {
    "json": "application/json",
    "html": "text/html",
    "markdown": "text/markdown",
}


@router.get("/{scan_id}/{format}")
async def download_report(scan_id: str, format: str):
    """
    Stream a generated report file to the client.

    Security:
    - scan_id must correspond to a real completed job (never construct
      filesystem paths from raw user input).
    - format must be one of: json, html, markdown.
    """
    if format not in _ALLOWED_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format: {format!r}")

    # Resolve report path only from trusted job results
    job = job_store.get_job(scan_id)

    # scan_id may be either the job_id OR the internal scan_id stored in results.
    # Try job_id first, then fall back to searching by scan_id in results.
    if job is None:
        # Linear scan over in-memory store — acceptable at current scale
        for j in _all_jobs():
            if (
                j.status == job_store.JobStatus.COMPLETE
                and j.results
                and j.results.get("scan_id") == scan_id
            ):
                job = j
                break

    if job is None or job.status != job_store.JobStatus.COMPLETE:
        raise HTTPException(status_code=404, detail="Report not found")

    report_paths: dict = (job.results or {}).get("report_paths") or {}
    file_path_str = report_paths.get(format)

    if not file_path_str:
        raise HTTPException(status_code=404, detail=f"No {format} report for this scan")

    file_path = Path(file_path_str)
    if not file_path.is_file():
        logger.error("Report file missing on disk: %s", file_path)
        raise HTTPException(status_code=404, detail="Report file not found")

    ext = "md" if format == "markdown" else format
    return FileResponse(
        path=str(file_path),
        media_type=_MIME[format],
        filename=f"report_{scan_id}.{ext}",
    )


def _all_jobs():
    """Return all jobs from the in-memory store."""
    from api.core.job_store import _jobs
    return list(_jobs.values())
