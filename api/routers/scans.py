import json
import uuid
import asyncio
import logging
import os
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from api.core import job_store
from api.core.config import settings
from api.models.requests import ScanConfig
from api.services import scan_service

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("")
async def submit_scan(
    file: UploadFile = File(...),
    config: str = Form("{}"),
):
    """
    Accept a code file + JSON config, queue an async scan job.
    Returns { jobId, status } immediately.
    """
    try:
        config_data = json.loads(config)
    except json.JSONDecodeError:
        config_data = {}

    scan_config = ScanConfig.model_validate(config_data)

    job_id = str(uuid.uuid4())
    job_store.create_job(job_id)

    # Write upload to a temp file (cleaned up in the background task's finally block)
    temp_dir = Path(settings.temp_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(file.filename or "upload.txt").suffix or ".txt"
    temp_path = str(temp_dir / f"{job_id}{suffix}")

    content = await file.read()
    with open(temp_path, "wb") as fh:
        fh.write(content)

    loop = asyncio.get_running_loop()
    asyncio.create_task(_run_scan_task(job_id, temp_path, scan_config, loop))

    return {"jobId": job_id, "status": "queued"}


@router.get("/{job_id}")
async def get_scan_status(job_id: str):
    """Return current status and results (when complete) for a scan job."""
    job = job_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    response: dict = {
        "jobId": job.job_id,
        "status": job.status,
        "error": job.error,
        "results": None,
    }
    if job.status == job_store.JobStatus.COMPLETE and job.results:
        response["results"] = _shape_results(job.results)
    return response


async def _run_scan_task(
    job_id: str,
    file_path: str,
    config: ScanConfig,
    loop: asyncio.AbstractEventLoop,
) -> None:
    job_store.update_job(job_id, status=job_store.JobStatus.RUNNING)
    try:
        results = await asyncio.to_thread(
            scan_service.run_scan, file_path, config, job_id, loop
        )
        job_store.update_job(
            job_id,
            status=job_store.JobStatus.COMPLETE,
            results=results,
        )
    except Exception as exc:
        logger.error("Scan job %s failed: %s", job_id, exc, exc_info=True)
        job_store.update_job(
            job_id,
            status=job_store.JobStatus.ERROR,
            error="Scan failed — check server logs.",
        )
        job = job_store.get_job(job_id)
        if job:
            loop.call_soon_threadsafe(
                job.event_queue.put_nowait,
                {"type": "error", "message": "Scan failed. Check server logs."},
            )
    finally:
        try:
            os.unlink(file_path)
        except OSError:
            pass


def _shape_results(raw: dict) -> dict:
    """
    Normalise the raw results dict from AICodeScanner into the shape
    expected by ScanResults in web/lib/types.ts.
    """
    return {
        "scan_id": raw.get("scan_id", ""),
        "total_findings": raw.get("total_findings", 0),
        "severity_counts": raw.get("severity_counts", {}),
        "scan_duration_ms": raw.get("scan_duration_ms", 0),
        "findings": raw.get("findings", []),
        "report_paths": raw.get("report_paths") or None,
    }
