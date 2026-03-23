import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from api.config import job_store
from api.services import sandbox_service

router = APIRouter()
logger = logging.getLogger(__name__)

_SSE_TIMEOUT = 30.0


@router.post("")
async def submit_sandbox(files: list[UploadFile]):
    """
    Accept one or more code files, queue a sandbox analysis job.
    Returns { jobId, status } immediately.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    file_contents: dict[str, bytes] = {}
    for upload in files:
        filename = upload.filename or f"file_{len(file_contents)}.txt"
        file_contents[filename] = await upload.read()

    job_id = str(uuid.uuid4())
    job_store.create_job(job_id)

    loop = asyncio.get_running_loop()
    asyncio.create_task(_run_sandbox_task(job_id, file_contents, loop))

    return {"jobId": job_id, "status": "queued"}


@router.get("/{job_id}/stream")
async def stream_sandbox(job_id: str) -> StreamingResponse:
    return StreamingResponse(
        _event_generator(job_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/{job_id}")
async def get_sandbox_status(job_id: str):
    job = job_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "jobId": job.job_id,
        "status": job.status,
        "error": job.error,
        "results": job.results if job.status == job_store.JobStatus.COMPLETE else None,
    }


async def _run_sandbox_task(
    job_id: str,
    file_contents: dict[str, bytes],
    loop: asyncio.AbstractEventLoop,
) -> None:
    job_store.update_job(job_id, status=job_store.JobStatus.RUNNING)
    try:
        results = await asyncio.to_thread(
            sandbox_service.run_sandbox, file_contents, job_id, loop
        )
        job_store.update_job(
            job_id,
            status=job_store.JobStatus.COMPLETE,
            results=results,
        )
    except Exception as exc:
        logger.error("Sandbox job %s failed: %s", job_id, exc, exc_info=True)
        job_store.update_job(
            job_id,
            status=job_store.JobStatus.ERROR,
            error="Sandbox failed — check server logs.",
        )
        job = job_store.get_job(job_id)
        if job:
            loop.call_soon_threadsafe(
                job.event_queue.put_nowait,
                {"type": "error", "message": "Sandbox failed. Check server logs."},
            )


async def _event_generator(job_id: str):
    job = job_store.get_job(job_id)
    if not job:
        yield f"data: {json.dumps({'type': 'error', 'message': 'Job not found'})}\n\n"
        return

    for event in list(job.events):
        yield f"data: {json.dumps(event)}\n\n"
        if event.get("type") in ("complete", "error"):
            return

    while True:
        try:
            event = await asyncio.wait_for(job.event_queue.get(), timeout=_SSE_TIMEOUT)
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") in ("complete", "error"):
                break
        except asyncio.TimeoutError:
            yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        except Exception as exc:
            logger.error("SSE generator error for job %s: %s", job_id, exc, exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'message': 'Stream error'})}\n\n"
            break
