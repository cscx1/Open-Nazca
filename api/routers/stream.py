import asyncio
import json
import logging

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from api.config.job_store import get_job

router = APIRouter()
logger = logging.getLogger(__name__)

_SSE_TIMEOUT = 30.0  # seconds before sending a keepalive ping


async def _event_generator(job_id: str):
    job = get_job(job_id)
    if not job:
        yield f"data: {json.dumps({'type': 'error', 'message': 'Job not found'})}\n\n"
        return

    # Replay any events that arrived before the client connected
    for event in list(job.events):
        yield f"data: {json.dumps(event)}\n\n"
        if event.get("type") in ("complete", "error"):
            return

    # Stream live events
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


@router.get("/{job_id}/stream")
async def stream_scan(job_id: str) -> StreamingResponse:
    return StreamingResponse(
        _event_generator(job_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
