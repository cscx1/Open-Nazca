"""
In-process job store for scan and sandbox jobs.

Current implementation:
    Jobs are stored in a plain dict in module scope. This works for a
    single-process, single-worker deployment (e.g. `uvicorn --workers 1`).

Scalability limitations to address before multi-worker or multi-instance deploys:
    - Dict is per-process. With multiple uvicorn workers (--workers N > 1) or
      multiple pods/containers, a job created in worker A is invisible to worker B.
    - No TTL / cleanup. Long-running deployments accumulate completed jobs
      indefinitely, leaking memory.
    - asyncio.Queue is not serializable; it must be recreated if a job is
      re-hydrated from external storage.

Recommended migration path:
    Replace `_jobs` with a Redis-backed store (e.g. via redis-py or aioredis).
    Job state becomes a hash; SSE events stream via a Redis pub/sub channel.
    The asyncio.Queue can be a local subscriber that receives messages from that
    channel, keeping the SSE route unchanged.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any
import asyncio


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class Job:
    job_id: str
    status: JobStatus = JobStatus.QUEUED
    results: Any = None
    error: str | None = None
    events: list[dict] = field(default_factory=list)
    # asyncio.Queue for SSE streaming — put_nowait called via call_soon_threadsafe from threads
    event_queue: asyncio.Queue = field(default_factory=asyncio.Queue)


_jobs: dict[str, Job] = {}


def create_job(job_id: str) -> Job:
    job = Job(job_id=job_id)
    _jobs[job_id] = job
    return job


def get_job(job_id: str) -> Job | None:
    return _jobs.get(job_id)


def update_job(job_id: str, **kwargs) -> None:
    job = _jobs.get(job_id)
    if job:
        for k, v in kwargs.items():
            setattr(job, k, v)
