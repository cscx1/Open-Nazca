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


# Module-level store — replace with Redis later
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
