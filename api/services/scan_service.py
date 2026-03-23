"""
Thin adapter over src.scanner.AICodeScanner.
Only this file (and sandbox_service.py) are allowed to import from src/.
"""

import sys
import os
import logging
import asyncio

# Ensure the project root is on sys.path so src imports work.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.scanner import AICodeScanner  # noqa: E402
from api.models.requests import ScanConfig  # noqa: E402
from api.core.job_store import get_job  # noqa: E402

logger = logging.getLogger(__name__)


def run_scan(
    file_path: str,
    config: ScanConfig,
    job_id: str,
    loop: asyncio.AbstractEventLoop,
) -> dict:
    """
    Synchronous wrapper called via asyncio.to_thread().
    Pushes SSE-compatible progress events to the job's event_queue.
    Returns the raw results dict from AICodeScanner.
    """
    job = get_job(job_id)

    def push_event(event: dict) -> None:
        if job is not None:
            # list.append is GIL-protected — safe from any thread
            job.events.append(event)
            # Schedules put_nowait on the event loop thread
            loop.call_soon_threadsafe(job.event_queue.put_nowait, event)

    push_event({"type": "progress", "message": "Initializing scanner…", "pct": 10})

    scanner = AICodeScanner(
        use_snowflake=config.use_snowflake,
        use_llm_analysis=config.use_llm,
        llm_provider=config.llm_provider,
    )

    push_event({"type": "progress", "message": "Running vulnerability detectors…", "pct": 40})

    results = scanner.scan_file(
        file_path=file_path,
        scanned_by="web_user",
        generate_reports=True,
        report_formats=config.report_formats,
    )

    scanner.close()

    push_event({"type": "progress", "message": "Finalizing results…", "pct": 90})
    push_event({"type": "complete", "results": results})

    return results
