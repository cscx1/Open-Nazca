import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import scans, stream, sandbox, knowledge_base, reports
from api.core.config import settings
from api.core import errors

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)

app = FastAPI(title="Open Nazca API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

errors.register(app)

# All routes are namespaced under /api to match the Next.js proxy paths.
app.include_router(scans.router,          prefix="/api/scans",          tags=["scans"])
app.include_router(stream.router,         prefix="/api/scans",          tags=["scans"])
app.include_router(sandbox.router,        prefix="/api/sandbox",        tags=["sandbox"])
app.include_router(knowledge_base.router, prefix="/api/knowledge-base", tags=["knowledge-base"])
app.include_router(reports.router,        prefix="/api/reports",        tags=["reports"])


@app.get("/health", tags=["meta"])
async def health():
    return {"status": "ok"}
