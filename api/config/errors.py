import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException

logger = logging.getLogger(__name__)


def register(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        logger.error("ValueError at %s: %s", request.url.path, exc, exc_info=True)
        return JSONResponse(status_code=400, content={"error": str(exc)})

    @app.exception_handler(FileNotFoundError)
    async def file_not_found_handler(request: Request, exc: FileNotFoundError) -> JSONResponse:
        logger.error("FileNotFoundError at %s: %s", request.url.path, exc, exc_info=True)
        return JSONResponse(status_code=404, content={"error": "Resource not found"})

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled exception at %s: %s", request.url.path, exc, exc_info=True)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})
