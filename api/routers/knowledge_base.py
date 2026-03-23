import asyncio
import logging

from fastapi import APIRouter, HTTPException, UploadFile, File

from api.services import rag_service

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("")
async def list_documents():
    """Return all documents currently indexed in the knowledge base."""
    try:
        files = await asyncio.to_thread(rag_service.list_documents)
        return {"files": files}
    except Exception as exc:
        logger.error("Failed to list knowledge-base documents: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list documents")


@router.post("")
async def upload_document(file: UploadFile = File(...)):
    """Index a new document into the knowledge base."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    try:
        content = await file.read()
        message = await asyncio.to_thread(rag_service.add_document, content, file.filename)
        return {"success": True, "filename": file.filename, "message": message}
    except Exception as exc:
        logger.error("Failed to add document '%s': %s", file.filename, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to upload document")


@router.delete("/{filename}")
async def delete_document(filename: str):
    """Remove a document from the knowledge base."""
    try:
        message = await asyncio.to_thread(rag_service.delete_document, filename)
        return {"success": True, "message": message}
    except Exception as exc:
        logger.error("Failed to delete document '%s': %s", filename, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete document")
