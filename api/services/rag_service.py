"""
Thin adapter over src.rag_manager.RAGManager.
Lazily initialises a single shared manager instance.
"""

import sys
import os
import logging

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.rag_manager import RAGManager  # noqa: E402

logger = logging.getLogger(__name__)

_manager: RAGManager | None = None


def get_manager() -> RAGManager:
    global _manager
    if _manager is None:
        _manager = RAGManager()
    return _manager


def add_document(content: bytes, filename: str) -> str:
    return get_manager().add_document(content, filename)


def list_documents() -> list[str]:
    return get_manager().list_documents()


def delete_document(filename: str) -> str:
    return get_manager().delete_document(filename)
