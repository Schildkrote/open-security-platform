"""rag-authorization: document-level access control for RAG pipelines."""
from .acl import Document, DocumentStore, Sensitivity, User, can_access
from .audit import AuditLog
from .classify import classify
from .engine import AuthorizedRetriever, RetrievalResult, detect_overexposure
from .vectorstore import VectorStore, cosine, embed

__all__ = [
    "Sensitivity",
    "User",
    "Document",
    "DocumentStore",
    "can_access",
    "classify",
    "VectorStore",
    "embed",
    "cosine",
    "AuthorizedRetriever",
    "RetrievalResult",
    "detect_overexposure",
    "AuditLog",
]
