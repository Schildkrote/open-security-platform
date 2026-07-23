"""rag-authorization: document-level access control for RAG pipelines."""
from .acl import Sensitivity, User, Document, DocumentStore, can_access
from .classify import classify
from .vectorstore import VectorStore, embed, cosine
from .engine import AuthorizedRetriever, RetrievalResult, detect_overexposure
from .audit import AuditLog

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
