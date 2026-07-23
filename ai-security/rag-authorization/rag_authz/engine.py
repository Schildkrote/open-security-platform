"""Authorized retrieval middleware and overexposure detection."""
from __future__ import annotations

from dataclasses import dataclass, field

from .acl import DocumentStore, Sensitivity, User, can_access
from .audit import AuditLog
from .classify import classify
from .vectorstore import VectorStore


@dataclass
class RetrievalResult:
    results: list[tuple[str, float]] = field(default_factory=list)  # (doc_id, score)
    granted: int = 0
    denied: int = 0
    denied_ids: list[str] = field(default_factory=list)


class AuthorizedRetriever:
    """Enforces document-level ACLs around vector retrieval."""

    def __init__(self, docs: DocumentStore, vectors: VectorStore, audit: AuditLog | None = None) -> None:
        self.docs = docs
        self.vectors = vectors
        self.audit = audit or AuditLog()

    def retrieve(self, user: User, query: str, k: int = 5, candidate_factor: int = 5) -> RetrievalResult:
        candidates = self.vectors.search(query, k=k * candidate_factor)
        out = RetrievalResult()
        for doc_id, score in candidates:
            doc = self.docs.get(doc_id)
            if doc is None:
                continue
            if can_access(user, doc):
                out.results.append((doc_id, score))
                out.granted += 1
            else:
                out.denied += 1
                out.denied_ids.append(doc_id)
            if len(out.results) >= k:
                break
        self.audit.log(
            "retrieval",
            user=user.id,
            query=query,
            granted=out.granted,
            denied=out.denied,
            denied_ids=out.denied_ids,
        )
        return out


def detect_overexposure(docs: DocumentStore, users: list[User], broad_threshold: int = 3) -> list[dict]:
    """Find documents that are mislabeled or exposed to too many people."""
    issues: list[dict] = []
    for doc in docs.all():
        suggested, reasons = classify(doc.text)

        if suggested > doc.sensitivity:
            issues.append({
                "doc_id": doc.id,
                "issue": "under_classified",
                "labeled": doc.sensitivity.name,
                "suggested": suggested.name,
                "reasons": reasons,
            })
        if doc.sensitivity == Sensitivity.PUBLIC and suggested >= Sensitivity.CONFIDENTIAL:
            issues.append({
                "doc_id": doc.id,
                "issue": "sensitive_but_public",
                "suggested": suggested.name,
                "reasons": reasons,
            })

        audience = sum(1 for u in users if can_access(u, doc))
        if doc.sensitivity >= Sensitivity.CONFIDENTIAL and audience > broad_threshold:
            issues.append({
                "doc_id": doc.id,
                "issue": "broad_access",
                "audience": audience,
                "sensitivity": doc.sensitivity.name,
            })
    return issues
