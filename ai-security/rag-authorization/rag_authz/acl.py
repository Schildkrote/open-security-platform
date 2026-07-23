"""Document ACLs, users, and sensitivity levels."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Sensitivity(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


@dataclass
class User:
    id: str
    groups: set[str] = field(default_factory=set)
    clearance: int = Sensitivity.INTERNAL  # max sensitivity the user may read


@dataclass
class Document:
    id: str
    text: str
    owner: str
    groups: set[str] = field(default_factory=set)  # groups granted access
    sensitivity: Sensitivity = Sensitivity.INTERNAL


class DocumentStore:
    def __init__(self) -> None:
        self._docs: dict[str, Document] = {}

    def add(self, doc: Document) -> Document:
        self._docs[doc.id] = doc
        return doc

    def get(self, doc_id: str) -> Document | None:
        return self._docs.get(doc_id)

    def all(self) -> list[Document]:
        return list(self._docs.values())


def can_access(user: User, doc: Document) -> bool:
    """Authorization rule: the user must be permitted (owner/group/public) AND
    hold sufficient clearance for the document's sensitivity."""
    if user.clearance < int(doc.sensitivity):
        return False
    if doc.sensitivity == Sensitivity.PUBLIC:
        return True
    if user.id == doc.owner:
        return True
    return bool(user.groups & doc.groups)
