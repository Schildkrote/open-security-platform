# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Hash-chained, tamper-evident biometric audit log (Python).

Mirrors the Go module in ``platform/biometric-audit``. The chain is the
product's compliance backbone: every face-touching operation (enrol, train,
match, scrape, revoke) appends one Entry carrying the lawful-basis decision,
retention expiry, and redaction status.

Stdlib-only, offline-safe. JSONL on disk, one entry per line.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


def pseudo(s: str) -> str:
    """Stable SHA-256 hex of s (subject pseudonym — never the raw name)."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class Entry:
    """One audit record (matches the Go Entry shape)."""

    seq: int = 0
    timestamp: float = 0.0
    action: str = ""
    subject_pseudo: str = ""
    component: str = ""
    basis_outcome: str = ""
    basis_reason: str = ""
    basis_purpose: str = ""
    retention_max_days: int = 0
    retention_expires: float = 0.0
    redacted: bool = True
    detail: str = ""
    prev_hash: str = ""
    hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


def hash_entry(e: Entry) -> str:
    """Hash of all entry fields except `hash` itself (Go hashEntry mirror)."""
    payload = {
        "seq": e.seq,
        "timestamp": e.timestamp,
        "action": e.action,
        "subject_pseudo": e.subject_pseudo,
        "component": e.component,
        "basis_outcome": e.basis_outcome,
        "basis_reason": e.basis_reason,
        "basis_purpose": e.basis_purpose,
        "retention_max_days": e.retention_max_days,
        "retention_expires": e.retention_expires,
        "redacted": e.redacted,
        "detail": e.detail,
        "prev_hash": e.prev_hash,
    }
    b = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


class AuditLog:
    """Append-only hash-chained audit log.

    In-memory by default; pass ``path`` to persist as JSONL (one entry per
    line). Chain: entry[i].prev_hash == entry[i-1].hash, entry[0].prev_hash == "".
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.entries: list[Entry] = []
        self.last_hash = ""
        if self.path is not None and self.path.exists():
            self._load()

    def _load(self) -> None:
        assert self.path is not None
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            self.entries.append(Entry.from_dict(json.loads(line)))
        if self.entries:
            self.last_hash = self.entries[-1].hash
            # Trust-but-verify existing chains on load.
            self.verify()

    def append(
        self,
        *,
        action: str,
        subject_pseudo: str = "",
        component: str = "",
        basis_outcome: str = "",
        basis_reason: str = "",
        basis_purpose: str = "",
        retention_max_days: int = 0,
        redacted: bool = True,
        detail: str = "",
    ) -> Entry:
        ts = time.time()
        e = Entry(
            seq=len(self.entries) + 1,
            timestamp=ts,
            action=action,
            subject_pseudo=subject_pseudo,
            component=component,
            basis_outcome=basis_outcome,
            basis_reason=basis_reason,
            basis_purpose=basis_purpose,
            retention_max_days=retention_max_days,
            retention_expires=(ts + retention_max_days * 86400) if retention_max_days > 0 else 0.0,
            redacted=redacted,
            detail=detail,
            prev_hash=self.last_hash,
        )
        e.hash = hash_entry(e)
        self.entries.append(e)
        self.last_hash = e.hash
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(e.to_dict(), sort_keys=True) + "\n")
        return e

    def all(self) -> list[Entry]:
        return list(self.entries)

    def verify(self) -> None:
        """Walk the chain; raise ValueError on the first break."""
        prev = ""
        for i, e in enumerate(self.entries):
            if e.prev_hash != prev:
                raise ValueError(f"chain break at seq {e.seq}: prev_hash mismatch")
            if e.hash != hash_entry(e):
                raise ValueError(f"chain break at seq {e.seq}: content hash mismatch")
            if i + 1 != e.seq:
                raise ValueError(f"chain break at index {i}: seq {e.seq} expected {i + 1}")
            prev = e.hash


__all__ = ["AuditLog", "Entry", "hash_entry", "pseudo"]