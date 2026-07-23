"""Common cross-component integration event envelope + hash chain.

This is the Phase-1 "common event schema" adopted by the integration flow. The
chaining mirrors the Go ``platform/audit.Chain`` algorithm — sha256 over the
canonical JSON of the record with its ``hash`` field zeroed, ``prev_hash``
linkage seeded at ``"genesis"`` — so the event stream is tamper-evident and
consistent in spirit across languages. The envelope is documented in
``platform/schemas/integration_event.schema.json``.

Each component keeps its own domain audit trail; this chain is the
control-plane record of cross-component events (one entry per integration
step), which is what makes the flow auditable end to end.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

GENESIS = "genesis"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_event(
    type: str,
    source: str,
    action: str,
    subject: Optional[str] = None,
    refs: Optional[dict[str, Any]] = None,
    **data: Any,
) -> dict[str, Any]:
    """Build an integration event (prev_hash/hash are filled by EventChain)."""
    return {
        "id": str(uuid.uuid4()),
        "time": _now(),
        "type": type,
        "source": source,
        "action": action,
        "subject": subject,
        "refs": refs or {},
        "data": data,
        "prev_hash": "",
        "hash": "",
    }


def _digest(record: dict[str, Any]) -> str:
    tmp = dict(record)
    tmp["hash"] = ""
    return hashlib.sha256(json.dumps(tmp, sort_keys=True).encode()).hexdigest()


class EventChain:
    """Append-only, hash-chained log of integration events."""

    def __init__(self) -> None:
        self.prev = GENESIS
        self.events: list[dict[str, Any]] = []

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        event["prev_hash"] = self.prev
        event["hash"] = _digest(event)
        self.prev = event["hash"]
        self.events.append(event)
        return event

    def verify(self) -> bool:
        prev = GENESIS
        for event in self.events:
            if event["prev_hash"] != prev or _digest(event) != event["hash"]:
                return False
            prev = event["hash"]
        return True

    def __len__(self) -> int:
        return len(self.events)
