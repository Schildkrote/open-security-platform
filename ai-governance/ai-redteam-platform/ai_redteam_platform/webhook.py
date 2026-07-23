"""Outbound integration-event webhook emitter (opt-in, stdlib only).

Builds events conforming to ``platform/schemas/integration_event.schema.json``
and POSTs them to configured subscriber URLs. Emission is best-effort: a missing
or failing subscriber never breaks the producing request. With no URLs configured
(the default) nothing is emitted, so existing offline behaviour is unchanged.
"""
from __future__ import annotations

import hashlib
import json
import threading
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

GENESIS = "genesis"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(event: dict[str, Any]) -> str:
    # Canonical form: compact, sorted-key, raw-UTF-8 JSON (matches the Go and
    # Node emitters so chains verify across languages).
    tmp = dict(event)
    tmp["hash"] = ""
    canonical = json.dumps(tmp, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


class Emitter:
    """Hash-chained outbound integration-event emitter."""

    def __init__(self, source: str, urls: Optional[list[str]] = None) -> None:
        self.source = source
        self.urls = list(urls or [])
        self._prev = GENESIS
        self._lock = threading.Lock()

    def emit(
        self,
        type: str,
        action: str,
        subject: Optional[str] = None,
        refs: Optional[dict[str, Any]] = None,
        **data: Any,
    ) -> Optional[dict[str, Any]]:
        """Build, chain and POST an event to every subscriber (best-effort)."""
        if not self.urls:
            return None
        with self._lock:
            event = {
                "id": str(uuid.uuid4()),
                "time": _now(),
                "type": type,
                "source": self.source,
                "action": action,
                "subject": subject,
                "refs": refs or {},
                "data": data,
                "prev_hash": self._prev,
                "hash": "",
            }
            event["hash"] = _digest(event)
            self._prev = event["hash"]
        payload = json.dumps(event).encode()
        for url in self.urls:
            try:
                req = urllib.request.Request(
                    url, data=payload, method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read()
            except Exception:  # noqa: BLE001 - a down subscriber must not break the producer
                pass
        return event
