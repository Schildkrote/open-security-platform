"""Tamper-evident audit trail for every red-team action."""
from __future__ import annotations

import hashlib
import json
from typing import Any


class AuditLog:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._prev = "genesis"

    def log(self, event: str, **fields: Any) -> dict[str, Any]:
        entry = {"event": event, **fields, "prev_hash": self._prev}
        entry["hash"] = hashlib.sha256(
            f"{self._prev}|{json.dumps(entry, sort_keys=True, default=str)}".encode()
        ).hexdigest()
        self._prev = entry["hash"]
        self.records.append(entry)
        return entry

    def verify(self) -> bool:
        prev = "genesis"
        for entry in self.records:
            check = {k: v for k, v in entry.items() if k != "hash"}
            expected = hashlib.sha256(
                f"{prev}|{json.dumps(check, sort_keys=True, default=str)}".encode()
            ).hexdigest()
            if entry["prev_hash"] != prev or entry["hash"] != expected:
                return False
            prev = entry["hash"]
        return True
