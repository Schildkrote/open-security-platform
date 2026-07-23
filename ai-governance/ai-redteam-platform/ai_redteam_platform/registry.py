"""Target registry: the AI systems under test and their authorization status."""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any, Optional

RISK_TIERS = ("low", "medium", "high", "critical")


def register_target(
    conn: sqlite3.Connection,
    name: str,
    provider: Optional[str] = None,
    app_type: Optional[str] = None,
    owner: Optional[str] = None,
    environment: Optional[str] = None,
    endpoint: Optional[str] = None,
    tools: Optional[list[str]] = None,
    data_sources: Optional[list[str]] = None,
    risk_tier: str = "medium",
    authorization: str = "unauthorized",
) -> dict[str, Any]:
    if risk_tier not in RISK_TIERS:
        raise ValueError(f"risk_tier must be one of {RISK_TIERS}")
    tid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO targets (id,name,provider,app_type,owner,environment,endpoint,"
        "tools,data_sources,risk_tier,authorization) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            tid, name, provider, app_type, owner, environment, endpoint,
            json.dumps(tools or []), json.dumps(data_sources or []), risk_tier, authorization,
        ),
    )
    conn.commit()
    return get_target(conn, tid)


def get_target(conn: sqlite3.Connection, tid: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
    if not row:
        return None
    t = dict(row)
    t["tools"] = json.loads(t["tools"])
    t["data_sources"] = json.loads(t["data_sources"])
    return t


def list_targets(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [get_target(conn, r["id"]) for r in conn.execute("SELECT id FROM targets ORDER BY name")]


def set_authorization(conn: sqlite3.Connection, tid: str, status: str) -> dict[str, Any]:
    """Authorization gate: a target must be 'authorized' before any test runs."""
    if status not in ("authorized", "unauthorized", "revoked"):
        raise ValueError("invalid authorization status")
    conn.execute("UPDATE targets SET authorization=? WHERE id=?", (status, tid))
    conn.commit()
    return get_target(conn, tid)
