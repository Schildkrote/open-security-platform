"""AI system inventory and risk register."""
from __future__ import annotations

import sqlite3
import uuid
from typing import Any, Optional

RISK_LEVELS = ("low", "medium", "high", "critical")


def register_system(
    conn: sqlite3.Connection,
    name: str,
    owner: Optional[str] = None,
    system_type: Optional[str] = None,
    risk_level: str = "medium",
    description: Optional[str] = None,
    status: str = "inventory",
) -> dict[str, Any]:
    if risk_level not in RISK_LEVELS:
        raise ValueError(f"risk_level must be one of {RISK_LEVELS}")
    sid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO systems (id,name,owner,system_type,risk_level,status,description) "
        "VALUES (?,?,?,?,?,?,?)",
        (sid, name, owner, system_type, risk_level, status, description),
    )
    conn.commit()
    return get_system(conn, sid)


def get_system(conn: sqlite3.Connection, sid: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM systems WHERE id=?", (sid,)).fetchone()
    return dict(row) if row else None


def list_systems(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM systems ORDER BY name")]


def add_risk(
    conn: sqlite3.Connection,
    title: str,
    system_id: Optional[str] = None,
    category: Optional[str] = None,
    likelihood: int = 3,
    impact: int = 3,
    mitigation: Optional[str] = None,
) -> dict[str, Any]:
    rid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO risks (id,system_id,title,category,likelihood,impact,mitigation) "
        "VALUES (?,?,?,?,?,?,?)",
        (rid, system_id, title, category, likelihood, impact, mitigation),
    )
    conn.commit()
    return get_risk(conn, rid)


def get_risk(conn: sqlite3.Connection, rid: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM risks WHERE id=?", (rid,)).fetchone()
    return dict(row) if row else None


def list_risks(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM risks ORDER BY (likelihood*impact) DESC").fetchall()
    return [dict(r) for r in rows]


def risk_score(risk: dict[str, Any]) -> int:
    """Inherent risk score = likelihood x impact (1..25)."""
    return int(risk["likelihood"]) * int(risk["impact"])
