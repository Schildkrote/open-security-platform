"""Evidence collection with a tamper-evident hash chain."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any, Optional


def _hash(content: str, prev_hash: str) -> str:
    return hashlib.sha256(f"{prev_hash}|{content}".encode()).hexdigest()


def collect_evidence(
    conn: sqlite3.Connection,
    content: str,
    control_id: Optional[str] = None,
    system_id: Optional[str] = None,
    source: Optional[str] = None,
) -> dict[str, Any]:
    prev = conn.execute(
        "SELECT hash FROM evidence ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    prev_hash = prev["hash"] if prev else "genesis"
    eid = str(uuid.uuid4())
    h = _hash(content, prev_hash)
    conn.execute(
        "INSERT INTO evidence (id,control_id,system_id,source,content,prev_hash,hash) "
        "VALUES (?,?,?,?,?,?,?)",
        (eid, control_id, system_id, source, content, prev_hash, h),
    )
    conn.commit()
    return get_evidence(conn, eid)


def get_evidence(conn: sqlite3.Connection, eid: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    return dict(row) if row else None


def list_evidence(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM evidence ORDER BY rowid")]


def verify_chain(conn: sqlite3.Connection) -> dict[str, Any]:
    """Re-walk the chain and confirm no record was tampered with."""
    prev_hash = "genesis"
    for row in conn.execute("SELECT * FROM evidence ORDER BY rowid"):
        expected = _hash(row["content"], prev_hash)
        if row["prev_hash"] != prev_hash or row["hash"] != expected:
            return {"valid": False, "broken_at": row["id"]}
        prev_hash = row["hash"]
    return {"valid": True, "count": len(list_evidence(conn))}
