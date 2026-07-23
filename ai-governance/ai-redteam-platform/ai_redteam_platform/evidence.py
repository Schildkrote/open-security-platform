"""Evidence store: redacted, hashed, hash-chained, with retention controls.

By default we do NOT store raw prompts/outputs (they may contain sensitive
data). We store redacted copies plus a content hash for integrity.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import uuid
from typing import Any

_REDACTORS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("OPENAI_KEY", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
]


def redact(text: str) -> str:
    out = text
    for name, pattern in _REDACTORS:
        out = pattern.sub(f"[REDACTED:{name}]", out)
    return out


def _hash(content: str, prev: str) -> str:
    return hashlib.sha256(f"{prev}|{content}".encode()).hexdigest()


def store_evidence(
    conn: sqlite3.Connection,
    campaign_id: str,
    case_id: str,
    target_id: str,
    prompt: str,
    response: str,
    passed: bool,
    reason: str,
) -> dict[str, Any]:
    prompt_r = redact(prompt)
    response_r = redact(response)
    content = f"{prompt_r}\n{response_r}"
    sha = hashlib.sha256(content.encode()).hexdigest()

    prev = conn.execute("SELECT hash FROM evidence ORDER BY rowid DESC LIMIT 1").fetchone()
    prev_hash = prev["hash"] if prev else "genesis"
    eid = str(uuid.uuid4())
    h = _hash(content, prev_hash)
    conn.execute(
        "INSERT INTO evidence (id,campaign_id,case_id,target_id,prompt_redacted,"
        "response_redacted,passed,reason,sha256,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (eid, campaign_id, case_id, target_id, prompt_r, response_r,
         1 if passed else 0, reason, sha, prev_hash, h),
    )
    conn.commit()
    return get_evidence(conn, eid)


def get_evidence(conn: sqlite3.Connection, eid: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    return dict(row) if row else None


def list_evidence(conn: sqlite3.Connection, campaign_id: str | None = None) -> list[dict[str, Any]]:
    if campaign_id:
        rows = conn.execute("SELECT * FROM evidence WHERE campaign_id=? ORDER BY rowid", (campaign_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM evidence ORDER BY rowid").fetchall()
    return [dict(r) for r in rows]


def verify_chain(conn: sqlite3.Connection) -> dict[str, Any]:
    prev = "genesis"
    for row in conn.execute("SELECT * FROM evidence ORDER BY rowid"):
        content = f"{row['prompt_redacted']}\n{row['response_redacted']}"
        if row["prev_hash"] != prev or row["hash"] != _hash(content, prev):
            return {"valid": False, "broken_at": row["id"]}
        prev = row["hash"]
    return {"valid": True}


def purge_older_than(conn: sqlite3.Connection, days: int) -> int:
    """Retention control: delete evidence older than `days` days."""
    cur = conn.execute("DELETE FROM evidence WHERE collected_at < datetime('now', ?)", (f"-{days} days",))
    conn.commit()
    return cur.rowcount
