"""AI control library and cross-framework mapping engine."""
from __future__ import annotations

import sqlite3
import uuid
from typing import Any, Optional


def add_control(
    conn: sqlite3.Connection,
    title: str,
    family: Optional[str] = None,
    description: Optional[str] = None,
    mappings: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    cid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO controls (id,title,family,description) VALUES (?,?,?,?)",
        (cid, title, family, description),
    )
    for framework, refs in (mappings or {}).items():
        for ref in refs:
            conn.execute(
                "INSERT OR IGNORE INTO control_mappings (control_id,framework,reference) "
                "VALUES (?,?,?)",
                (cid, framework, ref),
            )
    conn.commit()
    return get_control(conn, cid)


def get_control(conn: sqlite3.Connection, cid: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM controls WHERE id=?", (cid,)).fetchone()
    if not row:
        return None
    ctrl = dict(row)
    ctrl["mappings"] = mappings_for(conn, cid)
    return ctrl


def mappings_for(conn: sqlite3.Connection, cid: str) -> dict[str, list[str]]:
    rows = conn.execute(
        "SELECT framework, reference FROM control_mappings WHERE control_id=?", (cid,)
    ).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        out.setdefault(r["framework"], []).append(r["reference"])
    return out


def list_controls(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [get_control(conn, r["id"]) for r in conn.execute("SELECT id FROM controls ORDER BY family, title")]


def controls_for_framework(conn: sqlite3.Connection, framework: str) -> list[dict[str, Any]]:
    """The control-mapping engine: one control -> many frameworks. Given a
    framework, return every control that maps to it."""
    rows = conn.execute(
        "SELECT DISTINCT c.id FROM controls c "
        "JOIN control_mappings m ON m.control_id=c.id WHERE m.framework=? "
        "ORDER BY c.family, c.title",
        (framework,),
    ).fetchall()
    return [get_control(conn, r["id"]) for r in rows]


# A small built-in AI control library mapped across EU AI Act, NIST AI RMF,
# ISO/IEC 42001 and SOC 2 (AI). Used by seed.py and tests.
DEFAULT_CONTROLS: list[dict[str, Any]] = [
    {
        "title": "AI System Inventory",
        "family": "Governance",
        "description": "Maintain a register of all AI systems with owners and risk levels.",
        "mappings": {
            "EU_AI_ACT": ["Article 9", "Annex IV"],
            "NIST_AI_RMF": ["GOVERN-1"],
            "ISO_42001": ["A.5.2"],
            "SOC2_AI": ["CC2.1"],
        },
    },
    {
        "title": "AI Risk Assessment",
        "family": "Risk",
        "description": "Perform and document risk assessments for AI systems.",
        "mappings": {
            "EU_AI_ACT": ["Article 9", "Article 15"],
            "NIST_AI_RMF": ["GOVERN-2", "MEASURE-2"],
            "ISO_42001": ["A.8.2"],
            "SOC2_AI": ["CC4.1"],
        },
    },
    {
        "title": "Data Governance & Quality",
        "family": "Data",
        "description": "Ensure training/validation data is relevant, representative and governed.",
        "mappings": {
            "EU_AI_ACT": ["Article 10"],
            "NIST_AI_RMF": ["MEASURE-1"],
            "ISO_42001": ["A.7.4"],
            "SOC2_AI": ["CC6.1"],
        },
    },
    {
        "title": "Human Oversight",
        "family": "Governance",
        "description": "Provide human oversight mechanisms for high-risk AI.",
        "mappings": {
            "EU_AI_ACT": ["Article 14"],
            "NIST_AI_RMF": ["GOVERN-5"],
            "ISO_42001": ["A.6.2"],
            "SOC2_AI": ["CC5.1"],
        },
    },
    {
        "title": "Logging & Traceability",
        "family": "Assurance",
        "description": "Record AI system activity for audit and incident response.",
        "mappings": {
            "EU_AI_ACT": ["Article 12"],
            "NIST_AI_RMF": ["MANAGE-3"],
            "ISO_42001": ["A.7.7"],
            "SOC2_AI": ["CC7.2"],
        },
    },
    {
        "title": "Incident Reporting",
        "family": "Assurance",
        "description": "Report serious AI incidents to authorities and affected parties.",
        "mappings": {
            "EU_AI_ACT": ["Article 62"],
            "NIST_AI_RMF": ["MANAGE-4"],
            "ISO_42001": ["A.8.6"],
            "SOC2_AI": ["CC7.3"],
        },
    },
]
