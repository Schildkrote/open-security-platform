"""Inbound integration-event webhook consumer (stdlib only).

Maps incoming integration events (``platform/schemas/integration_event.schema.json``)
onto compliance-hub domain actions. Currently consumes ``finding.created`` by
recording the finding as tamper-evident evidence, auto-provisioning a system and
control the first time. Unknown event types are ignored (acked, no-op).
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import controls, evidence, models

SYSTEM_NAME = "AI Red-Team Targets"
CONTROL_TITLE = "AI Red-Team Evidence"


def _ensure_system(conn: sqlite3.Connection) -> dict[str, Any]:
    for system in models.list_systems(conn):
        if system["name"] == SYSTEM_NAME:
            return system
    return models.register_system(
        conn,
        name=SYSTEM_NAME,
        system_type="ai",
        risk_level="high",
        description="AI systems evaluated by red-team campaigns (auto-provisioned via webhook).",
    )


def _ensure_control(conn: sqlite3.Connection) -> dict[str, Any]:
    for control in controls.list_controls(conn):
        if control["title"] == CONTROL_TITLE:
            return control
    return controls.add_control(
        conn,
        title=CONTROL_TITLE,
        family="Assurance",
        description="Evidence captured from AI red-team findings (auto-provisioned via webhook).",
        mappings={"NIST_AI_RMF": ["MANAGE-3"], "EU_AI_ACT": ["Article 12"]},
    )


def _finding_to_content(finding: dict[str, Any]) -> str:
    return json.dumps(
        {
            "case_id": finding.get("case_id"),
            "name": finding.get("name"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "reason": finding.get("reason"),
            "owasp": finding.get("owasp", []),
            "atlas": finding.get("atlas", []),
            "compliance": finding.get("compliance", {}),
        },
        sort_keys=True,
    )


def consume_event(conn: sqlite3.Connection, event: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply an inbound integration event; return any evidence rows created."""
    if event.get("type") != "finding.created":
        return []
    finding = (event.get("data") or {}).get("finding") or {}
    if not finding:
        return []
    system = _ensure_system(conn)
    control = _ensure_control(conn)
    row = evidence.collect_evidence(
        conn,
        content=_finding_to_content(finding),
        control_id=control["id"],
        system_id=system["id"],
        source=event.get("source", "pentest-manager"),
    )
    return [row]
