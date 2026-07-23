"""Seed the control library and a sample AI system."""
from __future__ import annotations

import sys

from .controls import DEFAULT_CONTROLS, add_control
from .db import file_db
from .models import add_risk, register_system


def seed(directory: str = ".") -> None:
    conn = file_db(directory)
    for ctrl in DEFAULT_CONTROLS:
        add_control(conn, **ctrl)

    system = register_system(
        conn,
        name="Support Chatbot",
        owner="ML Platform Team",
        system_type="LLM application",
        risk_level="high",
        description="Customer-facing support assistant with RAG over internal docs.",
    )
    add_risk(
        conn,
        title="Prompt injection via customer input",
        system_id=system["id"],
        category="Security",
        likelihood=4,
        impact=4,
        mitigation="Input/output guardrails and tool allowlisting.",
    )
    add_risk(
        conn,
        title="PII leakage from RAG corpus",
        system_id=system["id"],
        category="Privacy",
        likelihood=3,
        impact=5,
        mitigation="Document-level ACLs and redaction.",
    )
    print(f"Seeded {len(DEFAULT_CONTROLS)} controls and 1 sample system into {directory}/compliance.db")


if __name__ == "__main__":
    seed(sys.argv[1] if len(sys.argv) > 1 else ".")
