"""Seed sample targets into the registry."""
from __future__ import annotations

import sys

from .db import file_db
from .registry import register_target, set_authorization


def seed(directory: str = ".") -> None:
    conn = file_db(directory)
    guarded = register_target(
        conn, name="Guarded Assistant", provider="internal", app_type="llm-chatbot",
        owner="ML Platform", environment="staging", risk_tier="medium",
    )
    unguarded = register_target(
        conn, name="Legacy Assistant", provider="internal", app_type="llm-chatbot",
        owner="ML Platform", environment="staging", risk_tier="high",
    )
    range_app = register_target(
        conn, name="Range: Vulnerable Chatbot", provider="range", app_type="llm-chatbot",
        owner="Security", environment="lab", endpoint="http://localhost:8091",
        tools=["search"], data_sources=["kb"], risk_tier="high",
    )
    # Authorize the lab/guarded targets for testing.
    set_authorization(conn, guarded["id"], "authorized")
    set_authorization(conn, range_app["id"], "authorized")
    print(f"Seeded targets into {directory}/ai_redteam.db:")
    print(f"  guarded   = {guarded['id']}")
    print(f"  unguarded = {unguarded['id']} (unauthorized)")
    print(f"  range     = {range_app['id']} (endpoint http://localhost:8091)")


if __name__ == "__main__":
    seed(sys.argv[1] if len(sys.argv) > 1 else ".")
