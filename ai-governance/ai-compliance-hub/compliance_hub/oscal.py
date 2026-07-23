"""OSCAL (NIST) import/export for the compliance hub (Phase 4).

Exports the control library as an OSCAL catalog and collected evidence as OSCAL
assessment-results; imports controls from an OSCAL catalog. Uses a pragmatic
subset of OSCAL 1.1.2 (catalog + assessment-results) — enough to interoperate
with OSCAL tooling while staying stdlib-only.
"""
from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from . import controls, evidence

OSCAL_VERSION = "1.1.2"


def _meta(title: str) -> dict[str, Any]:
    return {
        "title": title,
        "last-modified": "1970-01-01T00:00:00Z",
        "version": "0.1.0",
        "oscal-version": OSCAL_VERSION,
    }


def export_catalog(conn: sqlite3.Connection, title: str = "AI Control Catalog") -> dict[str, Any]:
    """Export the control library as an OSCAL catalog (controls grouped by family)."""
    by_family: dict[str, list[dict[str, Any]]] = {}
    for control in controls.list_controls(conn):
        oscal_control: dict[str, Any] = {
            "id": control["id"],
            "title": control["title"],
            "props": [
                {"name": f"mapping:{fw}", "value": ref}
                for fw, refs in (control.get("mappings") or {}).items()
                for ref in refs
            ],
        }
        if control.get("description"):
            oscal_control["parts"] = [{"name": "description", "prose": control["description"]}]
        by_family.setdefault(control.get("family") or "General", []).append(oscal_control)
    groups = [
        {"id": family.lower().replace(" ", "-"), "title": family, "controls": ctrls}
        for family, ctrls in by_family.items()
    ]
    return {"catalog": {"uuid": str(uuid.uuid4()), "metadata": _meta(title), "groups": groups}}


def import_catalog(conn: sqlite3.Connection, catalog: dict[str, Any]) -> int:
    """Import controls from an OSCAL catalog; returns the number imported."""
    root = catalog.get("catalog", catalog)
    count = 0
    for group in root.get("groups", []):
        family = group.get("title")
        for control in group.get("controls", []):
            mappings: dict[str, list[str]] = {}
            for prop in control.get("props", []):
                name = prop.get("name", "")
                if name.startswith("mapping:"):
                    mappings.setdefault(name[len("mapping:") :], []).append(prop.get("value", ""))
            description = None
            for part in control.get("parts", []):
                if part.get("name") == "description":
                    description = part.get("prose")
            controls.add_control(
                conn,
                title=control.get("title", "Untitled"),
                family=family,
                description=description,
                mappings=mappings,
            )
            count += 1
    return count


def export_assessment_results(
    conn: sqlite3.Connection, title: str = "AI Compliance Assessment"
) -> dict[str, Any]:
    """Export collected evidence as OSCAL assessment-results (observations)."""
    observations = [
        {
            "uuid": ev["id"],
            "description": ev.get("content") or "",
            "methods": ["TEST"],
            "props": [
                {"name": "source", "value": ev.get("source") or ""},
                {"name": "control-id", "value": ev.get("control_id") or ""},
            ],
        }
        for ev in evidence.list_evidence(conn)
    ]
    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": _meta(title),
            "results": [
                {"uuid": str(uuid.uuid4()), "title": title, "observations": observations}
            ],
        }
    }
