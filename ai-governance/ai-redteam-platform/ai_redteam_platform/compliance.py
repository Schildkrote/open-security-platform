"""Compliance mapping: relate test results to AI regulatory frameworks."""
from __future__ import annotations

from .engine import CaseOutcome
from .testlib import TestCase

FRAMEWORKS = ("EU_AI_ACT", "NIST_AI_RMF", "ISO_42001")


def compliance_coverage(cases: list[TestCase], outcomes: list[CaseOutcome]) -> dict[str, dict]:
    """For each framework, show which controls were tested and which have failures."""
    failed_ids = {o.case_id for o in outcomes if not o.passed}
    report: dict[str, dict] = {}

    for fw in FRAMEWORKS:
        tested: dict[str, dict] = {}  # control ref -> {cases, failing}
        for case in cases:
            for ref in case.compliance.get(fw, ()):  # type: ignore[union-attr]
                entry = tested.setdefault(ref, {"cases": [], "failing": []})
                entry["cases"].append(case.id)
                if case.id in failed_ids:
                    entry["failing"].append(case.id)
        controls = []
        for ref, entry in sorted(tested.items()):
            controls.append({
                "control": ref,
                "tested_cases": entry["cases"],
                "failing_cases": entry["failing"],
                "status": "fail" if entry["failing"] else "pass",
            })
        report[fw] = {
            "controls_tested": len(controls),
            "controls_failing": sum(1 for c in controls if c["status"] == "fail"),
            "controls": controls,
        }
    return report
