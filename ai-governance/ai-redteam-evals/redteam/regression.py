"""Regression testing: compare a run against a stored baseline."""
from __future__ import annotations

import json

from .harness import EvalReport


def save_baseline(report: EvalReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({r.case_id: r.passed for r in report.results}, f, indent=2)


def load_baseline(path: str) -> dict[str, bool]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compare(report: EvalReport, baseline: dict[str, bool]) -> dict:
    """A regression is a case that passed in the baseline but fails now."""
    regressions, fixed = [], []
    current = {r.case_id: r.passed for r in report.results}
    for case_id, was_passing in baseline.items():
        now = current.get(case_id)
        if was_passing and now is False:
            regressions.append(case_id)
        elif not was_passing and now is True:
            fixed.append(case_id)
    return {"regressions": regressions, "fixed": fixed, "has_regression": bool(regressions)}
