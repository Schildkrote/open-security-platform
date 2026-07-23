"""Report rendering: JSON and Markdown."""
from __future__ import annotations

import json

from .harness import EvalReport


def to_json(report: EvalReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent)


def to_markdown(report: EvalReport) -> str:
    lines = [
        f"# AI Red Team Report — {report.target}",
        "",
        f"**Overall robustness score:** {report.score:.1%} ({report.passed}/{report.total} passed)",
        "",
        "## By category",
        "",
        "| Category | Passed | Total | Score |",
        "|---|---|---|---|",
    ]
    for cat, b in sorted(report.by_category().items()):
        lines.append(f"| {cat} | {int(b['passed'])} | {int(b['total'])} | {b['score']:.1%} |")

    lines += ["", "## Results", "", "| Case | Category | Result | Reason |", "|---|---|---|---|"]
    for r in report.results:
        status = "PASS" if r.passed else "**FAIL**"
        lines.append(f"| {r.case_id} {r.name} | {r.category} | {status} | {r.reason} |")

    lines.append("")
    return "\n".join(lines)
