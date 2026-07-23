"""Purple-team reporting: coverage dashboard + exercise results (Markdown)."""
from __future__ import annotations

from .coverage import coverage_matrix, coverage_percent, gaps, recommendations
from .exercise import ExerciseResult


def coverage_report(exercise: ExerciseResult | None = None) -> str:
    matrix = coverage_matrix()
    lines = [
        "# Purple Team Detection Coverage Report",
        "",
        f"**ATT&CK detection coverage:** {coverage_percent():.1%} "
        f"({sum(1 for r in matrix if r['status'] == 'detected')}/{len(matrix)} techniques)",
        "",
        "## Coverage matrix",
        "",
        "| Technique | Tactic | Status | Rules |",
        "|---|---|---|---|",
    ]
    for row in matrix:
        status = "DETECTED" if row["status"] == "detected" else "**GAP**"
        lines.append(f"| {row['technique_id']} {row['name']} | {row['tactic']} | {status} | {', '.join(row['rules']) or '-'} |")

    gap_list = gaps()
    lines += ["", "## Detection gaps", ""]
    if not gap_list:
        lines.append("_No gaps — every technique has a detection rule._")
    for g in gap_list:
        lines.append(f"- **{g['technique_id']} {g['name']}** ({g['tactic']}) — needs telemetry: {', '.join(g['data_sources'])}")

    recs = recommendations()
    lines += ["", "## Recommendations", ""]
    for r in recs:
        lines.append(f"- {r['action']}")

    if exercise:
        lines += [
            "",
            "## Exercise results",
            "",
            f"Ran **{exercise.total}** safe tests; **{exercise.detected} detected** "
            f"(detection rate {exercise.detection_rate:.1%}).",
            "",
            "| Technique | Test | Red action | Detected | Rules |",
            "|---|---|---|---|---|",
        ]
        for e in exercise.timeline:
            det = "yes" if e.detected else "**NO**"
            lines.append(f"| {e.technique_id} | {e.test_id} | `{e.red_action}` | {det} | {', '.join(e.rules_fired) or '-'} |")
        undetected = exercise.undetected()
        if undetected:
            lines += ["", "### Undetected during exercise", ""]
            for e in undetected:
                lines.append(f"- {e.technique_id} {e.technique_name} ({e.test_id})")

    return "\n".join(lines) + "\n"
