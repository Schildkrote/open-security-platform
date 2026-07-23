"""Detection coverage matrix, gap analysis, and tuning recommendations."""
from __future__ import annotations

from .attack import TECHNIQUES, Technique
from .detections import DETECTION_RULES, DetectionRule, rules_for_technique


def coverage_matrix(
    techniques: list[Technique] | None = None,
    rules: list[DetectionRule] | None = None,
) -> list[dict]:
    techniques = techniques if techniques is not None else TECHNIQUES
    rows = []
    for t in techniques:
        t_rules = [r for r in (rules or DETECTION_RULES) if r.technique_id == t.id]
        rows.append({
            "technique_id": t.id,
            "name": t.name,
            "tactic": t.tactic,
            "status": "detected" if t_rules else "gap",
            "rules": [r.id for r in t_rules],
            "data_sources": list(t.data_sources),
        })
    return rows


def gaps(techniques: list[Technique] | None = None, rules: list[DetectionRule] | None = None) -> list[dict]:
    return [row for row in coverage_matrix(techniques, rules) if row["status"] == "gap"]


def coverage_percent(techniques: list[Technique] | None = None, rules: list[DetectionRule] | None = None) -> float:
    matrix = coverage_matrix(techniques, rules)
    if not matrix:
        return 0.0
    detected = sum(1 for row in matrix if row["status"] == "detected")
    return round(detected / len(matrix), 4)


def recommendations(techniques: list[Technique] | None = None, rules: list[DetectionRule] | None = None) -> list[dict]:
    """For each gap, recommend the data sources to enable and a rule to write."""
    recs = []
    for t in (techniques or TECHNIQUES):
        if rules_for_technique(t.id):
            continue
        recs.append({
            "technique_id": t.id,
            "name": t.name,
            "tactic": t.tactic,
            "enable_data_sources": list(t.data_sources),
            "action": f"Author a detection rule for {t.name} ({t.id}) using {', '.join(t.data_sources)}.",
        })
    return recs
