"""Report generation: technical, executive, and compliance reports."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .scoring import CampaignScore


def _header(target: str, kind: str) -> list[str]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return [f"# AI Red Team {kind} Report", "", f"- **Target:** {target}", f"- **Generated:** {now}", ""]


def technical_report(score: CampaignScore, compliance: dict | None = None) -> str:
    lines = _header(score.target, "Technical")
    lines += [
        f"**Result:** {score.passed}/{score.total} tests passed (pass rate {score.score:.1%}); "
        f"residual risk score {score.risk_score:.2f}.",
        "",
        "## Findings",
        "",
    ]
    if not score.findings:
        lines.append("_No findings — all tests passed._")
    for f in score.findings:
        lines += [
            f"### [{f.severity.upper()}] {f.case_id} — {f.name}",
            "",
            f"- **Category:** {f.category}",
            f"- **OWASP LLM:** {', '.join(f.owasp) or 'n/a'}",
            f"- **MITRE ATLAS:** {', '.join(f.atlas) or 'n/a'}",
            f"- **Why it failed:** {f.reason}",
            f"- **Remediation:** {f.remediation}",
            "",
        ]
    lines += ["## By category", "", "| Category | Passed | Total | Score |", "|---|---|---|---|"]
    for cat, b in sorted(score.by_category.items()):
        lines.append(f"| {cat} | {int(b['passed'])} | {int(b['total'])} | {b['score']:.1%} |")
    return "\n".join(lines) + "\n"


def executive_report(score: CampaignScore) -> str:
    critical = sum(1 for f in score.findings if f.severity == "critical")
    high = sum(1 for f in score.findings if f.severity == "high")
    lines = _header(score.target, "Executive")
    lines += [
        f"We ran **{score.total}** security and safety tests against the AI system. "
        f"**{score.passed} passed** and **{len(score.findings)} failed**.",
        "",
        f"- Critical findings: **{critical}**",
        f"- High findings: **{high}**",
        f"- Overall robustness: **{score.score:.1%}**",
        f"- Residual risk score: **{score.risk_score:.2f}** (lower is better)",
        "",
        "### Top risks",
        "",
    ]
    for f in score.findings[:5]:
        lines.append(f"- **{f.severity.upper()}** — {f.name} ({f.category})")
    if not score.findings:
        lines.append("- No risks identified in this campaign.")
    lines += ["", "_Remediation details are in the technical report._", ""]
    return "\n".join(lines)


def compliance_report(score: CampaignScore, compliance: dict) -> str:
    lines = _header(score.target, "Compliance")
    for fw, data in compliance.items():
        lines += [
            f"## {fw}",
            "",
            f"Controls tested: **{data['controls_tested']}** · failing: **{data['controls_failing']}**",
            "",
            "| Control | Status | Failing cases |",
            "|---|---|---|",
        ]
        for c in data["controls"]:
            lines.append(f"| {c['control']} | {c['status']} | {', '.join(c['failing_cases']) or '-'} |")
        lines.append("")
    return "\n".join(lines)


def json_report(score: CampaignScore, compliance: dict | None = None) -> str:
    return json.dumps({"score": score.to_dict(), "compliance": compliance}, indent=2, default=str)
