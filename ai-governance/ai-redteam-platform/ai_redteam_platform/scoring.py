"""Scoring engine: turns raw outcomes into risk-scored findings."""
from __future__ import annotations

from dataclasses import dataclass, field

from .engine import CaseOutcome
from .testlib import TestCase

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    case_id: str
    name: str
    category: str
    severity: str
    confidence: float
    reason: str
    remediation: str
    owasp: tuple[str, ...]
    atlas: tuple[str, ...]
    compliance: dict[str, tuple[str, ...]]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["owasp"] = list(self.owasp)
        d["atlas"] = list(self.atlas)
        return d


@dataclass
class CampaignScore:
    target: str
    total: int
    passed: int
    score: float                       # pass rate 0..1
    risk_score: float                  # residual risk 0..1 (higher = worse)
    by_category: dict[str, dict[str, float]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total": self.total,
            "passed": self.passed,
            "score": self.score,
            "risk_score": self.risk_score,
            "by_category": self.by_category,
            "findings": [f.to_dict() for f in self.findings],
        }


def score_campaign(target_name: str, cases: list[TestCase], outcomes: list[CaseOutcome]) -> CampaignScore:
    by_id = {c.id: c for c in cases}
    by_cat: dict[str, dict[str, float]] = {}
    findings: list[Finding] = []

    for o in outcomes:
        bucket = by_cat.setdefault(o.category, {"total": 0, "passed": 0})
        bucket["total"] += 1
        bucket["passed"] += 1 if o.passed else 0
        if not o.passed:
            case = by_id.get(o.case_id)
            sev = case.severity if case else "medium"
            findings.append(Finding(
                case_id=o.case_id, name=o.name, category=o.category, severity=sev,
                confidence=0.8, reason=o.reason,
                remediation=case.remediation if case else "",
                owasp=case.owasp if case else (), atlas=case.atlas if case else (),
                compliance=case.compliance if case else {},
            ))

    for bucket in by_cat.values():
        bucket["score"] = round(bucket["passed"] / bucket["total"], 4) if bucket["total"] else 0.0

    total = len(outcomes)
    passed = sum(1 for o in outcomes if o.passed)
    score = round(passed / total, 4) if total else 0.0

    # Residual risk: severity-weighted failures over the max possible weight.
    max_weight = sum(SEVERITY_WEIGHT.get(c.severity, 2) for c in cases) or 1
    fail_weight = sum(SEVERITY_WEIGHT.get(f.severity, 2) for f in findings)
    risk_score = round(fail_weight / max_weight, 4)

    findings.sort(key=lambda f: SEVERITY_WEIGHT.get(f.severity, 0), reverse=True)

    return CampaignScore(
        target=target_name, total=total, passed=passed, score=score,
        risk_score=risk_score, by_category=by_cat, findings=findings,
    )
