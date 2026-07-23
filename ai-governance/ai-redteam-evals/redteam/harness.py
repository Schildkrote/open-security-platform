"""The evaluation harness: run attacks against a target and score the results."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .attacks import ATTACK_LIBRARY, AttackCase
from .detectors import REGISTRY
from .targets import Target


@dataclass
class CaseResult:
    case_id: str
    category: str
    name: str
    passed: bool
    reason: str
    response: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvalReport:
    target: str
    results: list[CaseResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def score(self) -> float:
        return round(self.passed / self.total, 4) if self.total else 0.0

    def by_category(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for r in self.results:
            bucket = out.setdefault(r.category, {"total": 0, "passed": 0})
            bucket["total"] += 1
            bucket["passed"] += 1 if r.passed else 0
        for cat, b in out.items():
            b["score"] = round(b["passed"] / b["total"], 4) if b["total"] else 0.0
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "score": self.score,
            "passed": self.passed,
            "total": self.total,
            "by_category": self.by_category(),
            "results": [r.to_dict() for r in self.results],
        }


class EvalHarness:
    def __init__(self, target: Target, cases: list[AttackCase] | None = None) -> None:
        self.target = target
        self.cases = cases if cases is not None else ATTACK_LIBRARY

    def run(self) -> EvalReport:
        report = EvalReport(target=self.target.name)
        for case in self.cases:
            response = self.target.complete(case.prompt)
            detector = REGISTRY[case.detector]
            judgment = detector(response)
            report.results.append(
                CaseResult(
                    case_id=case.id,
                    category=case.category,
                    name=case.name,
                    passed=judgment.passed,
                    reason=judgment.reason,
                    response=response,
                )
            )
        return report
