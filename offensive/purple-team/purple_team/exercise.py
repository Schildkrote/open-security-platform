"""Purple-team exercise runner: red action -> blue detection -> timeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .attack import by_id
from .detections import MockSIEM
from .tests import SAFE_TESTS, SafeTest


@dataclass
class TimelineEntry:
    time: str
    technique_id: str
    technique_name: str
    test_id: str
    red_action: str
    detected: bool
    rules_fired: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ExerciseResult:
    timeline: list[TimelineEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.timeline)

    @property
    def detected(self) -> int:
        return sum(1 for e in self.timeline if e.detected)

    @property
    def detection_rate(self) -> float:
        return round(self.detected / self.total, 4) if self.total else 0.0

    def undetected(self) -> list[TimelineEntry]:
        return [e for e in self.timeline if not e.detected]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "detected": self.detected,
            "detection_rate": self.detection_rate,
            "timeline": [e.to_dict() for e in self.timeline],
        }


def run_exercise(siem: MockSIEM | None = None, tests: list[SafeTest] | None = None) -> ExerciseResult:
    """Simulate a purple-team exercise: run each safe test and record whether
    the detection stack observed it."""
    siem = siem or MockSIEM()
    tests = tests if tests is not None else SAFE_TESTS
    result = ExerciseResult()
    for test in tests:
        technique = by_id(test.technique_id)
        fired = siem.evaluate(test)
        result.timeline.append(TimelineEntry(
            time=datetime.now(timezone.utc).isoformat(),
            technique_id=test.technique_id,
            technique_name=technique.name if technique else test.technique_id,
            test_id=test.id,
            red_action=test.safe_command,
            detected=bool(fired),
            rules_fired=fired,
        ))
    return result
