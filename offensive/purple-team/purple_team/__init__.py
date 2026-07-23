"""purple-team: ATT&CK-based detection coverage, safe testing, and gap analysis."""
from .attack import TECHNIQUES, Technique, by_id, tactics
from .tests import SAFE_TESTS, SafeTest, tests_for_technique
from .detections import DETECTION_RULES, DetectionRule, MockSIEM, rules_for_technique
from .coverage import coverage_matrix, gaps, coverage_percent, recommendations
from .exercise import run_exercise, ExerciseResult, TimelineEntry
from .reports import coverage_report

__all__ = [
    "TECHNIQUES", "Technique", "by_id", "tactics",
    "SAFE_TESTS", "SafeTest", "tests_for_technique",
    "DETECTION_RULES", "DetectionRule", "MockSIEM", "rules_for_technique",
    "coverage_matrix", "gaps", "coverage_percent", "recommendations",
    "run_exercise", "ExerciseResult", "TimelineEntry",
    "coverage_report",
]
