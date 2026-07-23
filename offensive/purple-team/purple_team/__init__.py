"""purple-team: ATT&CK-based detection coverage, safe testing, and gap analysis."""
from .attack import TECHNIQUES, Technique, by_id, tactics
from .coverage import coverage_matrix, coverage_percent, gaps, recommendations
from .detections import DETECTION_RULES, DetectionRule, MockSIEM, rules_for_technique
from .exercise import ExerciseResult, TimelineEntry, run_exercise
from .reports import coverage_report
from .tests import SAFE_TESTS, SafeTest, tests_for_technique

__all__ = [
    "TECHNIQUES", "Technique", "by_id", "tactics",
    "SAFE_TESTS", "SafeTest", "tests_for_technique",
    "DETECTION_RULES", "DetectionRule", "MockSIEM", "rules_for_technique",
    "coverage_matrix", "gaps", "coverage_percent", "recommendations",
    "run_exercise", "ExerciseResult", "TimelineEntry",
    "coverage_report",
]
