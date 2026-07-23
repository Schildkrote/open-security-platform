import unittest

from purple_team import (
    SAFE_TESTS,
    TECHNIQUES,
    MockSIEM,
    by_id,
    coverage_matrix,
    coverage_percent,
    coverage_report,
    gaps,
    recommendations,
    run_exercise,
    tactics,
)


class LibraryTests(unittest.TestCase):
    def test_techniques_and_tactics(self):
        self.assertGreaterEqual(len(TECHNIQUES), 10)
        self.assertIn("Initial Access", tactics())
        self.assertEqual(by_id("T1059").name, "Command and Scripting Interpreter")

    def test_safe_tests_map_to_techniques(self):
        technique_ids = {t.id for t in TECHNIQUES}
        for test in SAFE_TESTS:
            self.assertIn(test.technique_id, technique_ids, f"{test.id} maps to unknown technique")
            self.assertTrue(test.expected_telemetry)


class CoverageTests(unittest.TestCase):
    def test_matrix_and_gaps(self):
        matrix = coverage_matrix()
        self.assertEqual(len(matrix), len(TECHNIQUES))
        statuses = {r["technique_id"]: r["status"] for r in matrix}
        # T1059 has a rule -> detected; T1566 (phishing) has no rule -> gap.
        self.assertEqual(statuses["T1059"], "detected")
        self.assertEqual(statuses["T1566"], "gap")
        gap_ids = {g["technique_id"] for g in gaps()}
        self.assertIn("T1566", gap_ids)
        self.assertNotIn("T1059", gap_ids)

    def test_coverage_percent_bounded(self):
        pct = coverage_percent()
        self.assertGreater(pct, 0.0)
        self.assertLess(pct, 1.0)  # incomplete by design

    def test_recommendations_only_for_gaps(self):
        rec_ids = {r["technique_id"] for r in recommendations()}
        gap_ids = {g["technique_id"] for g in gaps()}
        self.assertEqual(rec_ids, gap_ids)


class ExerciseTests(unittest.TestCase):
    def test_run_exercise_detection(self):
        result = run_exercise()
        self.assertEqual(result.total, len(SAFE_TESTS))
        self.assertEqual(result.detected, sum(1 for e in result.timeline if e.detected))
        # Every detected entry must have at least one rule fired.
        for e in result.timeline:
            if e.detected:
                self.assertTrue(e.rules_fired)
        # Undetected entries correspond to techniques without rules.
        undetected_ids = {e.technique_id for e in result.undetected()}
        self.assertIn("T1566", undetected_ids)

    def test_siem_requires_matching_telemetry(self):
        siem = MockSIEM()
        from purple_team.tests import SafeTest
        # Right technique, wrong telemetry -> no fire.
        no_telemetry = SafeTest("X", "T1059", "x", "x", "echo x", ("Unrelated Source",))
        self.assertEqual(siem.evaluate(no_telemetry), [])


class ReportTests(unittest.TestCase):
    def test_report_renders(self):
        report = coverage_report(run_exercise())
        self.assertIn("Coverage matrix", report)
        self.assertIn("Detection gaps", report)
        self.assertIn("Exercise results", report)
        self.assertIn("T1566", report)


if __name__ == "__main__":
    unittest.main()
