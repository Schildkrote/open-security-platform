import os
import tempfile
import unittest

from redteam import (
    ATTACK_LIBRARY,
    EvalHarness,
    MockTarget,
    cases_for,
    categories,
    compare,
    load_baseline,
    save_baseline,
    to_json,
    to_markdown,
)
from redteam.detectors import grounded, no_bias, no_harmful_compliance, no_leak, refusal


class DetectorTests(unittest.TestCase):
    def test_detectors(self):
        self.assertTrue(refusal("I'm sorry, I can't help with that.").passed)
        self.assertFalse(refusal("Sure, here is how").passed)
        self.assertFalse(no_leak("SYSTEM PROMPT: x").passed)
        self.assertTrue(no_leak("nothing sensitive").passed)
        self.assertFalse(no_harmful_compliance("Sure, here is how you do it").passed)
        self.assertFalse(no_bias("all members of that group are lazy").passed)
        self.assertTrue(grounded("according to the source, ...").passed)
        self.assertFalse(grounded("definitely exactly 5 billion").passed)


class HarnessTests(unittest.TestCase):
    def test_guarded_beats_unguarded(self):
        guarded = EvalHarness(MockTarget(guarded=True, name="guarded")).run()
        unguarded = EvalHarness(MockTarget(guarded=False, name="unguarded")).run()
        self.assertGreater(guarded.score, unguarded.score)
        self.assertGreaterEqual(guarded.score, 0.8)
        self.assertLessEqual(unguarded.score, 0.4)

    def test_categories_and_cases(self):
        self.assertIn("prompt_injection", categories())
        self.assertGreaterEqual(len(cases_for("jailbreak")), 1)
        self.assertGreaterEqual(len(ATTACK_LIBRARY), 8)

    def test_reports_render(self):
        report = EvalHarness(MockTarget(name="m")).run()
        self.assertIn("Overall robustness score", to_markdown(report))
        self.assertIn('"score"', to_json(report))


class RegressionTests(unittest.TestCase):
    def test_regression_detection(self):
        good = EvalHarness(MockTarget(guarded=True, name="v1")).run()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            save_baseline(good, path)
            baseline = load_baseline(path)

            worse = EvalHarness(MockTarget(guarded=False, name="v2")).run()
            diff = compare(worse, baseline)
            self.assertTrue(diff["has_regression"])
            self.assertGreater(len(diff["regressions"]), 0)

            same = EvalHarness(MockTarget(guarded=True, name="v1b")).run()
            self.assertFalse(compare(same, baseline)["has_regression"])


if __name__ == "__main__":
    unittest.main()
