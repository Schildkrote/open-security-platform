"""Tests for the red-team engine adapters (environment-robust)."""
from __future__ import annotations

import unittest

from ai_redteam_platform import engines
from ai_redteam_platform.engine import CaseOutcome, MockTarget
from ai_redteam_platform.testlib import all_cases


class FakeAdapter:
    name = "fake"

    def available(self) -> bool:
        return True

    def run(self, target, cases):
        return [
            CaseOutcome(
                case_id="c1",
                category="test",
                name="fake",
                passed=True,
                reason="fake",
                response="ok",
                detector="fake",
            )
        ]


class EngineAdapterTests(unittest.TestCase):
    def test_registry_has_expected_engines(self):
        for name in ("ai-redteam-evals", "garak", "promptfoo"):
            self.assertEqual(engines.get_engine(name).name, name)

    def test_unknown_engine_raises(self):
        with self.assertRaises(KeyError):
            engines.get_engine("does-not-exist")

    def test_evals_adapter_availability_matches(self):
        from ai_redteam_platform.engine import redteam_available

        self.assertEqual(engines.EvalsAdapter().available(), redteam_available())

    def test_garak_adapter(self):
        adapter = engines.GarakAdapter()
        self.assertIsInstance(adapter.available(), bool)
        if not adapter.available():
            with self.assertRaises(RuntimeError):
                adapter.run(MockTarget(), all_cases())

    def test_promptfoo_adapter(self):
        adapter = engines.PromptfooAdapter()
        self.assertIsInstance(adapter.available(), bool)
        if not adapter.available():
            with self.assertRaises(RuntimeError):
                adapter.run(MockTarget(), all_cases())

    def test_fake_adapter_conforms_and_runs(self):
        adapter = FakeAdapter()
        self.assertTrue(adapter.available())
        outcomes = adapter.run(MockTarget(), all_cases())
        self.assertEqual(len(outcomes), 1)
        self.assertTrue(outcomes[0].passed)


if __name__ == "__main__":
    unittest.main()
