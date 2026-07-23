"""Tests for the ATT&CK -> Sigma rule mapping."""
from __future__ import annotations

import unittest

from purple_team import sigma
from purple_team.attack import TECHNIQUES


class SigmaMappingTests(unittest.TestCase):
    def test_rules_for_known_technique(self):
        rules = sigma.rules_for("T1566")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].title, "Phishing Attachment Execution")

    def test_rules_for_unknown_technique(self):
        self.assertEqual(sigma.rules_for("T9999"), [])

    def test_every_library_technique_has_a_rule(self):
        cov = sigma.coverage([t.id for t in TECHNIQUES])
        self.assertTrue(all(cov.values()), f"uncovered: {sigma.gaps([t.id for t in TECHNIQUES])}")

    def test_gaps(self):
        self.assertEqual(sigma.gaps(["T1566", "T9999"]), ["T9999"])

    def test_to_sigma_yaml(self):
        rule = sigma.rules_for("T1110")[0]
        yaml = sigma.to_sigma_yaml(rule)
        self.assertIn("title: Brute Force - Multiple Failed Logons", yaml)
        self.assertIn("attack.t1110", yaml)
        self.assertIn("product: windows", yaml)


if __name__ == "__main__":
    unittest.main()
