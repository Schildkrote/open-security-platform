"""Tests for OSCAL import/export."""
from __future__ import annotations

import unittest

from compliance_hub import controls as controls_mod
from compliance_hub import db, evidence, oscal


class OscalTests(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        controls_mod.add_control(
            self.conn,
            title="AI Risk Assessment",
            family="Risk",
            description="Perform risk assessments.",
            mappings={"NIST_AI_RMF": ["GOVERN-2"], "EU_AI_ACT": ["Article 9"]},
        )

    def test_export_catalog_shape(self):
        catalog = oscal.export_catalog(self.conn)
        self.assertIn("catalog", catalog)
        self.assertEqual(catalog["catalog"]["metadata"]["oscal-version"], oscal.OSCAL_VERSION)
        groups = catalog["catalog"]["groups"]
        self.assertEqual(len(groups), 1)
        control = groups[0]["controls"][0]
        self.assertEqual(control["title"], "AI Risk Assessment")
        prop_names = {p["name"] for p in control["props"]}
        self.assertIn("mapping:NIST_AI_RMF", prop_names)

    def test_catalog_round_trip(self):
        catalog = oscal.export_catalog(self.conn)
        fresh = db.connect(":memory:")
        n = oscal.import_catalog(fresh, catalog)
        self.assertEqual(n, 1)
        imported = controls_mod.list_controls(fresh)[0]
        self.assertEqual(imported["title"], "AI Risk Assessment")
        self.assertEqual(imported["family"], "Risk")
        self.assertEqual(imported["mappings"]["NIST_AI_RMF"], ["GOVERN-2"])

    def test_export_assessment_results(self):
        evidence.collect_evidence(self.conn, content="control tested", source="ai-redteam-platform")
        results = oscal.export_assessment_results(self.conn)
        observations = results["assessment-results"]["results"][0]["observations"]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["description"], "control tested")


if __name__ == "__main__":
    unittest.main()
