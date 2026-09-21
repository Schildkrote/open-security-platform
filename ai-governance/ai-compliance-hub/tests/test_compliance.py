import json
import threading
import unittest
import urllib.error
import urllib.request

from compliance_hub import api, cards, controls, db, evidence, models


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect()

    def test_system_and_risk(self):
        s = models.register_system(self.conn, "Bot", risk_level="high")
        self.assertEqual(s["risk_level"], "high")
        r = models.add_risk(self.conn, "injection", system_id=s["id"], likelihood=4, impact=5)
        self.assertEqual(models.risk_score(r), 20)
        with self.assertRaises(ValueError):
            models.register_system(self.conn, "Bad", risk_level="extreme")

    def test_control_mapping_engine(self):
        for c in controls.DEFAULT_CONTROLS:
            controls.add_control(self.conn, **c)
        eu = controls.controls_for_framework(self.conn, "EU_AI_ACT")
        nist = controls.controls_for_framework(self.conn, "NIST_AI_RMF")
        self.assertGreaterEqual(len(eu), 5)
        self.assertGreaterEqual(len(nist), 5)
        # Every EU AI Act control should carry an EU_AI_ACT mapping.
        for c in eu:
            self.assertIn("EU_AI_ACT", c["mappings"])

    def test_evidence_chain_integrity(self):
        evidence.collect_evidence(self.conn, "first", source="audit")
        evidence.collect_evidence(self.conn, "second", source="audit")
        self.assertTrue(evidence.verify_chain(self.conn)["valid"])
        # Tamper with a record and confirm detection.
        self.conn.execute("UPDATE evidence SET content='tampered' WHERE rowid=1")
        self.conn.commit()
        self.assertFalse(evidence.verify_chain(self.conn)["valid"])

    def test_system_card_render(self):
        s = models.register_system(self.conn, "Bot", owner="Team", risk_level="high")
        models.add_risk(self.conn, "leak", system_id=s["id"], likelihood=3, impact=5)
        card = cards.system_card(self.conn, s["id"])
        self.assertIn("AI System Card: Bot", card)
        self.assertIn("leak", card)
        self.assertIn("Risk Assessment", card)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect()
        for c in controls.DEFAULT_CONTROLS:
            controls.add_control(self.conn, **c)
        self.server = api.serve(self.conn, port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
            return json.loads(r.read())

    def _post(self, path, payload):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    def test_end_to_end(self):
        self.assertTrue(self._get("/healthz")["ok"])
        system = self._post("/systems", {"name": "Bot", "risk_level": "high"})
        self._post("/risks", {"title": "injection", "system_id": system["id"]})
        self._post("/evidence", {"content": "review done", "system_id": system["id"]})
        self.assertTrue(self._get("/evidence/verify")["valid"])
        card = self._get(f"/systems/{system['id']}/card")["card"]
        self.assertIn("AI System Card: Bot", card)
        eu = self._get("/controls?framework=EU_AI_ACT")
        self.assertGreaterEqual(len(eu), 25)

    def test_frameworks_endpoint(self):
        body = self._get("/frameworks")
        self.assertIn("EU_AI_ACT", body["frameworks"])
        self.assertEqual(body["registered_references"]["OWASP_LLM_TOP10"], 10)
        self.assertIn("A.7.4", body["catalog"]["ISO_42001"]["references"])

    def test_controls_coverage_endpoint(self):
        body = self._get("/controls/coverage")
        self.assertGreaterEqual(body["controls"], len(controls.DEFAULT_CONTROLS))
        self.assertGreaterEqual(body["by_framework"]["EU_AI_ACT"], 25)
        self.assertIn("Governance", body["by_family"])

    def test_controls_gaps_endpoint(self):
        body = self._get("/controls/gaps")
        self.assertIn("SOC2_AI", body)
        self.assertIn("count", body["SOC2_AI"])
        self.assertIn("controls", body["SOC2_AI"])
        scoped = self._get("/controls/gaps?framework=EU_AI_ACT")
        self.assertEqual(list(scoped), ["EU_AI_ACT"])

    def test_controls_validate_endpoint(self):
        body = self._get("/controls/validate")
        self.assertTrue(body["valid"])
        self.assertEqual(body["errors"], [])

    def _post_status(self, path, payload):
        """POST that returns (status, parsed body) instead of raising on 4xx."""
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_post_control_rejects_invalid_citation(self):
        status, body = self._post_status(
            "/controls",
            {
                "title": "Bad Control",
                "family": "Risk",
                "mappings": {"EU_AI_ACT": ["Article 62"]},
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid citation")
        self.assertIn("Article 73", body["details"][0])
        # Nothing was stored.
        titles = [c["title"] for c in self._get("/controls")]
        self.assertNotIn("Bad Control", titles)

    def test_post_control_rejects_unknown_framework(self):
        status, body = self._post_status(
            "/controls",
            {"title": "X", "mappings": {"GDPR": ["Article 5"]}},
        )
        self.assertEqual(status, 400)
        self.assertIn("unknown framework", body["details"][0])

    def test_post_control_accepts_valid_citation(self):
        status, body = self._post_status(
            "/controls",
            {
                "title": "Good Control",
                "family": "Risk",
                "mappings": {"EU_AI_ACT": ["Article 73"], "ISO_42001": ["A.8.4"]},
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["title"], "Good Control")
        self.assertIn("EU_AI_ACT", body["mappings"])


if __name__ == "__main__":
    unittest.main()
