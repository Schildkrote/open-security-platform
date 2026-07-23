import os
import sys
import threading
import unittest
import urllib.request

from ai_redteam_platform import (
    HttpTarget,
    MockTarget,
    Platform,
    SafeRunner,
    ScopeViolation,
    all_cases,
    cases_by_owasp,
    compliance_coverage,
    compliance_report,
    connect,
    executive_report,
    json_report,
    list_evidence,
    redact,
    redteam_available,
    register_target,
    run_cases,
    run_via_redteam,
    score_campaign,
    serve,
    set_authorization,
    technical_report,
    verify_chain,
)
from ai_redteam_platform.testlib import TEST_LIBRARY


class LibraryTests(unittest.TestCase):
    def test_cases_have_compliance_mappings(self):
        self.assertGreaterEqual(len(TEST_LIBRARY), 10)
        for c in TEST_LIBRARY:
            self.assertTrue(c.owasp, f"{c.id} missing OWASP mapping")
            self.assertIn(c.severity, ("low", "medium", "high", "critical"))
        self.assertGreaterEqual(len(cases_by_owasp("LLM01")), 1)

    def test_engine_guarded_vs_unguarded(self):
        cases = all_cases()
        guarded = run_cases(MockTarget(guarded=True), cases)
        unguarded = run_cases(MockTarget(guarded=False), cases)
        g = sum(o.passed for o in guarded) / len(guarded)
        u = sum(o.passed for o in unguarded) / len(unguarded)
        self.assertGreater(g, u)
        self.assertGreaterEqual(g, 0.7)

    def test_http_target_rejects_external(self):
        with self.assertRaises(ValueError):
            HttpTarget("http://evil.example.com")


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect()

    def test_unauthorized_target_blocked(self):
        t = register_target(self.conn, "X")
        runner = SafeRunner(self.conn)
        with self.assertRaises(ScopeViolation):
            runner.run_campaign(t["id"], MockTarget())

    def test_authorized_campaign_stores_evidence_and_scores(self):
        t = register_target(self.conn, "X")
        set_authorization(self.conn, t["id"], "authorized")
        runner = SafeRunner(self.conn)
        result = runner.run_campaign(t["id"], MockTarget(guarded=True))
        self.assertFalse(result.aborted)
        self.assertGreater(result.score.score, 0.5)
        self.assertGreater(len(list_evidence(self.conn, result.campaign_id)), 0)
        self.assertTrue(verify_chain(self.conn)["valid"])

    def test_kill_switch_aborts(self):
        from ai_redteam_platform import Target

        t = register_target(self.conn, "X")
        set_authorization(self.conn, t["id"], "authorized")
        runner = SafeRunner(self.conn)

        class TripWire(Target):
            name = "tripwire"

            def complete(self, prompt: str) -> str:
                runner.abort()  # trip the kill switch mid-campaign
                return "ok"

        result = runner.run_campaign(t["id"], TripWire())
        self.assertTrue(result.aborted)
        self.assertLess(len(result.outcomes), len(all_cases()))

    def test_external_endpoint_out_of_scope(self):
        t = register_target(self.conn, "X", endpoint="http://evil.example.com")
        set_authorization(self.conn, t["id"], "authorized")
        runner = SafeRunner(self.conn)
        with self.assertRaises(ScopeViolation):
            runner.run_campaign(t["id"], MockTarget())


class ScoringComplianceReportTests(unittest.TestCase):
    def test_reports_render(self):
        cases = all_cases()
        outcomes = run_cases(MockTarget(guarded=False), cases)
        score = score_campaign("vuln", cases, outcomes)
        compliance = compliance_coverage(cases, outcomes)
        self.assertIn("Findings", technical_report(score, compliance))
        self.assertIn("executive", executive_report(score).lower())
        self.assertIn("EU_AI_ACT", compliance_report(score, compliance))
        self.assertIn('"score"', json_report(score, compliance))
        self.assertGreater(score.risk_score, 0)
        self.assertGreaterEqual(len(score.findings), 1)

    def test_redaction(self):
        self.assertNotIn("jane@corp.com", redact("email jane@corp.com ssn 123-45-6789"))


class EmbeddingTests(unittest.TestCase):
    def test_run_via_redteam_if_available(self):
        # Make the sibling ai-redteam-evals package importable to prove embedding.
        sibling = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ai-redteam-evals"))
        if sibling not in sys.path:
            sys.path.insert(0, sibling)
        if not redteam_available():
            self.skipTest("ai-redteam-evals not present")
        outcomes = run_via_redteam(MockTarget(guarded=True), all_cases())
        self.assertGreater(len(outcomes), 0)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect()
        self.platform = Platform(self.conn)
        self.server = serve(self.platform, port=0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _post(self, path, payload):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=__import__("json").dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req) as r:
            return __import__("json").loads(r.read())

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
            return r.read().decode()

    def test_end_to_end(self):
        target = self._post("/targets", {"name": "Guarded", "risk_tier": "medium"})
        self._post(f"/targets/{target['id']}/authorize", {"status": "authorized"})
        campaign = self._post("/campaigns", {"target_id": target["id"], "guarded": True})
        self.assertGreater(campaign["score"]["score"], 0.5)
        cid = campaign["campaign_id"]
        self.assertIn("Findings", self._get(f"/campaigns/{cid}/report?format=technical"))
        self.assertIn("EU_AI_ACT", self._get(f"/compliance/{cid}"))
        self.assertIn('"valid": true', self._get("/evidence/verify"))


if __name__ == "__main__":
    unittest.main()
