"""End-to-end Phase-2 integration test.

Starts all five components (Python in-thread; Node + Go as subprocesses), runs
the full flow over HTTP, and asserts the DoD: a red-team campaign produces a
finding in pentest-manager, evidence in ai-compliance-hub, a privileged action
brokered by open-pam-jit and executed inside agent-sandbox — with every
tamper-evident trail verifying. Fully offline (mock backends, 127.0.0.1 only).

Run via ``make integration`` (needs go + node + python on PATH).
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class EndToEndFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("go") or not shutil.which("node"):
            raise unittest.SkipTest("integration test requires go and node on PATH")

        sys.path.insert(0, ROOT)
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-redteam-platform"))
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-compliance-hub"))
        sys.path.insert(0, os.path.join(ROOT, "ai-security", "agent-sandbox"))

        from integration import servers

        cls._stack = ExitStack()
        cls._tmp = tempfile.mkdtemp(prefix="osp-integration-")

        # Python: ai-redteam-platform (in-thread).
        import ai_redteam_platform.db as rt_db
        from ai_redteam_platform.api import Platform
        from ai_redteam_platform.api import serve as rt_serve

        rt_server = servers.PythonServer(rt_serve(Platform(rt_db.connect(":memory:")), 0))
        cls.rt_base = cls._stack.enter_context(rt_server).base

        # Python: ai-compliance-hub (in-thread).
        import compliance_hub.db as ch_db
        from compliance_hub.api import serve as ch_serve

        ch_server = servers.PythonServer(ch_serve(ch_db.connect(":memory:"), 0))
        cls.ch_base = cls._stack.enter_context(ch_server).base

        # Node: pentest-manager (subprocess).
        pt_port = servers.free_port()
        pt_dir = os.path.join(ROOT, "offensive", "pentest-manager")
        cls.pt_base = cls._stack.enter_context(servers.node_server(pt_dir, pt_port)).base

        # Go: open-pam-jit (build once, then subprocess).
        pam_bin = servers.build_go(ROOT, os.path.join(cls._tmp, "open-pam-jit"))
        pam_port = servers.free_port()
        audit_file = os.path.join(cls._tmp, "pam-audit.jsonl")
        cls.pam_base = cls._stack.enter_context(
            servers.go_server(pam_bin, pam_port, audit_file)
        ).base

    @classmethod
    def tearDownClass(cls) -> None:
        stack = getattr(cls, "_stack", None)
        if stack is not None:
            stack.close()
        tmp = getattr(cls, "_tmp", None)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_full_flow(self) -> None:
        from agent_sandbox import Sandbox

        from integration.flow import run_flow

        with Sandbox() as sandbox:
            result = run_flow(
                self.rt_base,
                self.pt_base,
                self.ch_base,
                self.pam_base,
                sandbox_run=sandbox.run,
            )

        # Red-team campaign produced findings.
        self.assertGreaterEqual(len(result["findings"]), 1)
        self.assertFalse(result["verifications"]["integration_chain"] is False)

        # Findings landed in pentest-manager.
        self.assertGreaterEqual(len(result["pentest_findings"]), 1)
        self.assertTrue(result["pentest_findings"][0]["id"])

        # Evidence landed in ai-compliance-hub (findings + sandbox record).
        self.assertGreaterEqual(len(result["evidence"]), 1)
        self.assertIn("sandbox_evidence", result)

        # Privileged action brokered by open-pam-jit.
        self.assertTrue(result["pam_credential_id"])

        # Action executed inside agent-sandbox.
        self.assertTrue(result["sandbox_record"]["allowed"])
        self.assertEqual(result["sandbox_record"]["exit_code"], 0)

        # Every tamper-evident trail verifies.
        verifications = result["verifications"]
        self.assertTrue(verifications["compliance_evidence"]["valid"])
        self.assertTrue(verifications["pam_audit"]["valid"])
        self.assertTrue(verifications["integration_chain"])

        # The cross-component event chain captured every step.
        types = [e["type"] for e in result["events"]]
        self.assertIn("campaign.complete", types)
        self.assertIn("finding.created", types)
        self.assertIn("evidence.collected", types)
        self.assertIn("access.granted", types)
        self.assertIn("action.executed", types)


if __name__ == "__main__":
    unittest.main()
