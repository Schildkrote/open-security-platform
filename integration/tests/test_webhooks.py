"""End-to-end test for the NATIVE webhook spine.

Unlike test_e2e (an external orchestrator calling each API), here the components
talk to each other directly: ai-redteam-platform emits ``campaign.complete`` to
pentest-manager's webhook, which creates findings and emits ``finding.created``
to ai-compliance-hub's webhook, which records evidence. Triggering one campaign
cascades natively across Python -> Node -> Python. Fully offline (127.0.0.1,
mocks). Run via ``make integration``.
"""
from __future__ import annotations

import os
import shutil
import sys
import unittest
from contextlib import ExitStack

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class NativeWebhookFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("node"):
            raise unittest.SkipTest("native webhook test requires node on PATH")

        sys.path.insert(0, ROOT)
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-redteam-platform"))
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-compliance-hub"))

        from integration import servers

        cls._stack = ExitStack()

        # 1. ai-compliance-hub (sink) — in-thread.
        import compliance_hub.db as ch_db
        from compliance_hub.api import serve as ch_serve

        ch_server = servers.PythonServer(ch_serve(ch_db.connect(":memory:"), 0))
        cls.ch_base = cls._stack.enter_context(ch_server).base

        # 2. pentest-manager — subprocess, emits finding.created -> compliance.
        pt_port = servers.free_port()
        pt_dir = os.path.join(ROOT, "offensive", "pentest-manager")
        pt_server = servers.node_server(
            pt_dir, pt_port, extra_env={"OSP_WEBHOOK_URLS": f"{cls.ch_base}/webhook"}
        )
        cls.pt_base = cls._stack.enter_context(pt_server).base

        # 3. ai-redteam-platform — in-thread, emits campaign.complete -> pentest.
        import ai_redteam_platform.db as rt_db
        from ai_redteam_platform.api import Platform
        from ai_redteam_platform.api import serve as rt_serve

        platform = Platform(
            rt_db.connect(":memory:"), webhook_urls=[f"{cls.pt_base}/webhook"]
        )
        rt_server = servers.PythonServer(rt_serve(platform, 0))
        cls.rt_base = cls._stack.enter_context(rt_server).base

    @classmethod
    def tearDownClass(cls) -> None:
        stack = getattr(cls, "_stack", None)
        if stack is not None:
            stack.close()

    def test_native_webhook_cascade(self) -> None:
        from integration.flow import run_flow_native

        result = run_flow_native(self.rt_base, self.pt_base, self.ch_base)

        # The campaign produced findings...
        self.assertGreaterEqual(result["redteam_findings"], 1)
        # ...which pentest-manager turned into findings via its webhook...
        self.assertIsNotNone(result["pentest_client"])
        self.assertGreaterEqual(result["pentest_engagements"], 1)
        self.assertGreaterEqual(len(result["pentest_findings"]), 1)
        # ...and ai-compliance-hub turned into evidence via its webhook.
        self.assertGreaterEqual(len(result["compliance_evidence"]), 1)

        # Both tamper-evident trails verify.
        self.assertTrue(result["verifications"]["compliance_evidence"]["valid"])
        self.assertTrue(result["verifications"]["pentest_evidence"]["valid"])

        # The evidence came from the pentest-manager webhook source.
        sources = {e.get("source") for e in result["compliance_evidence"]}
        self.assertIn("pentest-manager", sources)


if __name__ == "__main__":
    unittest.main()
