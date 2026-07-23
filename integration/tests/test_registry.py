"""End-to-end test for the subscription/registry broker.

The same campaign -> finding -> evidence spine as test_webhooks, but routed
through the registry: every component emits to the broker (one URL), and the
broker fans events out to whoever subscribed to that event type. No component
knows the others' addresses — subscriptions are registered dynamically.

Fully offline (127.0.0.1, mocks). Run via ``make integration``.
"""
from __future__ import annotations

import os
import shutil
import sys
import unittest
from contextlib import ExitStack

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class RegistryRoutedSpineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("node"):
            raise unittest.SkipTest("registry test requires node on PATH")

        sys.path.insert(0, ROOT)
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-redteam-platform"))
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-compliance-hub"))

        from integration import servers
        from integration.registry import RegistryServer

        cls._stack = ExitStack()

        # The broker.
        cls.registry = cls._stack.enter_context(RegistryServer())

        # ai-compliance-hub (subscribes to finding.created) — in-thread.
        import compliance_hub.db as ch_db
        from compliance_hub.api import serve as ch_serve

        ch_server = servers.PythonServer(ch_serve(ch_db.connect(":memory:"), 0))
        cls.ch_base = cls._stack.enter_context(ch_server).base

        # pentest-manager (subscribes to campaign.complete) — emits to the broker.
        pt_port = servers.free_port()
        pt_dir = os.path.join(ROOT, "offensive", "pentest-manager")
        pt_server = servers.node_server(
            pt_dir, pt_port, extra_env={"OSP_WEBHOOK_URLS": cls.registry.events_url}
        )
        cls.pt_base = cls._stack.enter_context(pt_server).base

        # ai-redteam-platform — emits to the broker.
        import ai_redteam_platform.db as rt_db
        from ai_redteam_platform.api import Platform
        from ai_redteam_platform.api import serve as rt_serve

        platform = Platform(
            rt_db.connect(":memory:"), webhook_urls=[cls.registry.events_url]
        )
        rt_server = servers.PythonServer(rt_serve(platform, 0))
        cls.rt_base = cls._stack.enter_context(rt_server).base

    @classmethod
    def tearDownClass(cls) -> None:
        stack = getattr(cls, "_stack", None)
        if stack is not None:
            stack.close()

    def test_registry_routed_spine(self) -> None:
        from integration.clients import ComplianceClient, PentestClient, RedteamClient

        # Dynamic subscriptions: the broker learns who wants what.
        self.registry.registry.subscribe(
            "campaign.complete", f"{self.pt_base}/webhook", "pentest-manager"
        )
        self.registry.registry.subscribe(
            "finding.created", f"{self.ch_base}/webhook", "ai-compliance-hub"
        )

        rt = RedteamClient(self.rt_base)
        pt = PentestClient(self.pt_base)
        ch = ComplianceClient(self.ch_base)

        # Trigger a campaign; the broker routes campaign.complete -> pentest and
        # pentest's finding.created -> compliance.
        target = rt.register_target(name="Range Chatbot", app_type="llm", risk_tier="high")
        rt.authorize(target["id"], "authorized")
        campaign = rt.run_campaign(target["id"], guarded=False)
        self.assertGreaterEqual(len(campaign["score"]["findings"]), 1)

        # pentest-manager received campaign.complete and created findings.
        clients = pt.list_clients()
        ai_client = next((c for c in clients if c["name"] == "AI Red-Team"), None)
        self.assertIsNotNone(ai_client)
        engagements = pt.list_engagements(ai_client["id"])
        self.assertGreaterEqual(len(engagements), 1)
        findings = pt.list_findings(engagements[0]["id"])
        self.assertGreaterEqual(len(findings), 1)

        # ai-compliance-hub received finding.created and recorded evidence.
        self.assertGreaterEqual(len(ch.list_evidence()), 1)
        self.assertTrue(ch.verify_evidence()["valid"])

        # The broker actually delivered events.
        delivered_types = {d["type"] for d in self.registry.registry.delivered}
        self.assertIn("campaign.complete", delivered_types)
        self.assertIn("finding.created", delivered_types)


if __name__ == "__main__":
    unittest.main()
