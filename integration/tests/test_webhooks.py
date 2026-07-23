"""End-to-end tests for the NATIVE webhook spine.

Unlike test_e2e (an external orchestrator calling each API), here the components
talk to each other directly:

* ``test_native_webhook_cascade`` — ai-redteam-platform emits ``campaign.complete``
  to pentest-manager's webhook, which creates findings and emits
  ``finding.created`` to ai-compliance-hub's webhook, which records evidence
  (Python -> Node -> Python).
* ``test_native_privileged_action`` — open-pam-jit emits ``access.granted`` (Go,
  via the shared ``platform/events`` emitter) and agent-sandbox emits
  ``action.executed`` (via its ``on_execute`` hook) to a collector; both
  per-source hash chains are verified, including cross-language hash recomputation.

Fully offline (127.0.0.1, mocks). Run via ``make integration``.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def recompute_hash(event: dict) -> str:
    """Recompute an integration-event hash (canonical compact sorted-key JSON)."""
    tmp = dict(event)
    tmp["hash"] = ""
    canonical = json.dumps(tmp, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


class NativeWebhookFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("node") or not shutil.which("go"):
            raise unittest.SkipTest("native webhook tests require node and go on PATH")

        sys.path.insert(0, ROOT)
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-redteam-platform"))
        sys.path.insert(0, os.path.join(ROOT, "ai-governance", "ai-compliance-hub"))
        sys.path.insert(0, os.path.join(ROOT, "ai-security", "agent-sandbox"))

        from integration import servers

        cls._stack = ExitStack()
        cls._tmp = tempfile.mkdtemp(prefix="osp-native-")

        # Webhook collector (observes open-pam-jit + agent-sandbox events).
        cls.collector = cls._stack.enter_context(servers.CollectorServer())

        # ai-compliance-hub (sink) — in-thread.
        import compliance_hub.db as ch_db
        from compliance_hub.api import serve as ch_serve

        ch_server = servers.PythonServer(ch_serve(ch_db.connect(":memory:"), 0))
        cls.ch_base = cls._stack.enter_context(ch_server).base

        # pentest-manager — subprocess, emits finding.created -> compliance.
        pt_port = servers.free_port()
        pt_dir = os.path.join(ROOT, "offensive", "pentest-manager")
        pt_server = servers.node_server(
            pt_dir, pt_port, extra_env={"OSP_WEBHOOK_URLS": f"{cls.ch_base}/webhook"}
        )
        cls.pt_base = cls._stack.enter_context(pt_server).base

        # ai-redteam-platform — in-thread, emits campaign.complete -> pentest.
        import ai_redteam_platform.db as rt_db
        from ai_redteam_platform.api import Platform
        from ai_redteam_platform.api import serve as rt_serve

        platform = Platform(rt_db.connect(":memory:"), webhook_urls=[f"{cls.pt_base}/webhook"])
        rt_server = servers.PythonServer(rt_serve(platform, 0))
        cls.rt_base = cls._stack.enter_context(rt_server).base

        # open-pam-jit — subprocess, emits access.granted -> collector.
        pam_bin = servers.build_go(ROOT, os.path.join(cls._tmp, "open-pam-jit"))
        pam_port = servers.free_port()
        pam_server = servers.go_server(
            pam_bin,
            pam_port,
            os.path.join(cls._tmp, "pam-audit.jsonl"),
            extra_args=["-webhooks", f"{cls.collector.base}/webhook"],
        )
        cls.pam_base = cls._stack.enter_context(pam_server).base

    @classmethod
    def tearDownClass(cls) -> None:
        stack = getattr(cls, "_stack", None)
        if stack is not None:
            stack.close()
        tmp = getattr(cls, "_tmp", None)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

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

    def test_native_privileged_action(self) -> None:
        from agent_sandbox import Sandbox

        from integration.clients import PamClient
        from integration.events import HttpEmitter

        pam = PamClient(self.pam_base)
        before = len(self.collector.snapshot())

        # Two approved requests -> open-pam-jit emits two access.granted (chained).
        for i in range(2):
            req = pam.request_access(
                requester=f"operator-{i}",
                target_id="prod-db",
                justification="native webhook spine test",
                duration_sec=600,
            )
            pam.approve(req["id"], approver="security-lead")

        # Two sandboxed actions -> agent-sandbox emits two action.executed (chained).
        emitter = HttpEmitter("agent-sandbox", [f"{self.collector.base}/webhook"])
        with Sandbox() as sandbox:
            sandbox.on_execute = lambda rec: emitter.emit(
                "action.executed",
                "run",
                None,
                {},
                command=rec.command,
                allowed=rec.allowed,
                exit_code=rec.exit_code,
            )
            for i in range(2):
                rec = sandbox.run(f"echo native-spine-{i}")
                self.assertTrue(rec.allowed)
                self.assertEqual(rec.exit_code, 0)

        new_events = self.collector.snapshot()[before:]
        pam_events = [e for e in new_events if e["source"] == "open-pam-jit"]
        sandbox_events = [e for e in new_events if e["source"] == "agent-sandbox"]
        self.assertEqual(len(pam_events), 2)
        self.assertEqual(len(sandbox_events), 2)
        self.assertTrue(all(e["type"] == "access.granted" for e in pam_events))
        self.assertTrue(all(e["type"] == "action.executed" for e in sandbox_events))

        # Each per-source chain links correctly and every hash recomputes
        # (cross-language: open-pam-jit events are emitted by the Go emitter).
        for chain in (pam_events, sandbox_events):
            self.assertEqual(chain[0]["prev_hash"], "genesis")
            self.assertEqual(chain[1]["prev_hash"], chain[0]["hash"])
            for event in chain:
                self.assertEqual(recompute_hash(event), event["hash"])


if __name__ == "__main__":
    unittest.main()
