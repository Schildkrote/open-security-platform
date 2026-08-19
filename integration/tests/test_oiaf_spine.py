"""OIAF on the native webhook spine.

``test_oiaf_decisions_on_spine`` proves the first identity-producer on the bus:
oiafd (Go, identity/oiaf subtree) is started with ``-webhooks`` pointing at the
collector; an identity + TOTP factor + a challenge policy are provisioned; an
``access/evaluate`` (allowed) and a challenge cycle then land
``access.decided`` and ``challenge.verified`` events on the collector. The test
recomputes every event hash in **Python** (canonical compact sorted-key JSON,
the platform's cross-language algorithm) and walks the prev_hash chain — the
proof that OIAF decisions are first-class spine citizens.

Fully offline (127.0.0.1, mocks). Run via ``make integration``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import ExitStack
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def recompute_hash(event: dict) -> str:
    """Recompute an integration-event hash (canonical compact sorted-key JSON)."""
    tmp = dict(event)
    tmp["hash"] = ""
    canonical = json.dumps(tmp, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _request(base: str, path: str, method: str, body: dict | None, token: str) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{base}{path}", data=data, method=method)
    req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw}


def post(base: str, path: str, body: dict, token: str = "") -> tuple[int, Any]:
    return _request(base, path, "POST", body, token)


def get(base: str, path: str, token: str = "") -> tuple[int, Any]:
    return _request(base, path, "GET", None, token)


def _b32_decode(secret: str) -> bytes:
    pad = "=" * (-len(secret) % 8)
    return base64.b32decode(secret.upper() + pad)


def totp_now(secret: str) -> str:
    """RFC 6238 TOTP, 30 s step, 6 digits — stdlib only (mirrors e2e.sh)."""
    step = int(time.time()) // 30
    digest = hmac.new(_b32_decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


class OIAFSpineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("go"):
            raise unittest.SkipTest("oiaf spine test requires go on PATH")

        from integration import servers

        cls._stack = ExitStack()
        cls._tmp = tempfile.mkdtemp(prefix="osp-oiaf-spine-")

        cls.collector = cls._stack.enter_context(servers.CollectorServer())
        cls.admin_token = "osp-spine-" + "a" * 52
        cls.adapter_token = "osp-spine-" + "b" * 52

        oiaf_bin = servers.build_go(
            ROOT, os.path.join(cls._tmp, "oiafd"), package="./identity/oiaf/core/cmd/oiafd"
        )
        port = servers.free_port()
        server = servers.oiaf_server(
            oiaf_bin, port, f"{cls.collector.base}/webhook", cls.admin_token, cls.adapter_token
        )
        cls.oiaf_base = cls._stack.enter_context(server).base

    @classmethod
    def tearDownClass(cls) -> None:
        stack = getattr(cls, "_stack", None)
        if stack is not None:
            stack.close()
        tmp = getattr(cls, "_tmp", None)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_oiaf_decisions_on_spine(self) -> None:
        # Provision an identity (admin) — the challenge flow needs one.
        status, ident = post(
            self.oiaf_base,
            "/v1/identities",
            {"username": "spine-user", "display_name": "Spine User"},
            token=self.admin_token,
        )
        self.assertEqual(status, 201, f"identity create: {ident}")
        identity_id = ident["id"]

        # Enroll + activate TOTP so the challenge can be verified.
        status, enroll = post(
            self.oiaf_base,
            f"/v1/identities/{identity_id}/factors/totp/enroll",
            {},
            token=self.admin_token,
        )
        self.assertEqual(status, 201, f"totp enroll: {enroll}")
        secret = enroll["secret"]
        status, _ = post(
            self.oiaf_base,
            f"/v1/identities/{identity_id}/factors/totp/activate",
            {"factor_id": enroll["factor_id"], "code": totp_now(secret)},
            token=self.admin_token,
        )
        self.assertEqual(status, 200, "totp activate")

        # Allow decision (adapter) — must land on the collector as access.decided.
        status, dec = post(
            self.oiaf_base,
            "/v1/access/evaluate",
            {
                "identity": {"username": "spine-user"},
                "resource": {"name": "ssh", "type": "protocol"},
            },
            token=self.adapter_token,
        )
        self.assertEqual(status, 200, f"evaluate: {dec}")
        request_id = dec["request_id"]

        # Explicit CHALLENGE policy for this identity + resource.
        status, pol = post(
            self.oiaf_base,
            "/v1/policies",
            {
                "name": "spine-challenge",
                "enabled": True,
                "priority": 100,
                "conditions": {
                    "all": [
                        {"path": "identity.username", "op": "eq", "value": "spine-user"},
                        {"path": "resource.type", "op": "eq", "value": "vault"},
                    ]
                },
                "effect": "challenge",
            },
            token=self.admin_token,
        )
        self.assertEqual(status, 201, f"policy create: {pol}")

        status, dec2 = post(
            self.oiaf_base,
            "/v1/access/evaluate",
            {
                "identity": {"username": "spine-user"},
                "resource": {"name": "vault", "type": "vault"},
            },
            token=self.adapter_token,
        )
        self.assertEqual(status, 200, f"evaluate 2: {dec2}")
        self.assertEqual(dec2["decision"], "challenge", dec2)
        challenge_id = dec2["challenge"]["id"]

        # Verify the TOTP challenge with a freshly generated code.
        status, ch = post(
            self.oiaf_base,
            f"/v1/challenge/{challenge_id}/verify",
            {"method": "totp", "code": totp_now(secret)},
            token=self.adapter_token,
        )
        self.assertEqual(status, 200, f"challenge verify: {ch}")

        # Collect and verify the spine chain (cross-language).
        events = self.collector.snapshot()
        oiaf_events = [e for e in events if e.get("source") == "oiaf"]
        self.assertGreaterEqual(
            len(oiaf_events), 3, f"expected >=3 oiaf events, got {len(oiaf_events)}"
        )

        types = [e["type"] for e in oiaf_events]
        self.assertIn("access.decided", types)
        self.assertIn("challenge.verified", types)

        # Every event: hash recomputes in Python; chain links via prev_hash.
        prev = "genesis"
        for e in oiaf_events:
            self.assertEqual(e["prev_hash"], prev, f"chain break at {e['id']}")
            self.assertEqual(recompute_hash(e), e["hash"], f"cross-language hash mismatch on {e['id']}")
            prev = e["hash"]

        # The decision payload carries the request id from the API response.
        decided = next(e for e in oiaf_events if e["type"] == "access.decided")
        self.assertEqual(decided["refs"]["request_id"], request_id)


if __name__ == "__main__":
    unittest.main()