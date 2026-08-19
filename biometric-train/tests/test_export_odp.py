# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Golden tests for scripts/export_odp.py (OBP → ODP bridge).

Cross-language digest pin: the event envelope emitted by the exporter must
hash to exactly what ODP's Go ``events.Digest`` computes (same canonical
JSON: sorted keys, compact separators, hash zeroed). The pinned value was
generated in Go with a verbatim copy of ODP's Digest/marshalCanonical —
if it drifts, either side changed canonicalisation and the live bridge's
hash verification breaks.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "export_odp.py"

# Deterministic golden envelope (no wall-clock time).
GOLDEN_EV = {
    "id": "obp-golden-0",
    "time": "2026-08-19T10:00:00",
    "type": "biometric.match",
    "source": "obp",
    "action": "match_hit",
    "subject": "2bd806c97f0e00af1a1fc332",
    "refs": {},
    "data": {
        "client_pseudo": "2bd806c97f0e00af1a1fc332",
        "probe_id": "probe-1",
        "score": 0.9123,
        "source": "targeted_search",
        "retention_days": 30,
    },
    "prev_hash": "genesis",
    "hash": "aa83d6507d7c79e94cbe690edb1f6fcacc7b45d260382156cd51705b2c46b15b",
}
GOLDEN_DIGEST = "aa83d6507d7c79e94cbe690edb1f6fcacc7b45d260382156cd51705b2c46b15b"


def load_module():
    spec = importlib.util.spec_from_file_location("export_odp", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestExporterDigest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_digest_matches_go_odp(self):
        self.assertEqual(self.mod.event_digest(GOLDEN_EV), GOLDEN_DIGEST)

    def test_build_match_event_deterministic(self):
        ev = self.mod.build_match_event(
            hit_id="obp-golden-0",
            client_pseudo="2bd806c97f0e00af1a1fc332",
            probe_id="probe-1",
            score=0.9123,
            prev_hash="genesis",
            ts="2026-08-19T10:00:00",
        )
        self.assertEqual(ev["hash"], GOLDEN_DIGEST)
        self.assertEqual(json.loads(json.dumps(ev)), GOLDEN_EV)

    def test_chain_links(self):
        e1 = self.mod.build_match_event(
            hit_id="h-1", client_pseudo="p1", probe_id="pr", score=1.0,
            prev_hash="genesis", ts="2026-08-19T10:00:00")
        e2 = self.mod.build_match_event(
            hit_id="h-2", client_pseudo="p1", probe_id="pr", score=0.9,
            prev_hash=e1["hash"], ts="2026-08-19T10:00:01")
        self.assertEqual(e2["prev_hash"], e1["hash"])
        self.assertNotEqual(e1["hash"], e2["hash"])


if __name__ == "__main__":
    unittest.main()