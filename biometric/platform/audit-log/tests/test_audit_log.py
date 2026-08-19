# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Python hash-chained audit log (mirrors audit_test.go)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import audit_log as al  # noqa: E402


class TestChain(unittest.TestCase):
    def test_append_and_verify(self):
        log = al.AuditLog()
        log.append(action="enrol", subject_pseudo=al.pseudo("alice"),
                   component="train", basis_outcome="permitted")
        log.append(action="train", subject_pseudo=al.pseudo("alice"),
                   component="train", basis_outcome="permitted", retention_max_days=30)
        self.assertEqual(log.verify(), None)
        self.assertEqual(len(log.all()), 2)
        self.assertEqual(log.all()[1].prev_hash, log.all()[0].hash)
        self.assertGreater(log.all()[1].retention_expires, 0)

    def test_tamper_detected(self):
        log = al.AuditLog()
        log.append(action="enrol", subject_pseudo="p1", component="train",
                   basis_outcome="permitted")
        log.append(action="match", subject_pseudo="p1", component="rbr",
                   basis_outcome="permitted")
        log.entries[0].action = "enrolled"  # tamper
        with self.assertRaises(ValueError):
            log.verify()

    def test_persist_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "audit.jsonl"
            log = al.AuditLog(p)
            log.append(action="scrape", subject_pseudo="p2", component="scrape",
                       basis_outcome="permitted")
            log2 = al.AuditLog(p)
            self.assertEqual(len(log2.all()), 1)
            self.assertEqual(log2.all()[0].hash, log.all()[0].hash)
            log2.append(action="revoke", subject_pseudo="p2", component="train",
                        basis_outcome="permitted")
            log2.verify()
            lines = p.read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[1])["prev_hash"], json.loads(lines[0])["hash"])

    def test_pseudo_stable(self):
        self.assertEqual(al.pseudo("x"), al.pseudo("x"))
        self.assertNotEqual(al.pseudo("x"), al.pseudo("y"))


if __name__ == "__main__":
    unittest.main()