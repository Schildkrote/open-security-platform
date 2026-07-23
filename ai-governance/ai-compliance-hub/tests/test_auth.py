"""Tests for the shared HS256 JWT auth helper."""
from __future__ import annotations

import time
import unittest

from compliance_hub import auth

SECRET = "test-secret"


class FakeHeaders(dict):
    def get(self, key, default=None):  # mimic http.server headers
        return super().get(key, default)


class AuthTests(unittest.TestCase):
    def test_sign_verify_round_trip(self):
        token = auth.issue_token("alice", ["read", "admin"], 60, SECRET)
        claims = auth.verify(token, SECRET)
        self.assertEqual(claims["sub"], "alice")
        self.assertTrue(auth.has_scope(claims, "admin"))
        self.assertFalse(auth.has_scope(claims, "missing"))

    def test_wrong_secret_rejected(self):
        token = auth.issue_token("alice", [], 60, SECRET)
        with self.assertRaises(ValueError):
            auth.verify(token, "other")

    def test_tampered_rejected(self):
        token = auth.issue_token("alice", [], 60, SECRET)
        with self.assertRaises(ValueError):
            auth.verify(token + "x", SECRET)

    def test_expired_rejected(self):
        token = auth.issue_token("alice", [], -10, SECRET)
        with self.assertRaises(ValueError):
            auth.verify(token, SECRET)

    def test_authorized(self):
        token = auth.issue_token("alice", ["admin"], 60, SECRET)
        self.assertTrue(auth.authorized(FakeHeaders(Authorization=f"Bearer {token}"), SECRET, "admin"))
        self.assertFalse(auth.authorized(FakeHeaders(Authorization=f"Bearer {token}"), SECRET, "super"))
        self.assertFalse(auth.authorized(FakeHeaders(), SECRET, "admin"))
        # empty secret => auth disabled
        self.assertTrue(auth.authorized(FakeHeaders(), "", "admin"))

    def test_exp_not_required(self):
        token = auth.sign({"sub": "svc"}, SECRET)
        self.assertEqual(auth.verify(token, SECRET)["sub"], "svc")
        self.assertLessEqual(auth.verify(token, SECRET).get("exp", 0), int(time.time()) + 1)


if __name__ == "__main__":
    unittest.main()
