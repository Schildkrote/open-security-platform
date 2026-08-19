# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Golden tests: basis_matrix.decide must conform to matrix.json.

Mirrors ``platform/lawful-basis/matrix_test.go`` (TestDecideConformsToMatrix).
If these pass and the Go tests pass, the Python and Go engines agree with
the matrix on every (purpose, category, consent, dpia, le) combination.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from basis_matrix import (  # noqa: E402
    PERMITTED,
    PROHIBITED,
    REQUIRES_CONSENT,
    REQUIRES_DPIA,
    decide,
)

MATRIX = Path(__file__).resolve().parent.parent.parent / "lawful-basis" / "matrix.json"


def interpret(m: dict, purpose: str, category: str, consent: bool, dpia: bool, le: bool, retain: int):
    """Reference decision over the matrix (same canonical order as the Go test)."""
    purposes = m["purposes"]
    spec = purposes.get(purpose)
    canonical = purpose
    if spec is None:
        for name, p in purposes.items():
            if purpose in (p.get("aliases") or []):
                spec, canonical = p, name
                break
    if spec is None:
        return PROHIBITED, 0

    cap = m["retention_max_days"]["general"]
    if m["categories"].get(category, {}).get("special"):
        cap = m["retention_max_days"]["special"]
    retention = 0
    if retain > 0:
        retention = min(retain, cap)

    if canonical == "untargeted_mass_id":
        return PROHIBITED, 0
    if canonical == "rbr_public" and not le:
        return PROHIBITED, 0
    if canonical == "rbr_public" and not dpia:
        return REQUIRES_DPIA, retention
    special = m["categories"].get(category, {}).get("special", False)
    if special and not dpia:
        return REQUIRES_DPIA, retention
    if special and not consent and canonical != "rbr_public":
        return REQUIRES_CONSENT, retention
    rule = spec.get("rule")
    if rule == "prohibited":
        return PROHIBITED, 0
    if rule == "le+dpia":
        return PERMITTED, retention
    if rule == "consent":
        if not consent:
            return REQUIRES_CONSENT, retention
        return PERMITTED, retention
    if rule == "consent+dpia":
        if not consent:
            return REQUIRES_CONSENT, retention
        if not dpia:
            return REQUIRES_DPIA, retention
        return PERMITTED, retention
    raise AssertionError(f"unknown rule {rule!r}")


CASES = [(False, False, False), (True, False, False), (False, True, False),
         (True, True, False), (False, True, True), (True, True, True)]


class TestBasisMatrixGolden(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(MATRIX, encoding="utf-8") as f:
            cls.m = json.load(f)

    def test_decide_conforms_to_matrix(self):
        categories = ["", "general", "public_figure", "employee", "minor",
                      "health_context", "religion_context"]
        purposes = []
        for name, p in self.m["purposes"].items():
            purposes.append(name)
            purposes.extend(p.get("aliases") or [])
        purposes.append("not_a_real_purpose")

        for purpose in purposes:
            for cat in categories:
                for consent, dpia, le in CASES:
                    for retain in (0, 30, 365):
                        got = decide(
                            purpose,
                            category=cat or "general",
                            retention_days=retain,
                            has_consent=consent,
                            dpia_acknowledged=dpia,
                            is_law_enforcement=le,
                        )
                        want_out, want_ret = interpret(
                            self.m, purpose, cat or "general", consent, dpia, le, retain)
                        self.assertEqual(
                            got.outcome, want_out,
                            f"purpose={purpose!r} cat={cat!r} consent={consent} dpia={dpia} "
                            f"le={le} retain={retain}: outcome {got.outcome}, matrix wants "
                            f"{want_out} (reason: {got.reason})")
                        self.assertEqual(
                            got.retention_max, want_ret,
                            f"purpose={purpose!r} cat={cat!r} consent={consent} dpia={dpia} "
                            f"le={le} retain={retain}: retention {got.retention_max}, "
                            f"matrix wants {want_ret}")

    def test_matrix_standard_retention_honoured(self):
        for name, p in self.m["purposes"].items():
            d = decide(
                name,
                category="general",
                retention_days=p["retention_days"],
                has_consent=True,
                dpia_acknowledged=True,
                is_law_enforcement=True,
            )
            self.assertEqual(
                d.retention_max, p["retention_days"],
                f"requesting {name} standard retention {p['retention_days']} "
                f"returns {d.retention_max}")

    def test_untargeted_mass_id_always_prohibited(self):
        for consent, dpia, le in CASES:
            d = decide("untargeted_mass_id", has_consent=consent,
                       dpia_acknowledged=dpia, is_law_enforcement=le)
            self.assertEqual(d.outcome, PROHIBITED)
            self.assertEqual(d.retention_max, 0)

    def test_rbr_public_gates(self):
        # non-LE: prohibited even with consent+dpia
        d = decide("rbr_public", has_consent=True, dpia_acknowledged=True)
        self.assertEqual(d.outcome, PROHIBITED)
        # LE without DPiA: requires_dpia
        d = decide("rbr_public", is_law_enforcement=True)
        self.assertEqual(d.outcome, REQUIRES_DPIA)
        # LE + DPiA: permitted
        d = decide("rbr_public", is_law_enforcement=True, dpia_acknowledged=True)
        self.assertEqual(d.outcome, PERMITTED)


if __name__ == "__main__":
    unittest.main()