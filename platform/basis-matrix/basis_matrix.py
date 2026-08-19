# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Reference lawful-basis decision engine for the Python components.

This is the Python port of the Go engine in ``platform/lawful-basis``. The
single source of truth is ``platform/lawful-basis/matrix.json``; both
implementations must conform to it and are pinned by golden tests:

  * Go:     ``platform/lawful-basis/matrix_test.go`` (TestDecideConformsToMatrix)
  * Python: ``platform/basis-matrix/tests/test_matrix.py``

Do NOT fork the decision logic again inside components — call
:func:`decide_basis` (or :func:`check`) from here. The historical forks in
``train`` and ``scrape`` now delegate to this module.

Canonical decision order (mirrors matrix.json ``$comment``):

  1. normalize purpose aliases and defaults
  2. unknown purpose -> prohibited
  3. hard prohibitions (untargeted_mass_id always; rbr_public without LE)
  4. rbr_public LE without acknowledged DPiA -> requires_dpia
  5. special category without DPiA -> requires_dpia
  6. special category without consent (non-LE) -> requires_consent
  7. purpose rule (consent / consent+dpia / le+dpia / prohibited)
  8. permitted

Retention: ``retention_max = clamp(requested, cap)``; requested <= 0 stays 0;
prohibited -> 0. The matrix's ``retention_days`` is the standard request
callers pass, not something the engine applies on its own.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

MATRIX_PATH = Path(__file__).resolve().parent.parent.parent / "platform" / "lawful-basis" / "matrix.json"

PERMITTED = "permitted"
REQUIRES_CONSENT = "requires_consent"
REQUIRES_DPIA = "requires_dpia"
PROHIBITED = "prohibited"


@dataclass(frozen=True)
class Decision:
    """Outcome of :func:`decide` / :func:`check`."""

    outcome: str
    purpose: str
    regime: str
    category: str
    reason: str
    retention_max: int
    requires_audit: bool = True


@lru_cache(maxsize=1)
def _matrix() -> dict:
    with open(MATRIX_PATH, encoding="utf-8") as f:
        return json.load(f)


def _resolve_alias(m: dict, purpose: str) -> Tuple[dict, str]:
    """Resolve purpose aliases to (purpose_spec, canonical_name)."""
    purposes = m["purposes"]
    if purpose in purposes:
        return purposes[purpose], purpose
    for name, spec in purposes.items():
        if purpose in (spec.get("aliases") or []):
            return spec, name
    return {}, purpose


def decide(
    purpose: str,
    *,
    regime: str = "",
    category: str = "",
    retention_days: int = 0,
    has_consent: bool = False,
    dpia_acknowledged: bool = False,
    is_law_enforcement: bool = False,
) -> Decision:
    """Apply the regime x purpose x category matrix.

    This is the single decision point for every face-touching Python
    component. It is pinned to ``matrix.json`` by the golden tests; see the
    module docstring for the canonical order.
    """
    m = _matrix()

    purpose = (purpose or "").strip().lower()
    regime = (regime or "").strip().lower() or m["default_regime"]
    category = (category or "").strip().lower() or m["default_category"]

    # Step 1: aliases (client_protection -> targeted_search, corpus_ingest -> training).
    spec, canonical = _resolve_alias(m, purpose)

    # Retention: clamp(requested, cap); requested <= 0 stays 0; prohibited -> 0.
    cap = m["retention_max_days"]["general"]
    if m["categories"].get(category, {}).get("special"):
        cap = m["retention_max_days"]["special"]
    retention = 0
    if retention_days > 0:
        retention = min(retention_days, cap)

    def out(outcome: str, reason: str, ret: int = retention) -> Decision:
        return Decision(
            outcome=outcome,
            purpose=canonical,
            regime=regime,
            category=category,
            reason=reason,
            retention_max=ret,
        )

    # Step 2: unknown purpose -> prohibited.
    if not spec:
        return out(PROHIBITED, f'unknown or unsupported purpose "{purpose}"', 0)

    # Step 3: hard prohibitions.
    if canonical == "untargeted_mass_id":
        return out(PROHIBITED, "untargeted mass biometric ID of the public is prohibited by product policy and AI Act Art. 5", 0)
    if canonical == "rbr_public" and not is_law_enforcement:
        return out(PROHIBITED, "RBRIS in public spaces without LE statutory basis is prohibited (AI Act Art. 5)", 0)

    # Step 4: LE RBR without DPiA.
    if canonical == "rbr_public" and not dpia_acknowledged:
        return out(REQUIRES_DPIA, "LE RBRIS requires an acknowledged DPiA")

    special = m["categories"].get(category, {}).get("special", False)

    # Step 5: special category without DPiA.
    if special and not dpia_acknowledged:
        return out(REQUIRES_DPIA, f'category "{category}" is special-category; DPiA required')

    # Step 6: special category without consent (non-LE).
    if special and not has_consent and canonical != "rbr_public":
        return out(REQUIRES_CONSENT, f'category "{category}" requires explicit consent even with DPiA (non-LE)')

    # Step 7: purpose rule.
    rule = spec.get("rule")
    if rule == "prohibited":
        return out(PROHIBITED, f'purpose "{canonical}" is prohibited', 0)
    if rule == "le+dpia":
        # Steps 3-4 already gated LE + DPiA.
        return out(PERMITTED, "LE RBRIS with DPiA")
    if rule == "consent":
        if not has_consent:
            return out(REQUIRES_CONSENT, f'purpose "{canonical}" requires valid client consent')
        return out(PERMITTED, f"client consent present for purpose {canonical} under {regime}")
    if rule == "consent+dpia":
        if not has_consent:
            return out(REQUIRES_CONSENT, f'purpose "{canonical}" requires valid client consent')
        if not dpia_acknowledged:
            return out(REQUIRES_DPIA, f'purpose "{canonical}" requires DPiA')
        return out(PERMITTED, f"consent + DPiA present for purpose {canonical} under {regime}")

    return out(PROHIBITED, f'unknown rule "{rule}" for purpose "{canonical}"', 0)


def check(
    purpose: str,
    has_consent: bool,
    category: str = "general",
    retention_days: int = 0,
    dpia_acknowledged: bool = False,
    is_law_enforcement: bool = False,
) -> Decision:
    """Convenience wrapper matching the historical component call shape."""
    return decide(
        purpose,
        category=category,
        retention_days=retention_days,
        has_consent=has_consent,
        dpia_acknowledged=dpia_acknowledged,
        is_law_enforcement=is_law_enforcement,
    )


# Backwards-compatible name used by the historical forks.
decide_basis = check

__all__ = [
    "Decision",
    "PERMITTED",
    "REQUIRES_CONSENT",
    "REQUIRES_DPIA",
    "PROHIBITED",
    "check",
    "decide",
    "decide_basis",
]