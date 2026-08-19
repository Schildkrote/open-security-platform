"""Consent-gated targeted scrape for enrolled clients."""
from __future__ import annotations

import hashlib
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

# Single source of truth for lawful-basis decisions: platform/basis-matrix.
# The historical mirror below is gone; decide_basis now delegates there.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "platform" / "basis-matrix"))
import basis_matrix as _bm  # noqa: E402

# Hash-chained audit log: platform/audit-log.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "platform" / "audit-log"))
import audit_log as _al  # noqa: E402


def pseudo(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class Consent:
    client_id: str
    purposes: tuple[str, ...]
    revoked: bool = False

    def covers(self, purpose: str) -> bool:
        return (not self.revoked) and purpose in self.purposes


@dataclass
class BasisDecision:
    """Adapter around basis_matrix.Decision (keeps the historical shape)."""

    outcome: str
    reason: str
    retention_max_days: int = 0
    purpose: str = ""
    category: str = "general"

    def allowed(self) -> bool:
        return self.outcome == "permitted"


def decide_basis(
    purpose: str,
    *,
    has_consent: bool,
    category: str = "general",
    dpia: bool = False,
    is_le: bool = False,
    retention_days: int = 0,
) -> BasisDecision:
    """Delegates to platform/basis-matrix (single source of truth).

    retention_days defaults to the matrix standard for the purpose (30) so
    audit entries carry a meaningful retention ceiling.
    """
    if retention_days == 0:
        retention_days = 30
    d = _bm.decide(
        purpose,
        has_consent=has_consent,
        category=category,
        retention_days=retention_days,
        dpia_acknowledged=dpia,
        is_law_enforcement=is_le,
    )
    return BasisDecision(
        outcome=d.outcome,
        reason=d.reason,
        retention_max_days=d.retention_max,
        purpose=d.purpose,
        category=d.category,
    )


@dataclass
class CropRecord:
    """Minimised face record — no raw pixels by default."""

    crop_id: str
    subject_pseudo: str
    source: str
    bbox: tuple[int, int, int, int]
    timestamp: float
    category: str = "general"
    image_hash: str = ""
    raw_path: str = ""  # only if retain_raw

    def to_dict(self) -> dict:
        return asdict(self)


class Source(Protocol):
    name: str

    def fetch(self, client_id: str, limit: int = 10) -> list[CropRecord]: ...


@dataclass
class MockSource:
    """Deterministic offline source of synthetic crops for one client."""

    name: str = "mock"

    def fetch(self, client_id: str, limit: int = 10) -> list[CropRecord]:
        out: list[CropRecord] = []
        sp = pseudo(client_id)
        for i in range(min(limit, 5)):
            cid = f"mock-{client_id}-{i}"
            out.append(
                CropRecord(
                    crop_id=cid,
                    subject_pseudo=sp,
                    source="mock",
                    bbox=(10 + i, 20, 100, 120),
                    timestamp=time.time(),
                    category="general",
                    image_hash=pseudo(cid),
                )
            )
        return out


@dataclass
class WebSource:
    """Live web source: only hits URLs on an allowlist. Offline-safe if empty."""

    allowlist: list[str] = field(default_factory=list)
    name: str = "web"

    def fetch(self, client_id: str, limit: int = 10) -> list[CropRecord]:
        # Real HTTP is intentionally not implemented in the OSS core without
        # an allowlist entry + network. Empty allowlist → empty result.
        if not self.allowlist:
            return []
        raise RuntimeError("live web fetch requires user-supplied connector")


@dataclass
class ScrapeRun:
    client_id: str
    source: str
    basis: BasisDecision
    crops: list[CropRecord]
    refused: bool = False
    refuse_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "source": self.source,
            "basis": asdict(self.basis),
            "refused": self.refused,
            "refuse_reason": self.refuse_reason,
            "crops": [c.to_dict() for c in self.crops],
        }


def run_scrape(
    client_id: str,
    consent: Consent | None,
    source: Source,
    *,
    purpose: str = "targeted_search",
    category: str = "general",
    limit: int = 10,
    retain_raw: bool = False,
    audit: _al.AuditLog | None = None,
) -> ScrapeRun:
    has = bool(consent and consent.covers(purpose))
    decision = decide_basis(purpose, has_consent=has, category=category)
    log = audit if audit is not None else _al.AuditLog()
    if not decision.allowed():
        log.append(
            action="scrape",
            subject_pseudo=pseudo(client_id),
            component="scrape",
            basis_outcome=decision.outcome,
            basis_reason=decision.reason,
            basis_purpose=decision.purpose,
            retention_max_days=decision.retention_max_days,
            detail=f"refused source={source.name} reason={decision.reason}",
        )
        return ScrapeRun(
            client_id=client_id,
            source=source.name,
            basis=decision,
            crops=[],
            refused=True,
            refuse_reason=decision.reason,
        )
    crops = source.fetch(client_id, limit=limit)
    if not retain_raw:
        for c in crops:
            c.raw_path = ""
    log.append(
        action="scrape",
        subject_pseudo=pseudo(client_id),
        component="scrape",
        basis_outcome=decision.outcome,
        basis_reason=decision.reason,
        basis_purpose=decision.purpose,
        retention_max_days=decision.retention_max_days,
        detail=f"n_crops={len(crops)} source={source.name} retain_raw={retain_raw}",
    )
    return ScrapeRun(
        client_id=client_id,
        source=source.name,
        basis=decision,
        crops=crops,
    )
