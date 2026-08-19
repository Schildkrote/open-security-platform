"""Training-data corpus: authorized, basis-gated sources for high-quality FR data.

Sources never silently scrape the public. Each source declares its lawful
basis requirements. CCTV is only accepted as:
  - client-owned / client-authorized private premises feeds
  - research datasets with redistributable licenses
  - synthetic / rendered footage

Open internet CCTV indexes are documented as *discovery references* only;
ingestion still requires an authorization record (owner consent or dataset
license) bound to the client or research purpose.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Protocol


def pseudo(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Authorization:
    """Proof that we may use a source for a purpose."""

    kind: str  # client_consent | owner_consent | dataset_license | synthetic | le_warrant
    holder: str  # client_id, owner name, dataset id, etc.
    purposes: tuple[str, ...]
    notes: str = ""
    expires_at: float | None = None
    revoked: bool = False

    def valid_for(self, purpose: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        if self.revoked:
            return False
        if self.expires_at is not None and now > self.expires_at:
            return False
        return purpose in self.purposes


@dataclass
class CorpusItem:
    item_id: str
    client_id: str  # enrolled client this supports (or "" for foundation pretrain)
    image_hash: str
    source_type: str  # client_upload | cctv_authorized | research_dataset | synthetic
    quality: float  # 0..1
    path: str = ""
    meta: dict = field(default_factory=dict)
    auth_kind: str = ""
    ingested_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IngestResult:
    accepted: list[CorpusItem]
    rejected: list[tuple[str, str]]  # (ref, reason)
    basis_ok: bool
    basis_reason: str

    def to_dict(self) -> dict:
        return {
            "basis_ok": self.basis_ok,
            "basis_reason": self.basis_reason,
            "accepted": [a.to_dict() for a in self.accepted],
            "rejected": [{"ref": r, "reason": why} for r, why in self.rejected],
        }


class CorpusSource(Protocol):
    name: str
    source_type: str

    def list_candidates(self, limit: int = 100) -> list[dict]:
        """Return candidate dicts with at least image_hash and optional path/quality."""
        ...


@dataclass
class MockClientUploadSource:
    """Synthetic client-provided stills (offline)."""

    client_id: str
    n: int = 10
    name: str = "mock_client_upload"
    source_type: str = "client_upload"

    def list_candidates(self, limit: int = 100) -> list[dict]:
        out = []
        for i in range(min(self.n, limit)):
            h = f"{self.client_id}-upload-{i}"
            out.append(
                {
                    "image_hash": h,
                    "path": "",
                    "quality": 0.85 + (i % 3) * 0.05,
                    "meta": {"pose": ["frontal", "three_quarter", "profile"][i % 3]},
                }
            )
        return out


@dataclass
class MockAuthorizedCCTVSource:
    """Synthetic frames from a client-authorized private CCTV feed.

    Real connector would pull RTSP/ONVIF from an allowlisted endpoint with
    owner consent on file — never from random open internet streams.
    """

    client_id: str
    camera_id: str = "cam-lobby-1"
    n: int = 20
    name: str = "mock_cctv_authorized"
    source_type: str = "cctv_authorized"

    def list_candidates(self, limit: int = 100) -> list[dict]:
        out = []
        for i in range(min(self.n, limit)):
            h = f"{self.client_id}-cctv-{self.camera_id}-{i}"
            # Simulate quality drop for motion blur / low light.
            q = 0.55 + (i % 5) * 0.08
            out.append(
                {
                    "image_hash": h,
                    "path": "",
                    "quality": min(1.0, q),
                    "meta": {
                        "camera_id": self.camera_id,
                        "lighting": ["day", "night", "backlit"][i % 3],
                        "resolution": "1080p",
                    },
                }
            )
        return out


@dataclass
class MockResearchDatasetSource:
    """Curated research / licensed dataset slices (e.g. VGGFace2-class).

    Real use requires the dataset license to allow training and redistribution
    constraints to be respected. Foundation pretrain only — not mixed into a
    client model without separate basis.
    """

    dataset_id: str = "synthetic-faces-v1"
    n: int = 50
    name: str = "mock_research_dataset"
    source_type: str = "research_dataset"

    def list_candidates(self, limit: int = 100) -> list[dict]:
        out = []
        for i in range(min(self.n, limit)):
            h = f"{self.dataset_id}-{i:05d}"
            out.append(
                {
                    "image_hash": h,
                    "path": "",
                    "quality": 0.9,
                    "meta": {"dataset": self.dataset_id, "split": "train"},
                }
            )
        return out


@dataclass
class MockSyntheticSource:
    """Rendered / GAN / diffusion synthetic identities (no real persons)."""

    n: int = 30
    name: str = "mock_synthetic"
    source_type: str = "synthetic"

    def list_candidates(self, limit: int = 100) -> list[dict]:
        return [
            {
                "image_hash": f"syn-{i:05d}",
                "path": "",
                "quality": 0.95,
                "meta": {"renderer": "mock-diffusion"},
            }
            for i in range(min(self.n, limit))
        ]


# Open-stream discovery is intentionally NOT a Source that can ingest.
# It only returns documentation / operator checklist entries.
OPEN_CCTV_DISCOVERY_NOTES = {
    "warning": (
        "Publicly reachable CCTV/IP-cam indexes exist on the internet, but "
        "ingesting faces from them for recognition training is almost always "
        "unlawful without the camera owner's authorization and a valid basis "
        "for each data subject. This platform will not auto-ingest open streams."
    ),
    "discovery_only_examples": [
        {
            "class": "insecam-style public indexes",
            "use": "NOT for training ingest",
            "why": "No subject consent; often no owner authorization; untargeted mass collection",
        },
        {
            "class": "shodan/censys dorks for RTSP/HTTP cams",
            "use": "security research / exposure notification only",
            "why": "Accessing third-party cams without authorization is illegal in most regimes",
        },
        {
            "class": "municipal open-data traffic cams",
            "use": "only if license explicitly allows biometric processing (rare)",
            "why": "Usually published for traffic, not face recognition; still special-category risk",
        },
    ],
    "allowed_cctv_paths": [
        "Client-owned NVR export of premises where the client is the controller and subjects are signed-in / noticed",
        "Third-party venue with written owner_consent + client consent if matching the client",
        "Licensed research corpora that include CCTV-like conditions (e.g. surveillance face benchmarks with terms)",
        "Synthetic CCTV-style renders",
    ],
}


@dataclass
class Corpus:
    """In-memory corpus with authorization checks on every ingest."""

    items: list[CorpusItem] = field(default_factory=list)
    authorizations: list[Authorization] = field(default_factory=list)
    min_quality: float = 0.5

    def add_authorization(self, auth: Authorization) -> None:
        self.authorizations.append(auth)

    def _auth_ok(self, purpose: str, source_type: str, holder: str) -> tuple[bool, str, str]:
        """Return (ok, reason, auth_kind)."""
        # Synthetic always ok for foundation/pretrain.
        if source_type == "synthetic":
            return True, "synthetic data (no real subject)", "synthetic"

        purpose_needed = purpose
        for a in self.authorizations:
            if a.revoked:
                continue
            if not a.valid_for(purpose_needed):
                continue
            # client_upload / cctv_authorized must match holder to client or owner.
            if source_type == "client_upload" and a.kind == "client_consent" and a.holder == holder:
                return True, "client_consent", a.kind
            if source_type == "cctv_authorized" and a.kind in {"owner_consent", "client_consent"} and a.holder == holder:
                return True, f"{a.kind} for cctv", a.kind
            if source_type == "research_dataset" and a.kind == "dataset_license" and a.holder == holder:
                return True, "dataset_license", a.kind
        return False, f"no valid authorization for source_type={source_type} holder={holder} purpose={purpose}", ""

    def ingest(
        self,
        source: CorpusSource,
        *,
        client_id: str,
        purpose: str = "training",
        holder: str | None = None,
        limit: int = 100,
    ) -> IngestResult:
        holder = holder if holder is not None else client_id
        # Hard ban: anything claiming open_cctv / untargeted.
        if source.source_type in {"open_cctv", "untargeted_web", "insecam"}:
            return IngestResult(
                accepted=[],
                rejected=[(source.name, "open/untargeted CCTV ingest is prohibited")],
                basis_ok=False,
                basis_reason="prohibited source_type",
            )

        ok, reason, auth_kind = self._auth_ok(purpose, source.source_type, holder)
        if not ok:
            return IngestResult(
                accepted=[],
                rejected=[(source.name, reason)],
                basis_ok=False,
                basis_reason=reason,
            )

        accepted: list[CorpusItem] = []
        rejected: list[tuple[str, str]] = []
        for cand in source.list_candidates(limit=limit):
            h = str(cand.get("image_hash", "")).strip()
            if not h:
                rejected.append(("?", "missing image_hash"))
                continue
            q = float(cand.get("quality", 1.0))
            if q < self.min_quality:
                rejected.append((h, f"quality {q:.2f} < min_quality {self.min_quality}"))
                continue
            item = CorpusItem(
                item_id=f"{source.source_type}:{h}",
                client_id=client_id,
                image_hash=h,
                source_type=source.source_type,
                quality=q,
                path=str(cand.get("path", "")),
                meta=dict(cand.get("meta") or {}),
                auth_kind=auth_kind,
            )
            accepted.append(item)
            self.items.append(item)
        return IngestResult(
            accepted=accepted,
            rejected=rejected,
            basis_ok=True,
            basis_reason=reason,
        )

    def for_client(self, client_id: str) -> list[CorpusItem]:
        return [i for i in self.items if i.client_id == client_id]

    def quality_report(self, client_id: str | None = None) -> dict:
        items = self.items if client_id is None else self.for_client(client_id)
        if not items:
            return {"n": 0, "by_source": {}, "mean_quality": 0.0}
        by: dict[str, int] = {}
        qsum = 0.0
        for i in items:
            by[i.source_type] = by.get(i.source_type, 0) + 1
            qsum += i.quality
        return {
            "n": len(items),
            "by_source": by,
            "mean_quality": qsum / len(items),
            "min_quality": min(i.quality for i in items),
            "max_quality": max(i.quality for i in items),
        }

    def export_hashes(self, client_id: str) -> list[tuple[str, float, str]]:
        """(image_hash, quality, source_type) for Gallery.enrol."""
        return [(i.image_hash, i.quality, i.source_type) for i in self.for_client(client_id)]

    def save(self, path: str | Path) -> None:
        data = {
            "min_quality": self.min_quality,
            "authorizations": [asdict(a) for a in self.authorizations],
            "items": [i.to_dict() for i in self.items],
        }
        # dataclasses with tuple purposes
        for a in data["authorizations"]:
            a["purposes"] = list(a["purposes"])
        Path(path).write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str | Path) -> "Corpus":
        data = json.loads(Path(path).read_text())
        c = cls(min_quality=float(data.get("min_quality", 0.5)))
        for a in data.get("authorizations", []):
            c.authorizations.append(
                Authorization(
                    kind=a["kind"],
                    holder=a["holder"],
                    purposes=tuple(a["purposes"]),
                    notes=a.get("notes", ""),
                    expires_at=a.get("expires_at"),
                    revoked=a.get("revoked", False),
                )
            )
        for i in data.get("items", []):
            c.items.append(CorpusItem(**i))
        return c


def open_cctv_policy() -> dict:
    """Return the discovery-only policy document (never enables ingest)."""
    return dict(OPEN_CCTV_DISCOVERY_NOTES)
