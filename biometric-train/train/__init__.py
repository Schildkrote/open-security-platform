"""Client-permissioned FR training.

Mock trainer: builds a centroid embedding per client from enrolled image
hashes (deterministic, offline). Real embedders (table/onnx) plug in via
Gallery(embedder=...) or --embedder on the CLI once user-supplied weights
or precomputed tables exist.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from train.embedder import Embedder, MockEmbedder, cosine, make_embedder

# Single source of truth for lawful-basis decisions: platform/basis-matrix.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "platform" / "basis-matrix"))
import basis_matrix as _bm  # noqa: E402

# Hash-chained audit log: platform/audit-log.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "platform" / "audit-log"))
import audit_log as _al  # noqa: E402

DIM = 32


def pseudo(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def embed_hash(image_hash: str, emb: Embedder | None = None) -> list[float]:
    """Back-compat helper: embed via mock (or provided embedder)."""
    e = emb or MockEmbedder(dim=DIM)
    return e.embed(image_hash)


@dataclass
class Consent:
    client_id: str
    purposes: tuple[str, ...]
    revoked: bool = False
    granted_at: float = field(default_factory=time.time)

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
class EnrolledImage:
    image_hash: str
    embedding: list[float]
    enrolled_at: float
    image_path: str = ""
    source: str = "enrol"
    quality: float = 1.0


@dataclass
class ClientModel:
    client_id: str
    subject_pseudo: str
    centroid: list[float]
    n_images: int
    trained_at: float
    version: int = 1
    embedder: str = "mock"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Gallery:
    """In-memory training gallery keyed by client_id.

    Every face-touching operation (enrol/train/revoke) appends an entry to
    the hash-chained audit log (``self.audit``), carrying the lawful-basis
    decision. Pass ``audit=`` or ``audit_path=`` to enable; by default a
    log exists so the chain is always tamper-evident, but only a path
    persists it to disk.
    """

    clients: dict[str, list[EnrolledImage]] = field(default_factory=dict)
    consents: dict[str, Consent] = field(default_factory=dict)
    models: dict[str, ClientModel] = field(default_factory=dict)
    embedder: Embedder = field(default_factory=MockEmbedder)
    audit: _al.AuditLog = field(default_factory=_al.AuditLog)

    @property
    def audit_path(self) -> Path | None:
        return self.audit.path

    def set_audit_path(self, path: str | Path) -> None:
        """Point the gallery's audit log at a JSONL file (persists entries)."""
        self.audit = _al.AuditLog(Path(path))

    def _audit(self, action: str, client_id: str, d: BasisDecision, detail: str = "") -> None:
        self.audit.append(
            action=action,
            subject_pseudo=pseudo(client_id),
            component="train",
            basis_outcome=d.outcome,
            basis_reason=d.reason,
            basis_purpose=d.purpose,
            retention_max_days=d.retention_max_days,
            detail=detail,
        )

    def set_consent(self, consent: Consent) -> None:
        self.consents[consent.client_id] = consent

    def set_embedder(self, emb: Embedder) -> None:
        self.embedder = emb

    def _embed(self, image_hash: str, image_path: str = "") -> list[float]:
        return self.embedder.embed(image_hash, image_path or None)

    def enrol(
        self,
        client_id: str,
        image_hashes: Iterable[str],
        *,
        category: str = "general",
        paths: dict[str, str] | None = None,
        source: str = "enrol",
        quality: float = 1.0,
        qualities: dict[str, float] | None = None,
    ) -> tuple[int, BasisDecision]:
        c = self.consents.get(client_id)
        has = bool(c and c.covers("enrolment"))
        d = decide_basis("enrolment", has, category)
        if not d.allowed():
            self._audit("enrol", client_id, d, detail=f"refused reason={d.reason}")
            return 0, d
        bucket = self.clients.setdefault(client_id, [])
        n = 0
        existing = {e.image_hash for e in bucket}
        paths = paths or {}
        qualities = qualities or {}
        for h in image_hashes:
            h = h.strip()
            if not h or h in existing:
                continue
            p = paths.get(h, "")
            q = float(qualities.get(h, quality))
            bucket.append(
                EnrolledImage(
                    image_hash=h,
                    embedding=self._embed(h, p),
                    enrolled_at=time.time(),
                    image_path=p,
                    source=source,
                    quality=q,
                )
            )
            existing.add(h)
            n += 1
        self._audit("enrol", client_id, d, detail=f"n_enrolled={n} source={source}")
        return n, d

    def enrol_from_corpus(
        self,
        client_id: str,
        items: Iterable[tuple[str, float, str]],
        *,
        category: str = "general",
    ) -> tuple[int, BasisDecision]:
        """items: (image_hash, quality, source_type)."""
        items = list(items)
        if not items:
            return 0, decide_basis("enrolment", True, category)
        # Enrol per source group so source tags stick.
        total = 0
        last = decide_basis("enrolment", False, category)
        by_src: dict[str, list[tuple[str, float]]] = {}
        for h, q, src in items:
            by_src.setdefault(src, []).append((h, q))
        for src, pairs in by_src.items():
            hashes = [h for h, _ in pairs]
            quals = {h: q for h, q in pairs}
            n, last = self.enrol(
                client_id, hashes, category=category, source=src, qualities=quals
            )
            total += n
            if not last.allowed():
                return total, last
        return total, last

    def train(self, client_id: str, *, category: str = "general") -> tuple[ClientModel | None, BasisDecision]:
        c = self.consents.get(client_id)
        has = bool(c and c.covers("training"))
        d = decide_basis("training", has, category)
        if not d.allowed():
            self._audit("train", client_id, d, detail=f"refused reason={d.reason}")
            return None, d
        images = self.clients.get(client_id) or []
        if not images:
            ed = BasisDecision("prohibited", "no enrolled images", 0)
            self._audit("train", client_id, ed, detail="empty gallery")
            return None, ed
        dim = len(images[0].embedding)
        acc = [0.0] * dim
        wsum = 0.0
        for im in images:
            w = max(0.01, float(im.quality))
            wsum += w
            for i, v in enumerate(im.embedding):
                acc[i] += v * w
        acc = [x / wsum for x in acc]
        norm = math.sqrt(sum(x * x for x in acc)) or 1.0
        centroid = [x / norm for x in acc]
        prev = self.models.get(client_id)
        version = (prev.version + 1) if prev else 1
        model = ClientModel(
            client_id=client_id,
            subject_pseudo=pseudo(client_id),
            centroid=centroid,
            n_images=len(images),
            trained_at=time.time(),
            version=version,
            embedder=self.embedder.name,
        )
        self.models[client_id] = model
        self._audit("train", client_id, d,
                    detail=f"version={model.version} n_images={model.n_images} embedder={model.embedder}")
        return model, d

    def revoke(self, client_id: str) -> dict:
        c = self.consents.get(client_id)
        if c:
            c.revoked = True
        n_img = len(self.clients.pop(client_id, []))
        had_model = self.models.pop(client_id, None) is not None
        d = BasisDecision("permitted", "consent revocation purges biometric data", 0)
        self._audit("revoke", client_id, d,
                    detail=f"images_purged={n_img} model_purged={had_model}")
        return {"images_purged": n_img, "model_purged": had_model}

    def identify(
        self, image_hash: str, threshold: float = 0.82, image_path: str = ""
    ) -> list[tuple[str, float]]:
        d = decide_basis("targeted_search", True, "general")
        probe = self._embed(image_hash, image_path)
        hits: list[tuple[str, float]] = []
        for cid, images in self.clients.items():
            c = self.consents.get(cid)
            if not c or c.revoked:
                continue
            if not (c.covers("training") or c.covers("targeted_search")):
                continue
            best = 0.0
            for im in images:
                best = max(best, cosine(probe, im.embedding))
            model = self.models.get(cid)
            if model is not None:
                best = max(best, cosine(probe, model.centroid))
            if best >= threshold:
                hits.append((cid, best))
        hits.sort(key=lambda x: -x[1])
        self._audit(
            "identify", image_hash, d,
            detail=f"n_hits={len(hits)} threshold={threshold} probe={pseudo(image_hash)}",
        )
        return hits

    def save(self, path: str | Path) -> None:
        path = Path(path)
        data = {
            "embedder": self.embedder.name,
            "consents": {
                k: {
                    "client_id": v.client_id,
                    "purposes": list(v.purposes),
                    "revoked": v.revoked,
                    "granted_at": v.granted_at,
                }
                for k, v in self.consents.items()
            },
            "clients": {
                k: [
                    {
                        "image_hash": i.image_hash,
                        "enrolled_at": i.enrolled_at,
                        "image_path": i.image_path,
                        "source": i.source,
                        "quality": i.quality,
                        "embedding": i.embedding,
                    }
                    for i in v
                ]
                for k, v in self.clients.items()
            },
            "models": {k: v.to_dict() for k, v in self.models.items()},
        }
        path.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str | Path, embedder: Embedder | None = None) -> "Gallery":
        data = json.loads(Path(path).read_text())
        emb = embedder or MockEmbedder()
        g = cls(embedder=emb)
        for k, v in data.get("consents", {}).items():
            g.consents[k] = Consent(
                client_id=v["client_id"],
                purposes=tuple(v["purposes"]),
                revoked=v.get("revoked", False),
                granted_at=v.get("granted_at", time.time()),
            )
        for k, imgs in data.get("clients", {}).items():
            bucket: list[EnrolledImage] = []
            for i in imgs:
                evec = i.get("embedding")
                if not evec:
                    evec = g._embed(i["image_hash"], i.get("image_path", ""))
                bucket.append(
                    EnrolledImage(
                        image_hash=i["image_hash"],
                        embedding=evec,
                        enrolled_at=i.get("enrolled_at", time.time()),
                        image_path=i.get("image_path", ""),
                        source=i.get("source", "enrol"),
                        quality=float(i.get("quality", 1.0)),
                    )
                )
            g.clients[k] = bucket
        for k, m in data.get("models", {}).items():
            m = dict(m)
            m.setdefault("embedder", "mock")
            g.models[k] = ClientModel(**m)
        return g


__all__ = [
    "Consent",
    "BasisDecision",
    "EnrolledImage",
    "ClientModel",
    "Gallery",
    "decide_basis",
    "embed_hash",
    "pseudo",
    "cosine",
    "make_embedder",
    "MockEmbedder",
    "DIM",
]
