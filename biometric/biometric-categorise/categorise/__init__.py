"""Sensitivity categoriser for biometric subjects.

Rule-based mock classifier (offline). A real ML adapter can be plugged in
behind --mode ml once user-supplied weights exist.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


CATEGORIES = (
    "public_figure",
    "employee",
    "minor",
    "health_context",
    "religion_context",
    "general",
)

SPECIAL = frozenset({"minor", "health_context", "religion_context"})


@dataclass(frozen=True)
class Features:
    """Input features for categorisation (no raw pixels)."""

    age_estimate: int | None = None
    source_type: str = ""  # e.g. school_cctv, hospital_feed, church_stream, news
    tags: tuple[str, ...] = ()
    is_employee: bool = False
    is_public_figure: bool = False


@dataclass(frozen=True)
class Result:
    category: str
    confidence: float
    special: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def categorise(f: Features) -> Result:
    """Return the highest-priority matching category."""
    reasons: list[str] = []

    # Priority: minor > health > religion > public_figure > employee > general
    if f.age_estimate is not None and f.age_estimate < 18:
        reasons.append(f"age_estimate={f.age_estimate}<18")
        return Result("minor", 0.95, True, tuple(reasons))

    src = (f.source_type or "").lower()
    tags = {t.lower() for t in f.tags}

    health_markers = {"hospital", "clinic", "ward", "medical", "health"}
    if src in {"hospital_feed", "clinic_cctv"} or tags & health_markers:
        reasons.append("health context markers present")
        return Result("health_context", 0.9, True, tuple(reasons))

    religion_markers = {"church", "mosque", "temple", "synagogue", "worship"}
    if src in {"church_stream", "worship_cctv"} or tags & religion_markers:
        reasons.append("religion context markers present")
        return Result("religion_context", 0.9, True, tuple(reasons))

    if f.is_public_figure or "public_figure" in tags or src == "news":
        reasons.append("public figure flag/source")
        return Result("public_figure", 0.85, False, tuple(reasons))

    if f.is_employee or "employee" in tags or src in {"badge_cam", "office_cctv"}:
        reasons.append("employee flag/source")
        return Result("employee", 0.85, False, tuple(reasons))

    if "school" in src or "school" in tags:
        # School without age → treat as elevated, still minor-risk
        reasons.append("school source without age; treating as minor-risk")
        return Result("minor", 0.7, True, tuple(reasons))

    reasons.append("no special markers")
    return Result("general", 0.6, False, tuple(reasons))


def categorise_batch(items: Iterable[Features]) -> list[Result]:
    return [categorise(f) for f in items]
