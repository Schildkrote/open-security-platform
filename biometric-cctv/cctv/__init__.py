"""Authorized CCTV / RTSP frame pull.

Only cameras present in a signed allowlist may be contacted. Open-internet
cam discovery is intentionally not implemented.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class AllowlistError(ValueError):
    pass


class AuthError(PermissionError):
    pass


def expand_env(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in os.environ:
            raise AllowlistError(f"missing env var ${{{key}}} in allowlist URL")
        return os.environ[key]

    return _ENV_PATTERN.sub(repl, value)


@dataclass
class Camera:
    id: str
    rtsp_url: str
    holder: str
    auth_kind: str
    purposes: tuple[str, ...] = ("enrolment", "training")
    notes: str = ""
    max_fps_sample: float = 1.0
    min_face_px: int = 40
    enabled: bool = True

    def expanded_url(self) -> str:
        return expand_env(self.rtsp_url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rtsp_url": self.rtsp_url,
            "holder": self.holder,
            "auth_kind": self.auth_kind,
            "purposes": list(self.purposes),
            "notes": self.notes,
            "max_fps_sample": self.max_fps_sample,
            "min_face_px": self.min_face_px,
            "enabled": self.enabled,
        }


ALLOWED_AUTH_KINDS = frozenset(
    {"owner_consent", "client_consent", "le_warrant", "dataset_license"}
)
BANNED_HOST_HINTS = (
    "insecam",
    "openwebcam",
    "webcamxp.com",
)


@dataclass
class Allowlist:
    version: int
    cameras: dict[str, Camera] = field(default_factory=dict)
    path: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Allowlist":
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        cams: dict[str, Camera] = {}
        for c in raw.get("cameras") or []:
            cam = Camera(
                id=str(c["id"]),
                rtsp_url=str(c["rtsp_url"]),
                holder=str(c["holder"]),
                auth_kind=str(c.get("auth_kind") or "owner_consent"),
                purposes=tuple(c.get("purposes") or ("enrolment", "training")),
                notes=str(c.get("notes") or ""),
                max_fps_sample=float(c.get("max_fps_sample") or 1.0),
                min_face_px=int(c.get("min_face_px") or 40),
                enabled=bool(c.get("enabled", True)),
            )
            if cam.auth_kind not in ALLOWED_AUTH_KINDS:
                raise AllowlistError(f"camera {cam.id}: bad auth_kind {cam.auth_kind}")
            cams[cam.id] = cam
        return cls(version=int(raw.get("version") or 1), cameras=cams, path=str(path))

    def get(self, camera_id: str) -> Camera:
        if camera_id not in self.cameras:
            raise AllowlistError(
                f"camera {camera_id!r} not in allowlist "
                f"(refusing arbitrary RTSP — add it with owner/client consent first)"
            )
        cam = self.cameras[camera_id]
        if not cam.enabled:
            raise AllowlistError(f"camera {camera_id!r} is disabled")
        return cam

    def validate(self) -> list[str]:
        """Static checks; no network. Returns warnings."""
        warnings: list[str] = []
        if not self.cameras:
            raise AllowlistError("allowlist has no cameras")
        for cam in self.cameras.values():
            url = cam.rtsp_url
            try:
                expanded = cam.expanded_url()
            except AllowlistError as e:
                warnings.append(f"{cam.id}: {e}")
                expanded = url
            lower = expanded.lower()
            for hint in BANNED_HOST_HINTS:
                if hint in lower:
                    raise AllowlistError(
                        f"camera {cam.id}: host looks like an open-cam index ({hint}); banned"
                    )
            parsed = urlparse(expanded)
            if parsed.scheme not in ("rtsp", "rtsps", "http", "https", "file", "mock"):
                raise AllowlistError(
                    f"camera {cam.id}: unsupported scheme {parsed.scheme!r}"
                )
            if parsed.scheme == "file":
                p = Path(parsed.path)
                if not p.exists():
                    warnings.append(f"{cam.id}: file path does not exist yet: {p}")
            if not cam.holder:
                raise AllowlistError(f"camera {cam.id}: holder required")
            if not cam.purposes:
                raise AllowlistError(f"camera {cam.id}: purposes required")
        return warnings


@dataclass
class PullResult:
    camera_id: str
    out_dir: str
    frames: list[str]
    duration_s: float
    auth_kind: str
    holder: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "camera_id": self.camera_id,
            "out_dir": self.out_dir,
            "n_frames": len(self.frames),
            "frames": self.frames[:50],
            "duration_s": self.duration_s,
            "auth_kind": self.auth_kind,
            "holder": self.holder,
            "error": self.error,
        }


def _which_ffmpeg() -> str:
    path = shutil.which("ffmpeg")
    if not path:
        raise RuntimeError("ffmpeg not found on PATH (brew/apt install ffmpeg)")
    return path


def pull_frames(
    allowlist: Allowlist,
    camera_id: str,
    out_dir: str | Path,
    *,
    duration_s: float = 10.0,
    every_s: float = 2.0,
    dry_run: bool = False,
    mock: bool = False,
) -> PullResult:
    """Sample frames from an allowlisted camera via ffmpeg.

    mock=True writes synthetic JPEGs without opening the network (CI).
    dry_run=True validates + returns plan without writing.
    """
    cam = allowlist.get(camera_id)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    url = cam.expanded_url()

    if dry_run:
        return PullResult(
            camera_id=cam.id,
            out_dir=str(out),
            frames=[],
            duration_s=duration_s,
            auth_kind=cam.auth_kind,
            holder=cam.holder,
            error="dry_run",
        )

    if mock or url.startswith("file://mock") or url == "mock://":
        n = max(1, int(duration_s / max(every_s, 0.1)))
        frames: list[str] = []
        for i in range(n):
            # Minimal valid JPEG (1x1 pixel) so tools can hash files.
            # JPEG SOI + soft EOI is enough for hashing demos.
            payload = (
                b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                b"\xff\xd9"
            )
            # vary bytes slightly for distinct hashes
            payload = payload[:-2] + bytes([i % 251]) + b"\xff\xd9"
            name = f"{cam.id}_{i:05d}.jpg"
            path = out / name
            path.write_bytes(payload)
            frames.append(str(path))
        return PullResult(
            camera_id=cam.id,
            out_dir=str(out),
            frames=frames,
            duration_s=duration_s,
            auth_kind=cam.auth_kind,
            holder=cam.holder,
        )

    ffmpeg = _which_ffmpeg()
    # fps filter: 1/every_s frames per second
    fps = 1.0 / max(every_s, 0.05)
    pattern = str(out / f"{cam.id}_%05d.jpg")
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        url,
        "-t",
        str(duration_s),
        "-vf",
        f"fps={fps}",
        "-q:v",
        "2",
        pattern,
    ]
    # file:// local video support
    if urlparse(url).scheme == "file":
        cmd = [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            urlparse(url).path,
            "-t",
            str(duration_s),
            "-vf",
            f"fps={fps}",
            "-q:v",
            "2",
            pattern,
        ]

    t0 = time.time()
    try:
        subprocess.run(cmd, check=True, timeout=max(duration_s + 60, 120))
    except subprocess.CalledProcessError as e:
        return PullResult(
            camera_id=cam.id,
            out_dir=str(out),
            frames=[],
            duration_s=time.time() - t0,
            auth_kind=cam.auth_kind,
            holder=cam.holder,
            error=f"ffmpeg failed: {e}",
        )
    except subprocess.TimeoutExpired:
        return PullResult(
            camera_id=cam.id,
            out_dir=str(out),
            frames=[],
            duration_s=time.time() - t0,
            auth_kind=cam.auth_kind,
            holder=cam.holder,
            error="ffmpeg timeout",
        )

    frames = sorted(str(p) for p in out.glob(f"{cam.id}_*.jpg"))
    return PullResult(
        camera_id=cam.id,
        out_dir=str(out),
        frames=frames,
        duration_s=time.time() - t0,
        auth_kind=cam.auth_kind,
        holder=cam.holder,
    )


def file_hash(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(
    frames_dir: str | Path,
    *,
    client_id: str,
    camera_id: str,
    source_type: str = "cctv_authorized",
) -> list[dict[str, Any]]:
    """JSONL-ready rows for corpus ingest / promote."""
    rows: list[dict[str, Any]] = []
    for p in sorted(Path(frames_dir).glob("*.jpg")):
        rows.append(
            {
                "image_hash": file_hash(p),
                "path": str(p.resolve()),
                "client_id": client_id,
                "source_type": source_type,
                "camera_id": camera_id,
                "quality": 0.7,
            }
        )
    return rows


def write_manifest(rows: list[dict[str, Any]], out: str | Path) -> None:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def refuse_open_url(url: str) -> None:
    """Explicit guard for any caller that bypasses allowlist (defense in depth)."""
    lower = url.lower()
    for hint in BANNED_HOST_HINTS:
        if hint in lower:
            raise AuthError(f"refusing open-cam style URL ({hint})")
    # bare IPs without allowlist entry are not accepted here — caller must use Allowlist
