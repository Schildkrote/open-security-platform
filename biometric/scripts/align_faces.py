#!/usr/bin/env python3
# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Offline face alignment + embedding (run on the training box, never in CI).

Detects faces with InsightFace, extracts unit embeddings, and writes:
  1. a JSON embedding table (image key -> vector) for
     ``python3 -m train.cli --embedder table --table embeddings.json``
  2. optionally ``<key>.f32`` little-endian float32 blobs for the Go RBR
     external embedder (``go run ./cmd/rbr -embeddings <dir>``)

InsightFace/opencv are heavy and optional — imported lazily so this module
stays importable in the offline core. The export helpers (``build_table``,
``write_f32``, ``content_key``) are dependency-free and unit-tested.

Usage:
    python3 scripts/align_faces.py \
        --input raw_stills --out embeddings.json \
        --out-f32 f32/ --models /path/to/models --pack buffalo_l

Keys: by default the table is keyed by file stem (TableEmbedder falls back
to the stem when the runtime image_hash differs). Use ``--key content`` to
key by sha256 of the file bytes instead.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# train package (biometric-train/) is importable from the repo root layout.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "biometric-train"))

from train.embedder import pack_f32, write_embedding_table  # noqa: E402


def content_key(path: Path) -> str:
    """sha256 of the file bytes — stable identity for the same pixels."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_table(
    embeddings: dict[str, list[float]],
    out_path: str | Path,
    f32_dir: str | Path | None = None,
) -> dict[str, int]:
    """Write a normalized JSON table and optional .f32 blobs.

    Returns {"table": n_keys, "f32": n_blobs}. Vectors are L2-normalized by
    write_embedding_table; f32 blobs are written before normalization to
    keep the raw model output (Go normalizes on load).
    """
    write_embedding_table(out_path, embeddings)
    n_f32 = 0
    if f32_dir is not None:
        d = Path(f32_dir)
        d.mkdir(parents=True, exist_ok=True)
        for key, vec in embeddings.items():
            (d / f"{key}.f32").write_bytes(pack_f32([float(x) for x in vec]))
            n_f32 += 1
    return {"table": len(embeddings), "f32": n_f32}


def extract_faces(img_path: Path, app, min_face_px: int) -> list[list[float]]:
    """Largest qualifying face per image → unit embeddings."""
    import cv2  # type: ignore  (lazy: heavy optional dep)

    img = cv2.imread(str(img_path))
    if img is None:
        return []
    faces = app.get(img)
    if not faces:
        return []
    faces = [
        f
        for f in faces
        if (f.bbox[2] - f.bbox[0]) >= min_face_px and (f.bbox[3] - f.bbox[1]) >= min_face_px
    ]
    if not faces:
        return []
    face = max(faces, key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]))
    emb = getattr(face, "normed_embedding", None)
    if emb is None:
        emb = face.embedding
    return [emb.tolist()]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="align_faces")
    p.add_argument("--input", required=True, help="directory of images (recursed)")
    p.add_argument("--out", required=True, help="output JSON embedding table")
    p.add_argument("--out-f32", default="", help="optional dir for Go .f32 blobs")
    p.add_argument("--models", default=str(Path.home() / "insightface_models"))
    p.add_argument("--pack", default="buffalo_l")
    p.add_argument("--ctx", type=int, default=-1, help="0 = GPU, -1 = CPU")
    p.add_argument("--det-size", type=int, default=640)
    p.add_argument("--min-face-px", type=int, default=40)
    p.add_argument("--key", choices=("stem", "content"), default="stem")
    args = p.parse_args(argv)

    try:
        from insightface.app import FaceAnalysis  # type: ignore
    except ImportError:
        print(
            "insightface not installed. On the training box run:\n"
            "  pip install insightface onnxruntime opencv-python-headless numpy pillow",
            file=sys.stderr,
        )
        return 3

    app = FaceAnalysis(name=args.pack, root=args.models)
    app.prepare(ctx_id=args.ctx, det_size=(args.det_size, args.det_size))

    src = Path(args.input)
    imgs = sorted(
        [x for pat in ("*.jpg", "*.jpeg", "*.png", "*.webp") for x in src.rglob(pat)]
    )
    if not imgs:
        print(f"no images under {src}", file=sys.stderr)
        return 2

    embeddings: dict[str, list[float]] = {}
    skipped = 0
    for img_path in imgs:
        key = img_path.stem if args.key == "stem" else content_key(img_path)
        try:
            vecs = extract_faces(img_path, app, args.min_face_px)
        except Exception as e:  # noqa: BLE001 — keep the batch alive
            print(f"  ! {img_path.name}: {e}", file=sys.stderr)
            skipped += 1
            continue
        if not vecs:
            skipped += 1
            continue
        if key in embeddings:
            key = f"{key}__{len(embeddings)}"
        embeddings[key] = vecs[0]

    stats = build_table(embeddings, args.out, args.out_f32 or None)
    print(
        f"embedded {len(embeddings)}/{len(imgs)} images "
        f"(skipped={skipped}) → {args.out}"
        + (f" + {stats['f32']} .f32 blobs → {args.out_f32}" if args.out_f32 else "")
    )
    if not embeddings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())