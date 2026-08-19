"""Face embedder backends.

Mock is always available (offline, deterministic). Real backends load
user-supplied weights — never committed to the repo.

Supported real modes (optional deps, imported lazily):
  - onnx: ONNX Runtime + ArcFace/SFace-style model (path via weights=)
  - numpy: load a precomputed embedding table (image_hash -> vector)

The OSS core stays stdlib-only at import time. Real mode fails with a clear
error if optional packages or weight files are missing.
"""
from __future__ import annotations

import hashlib
import json
import math
import struct
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable


DEFAULT_DIM = 32
ARCFACE_DIM = 512


def l2normalize(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def cosine(a: list[float], b: list[float]) -> float:
    if not a or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


class Embedder(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def dim(self) -> int: ...

    @abstractmethod
    def embed(self, image_hash: str, image_path: str | None = None) -> list[float]:
        """Return a unit L2 embedding.

        image_hash is always required (audit identity). image_path is used by
        real backends that read pixels; mock ignores it.
        """


class MockEmbedder(Embedder):
    """Deterministic hash→vector embedder (offline CI)."""

    def __init__(self, dim: int = DEFAULT_DIM) -> None:
        self._dim = dim

    @property
    def name(self) -> str:
        return "mock"

    @property
    def dim(self) -> int:
        return self._dim

    def embed(self, image_hash: str, image_path: str | None = None) -> list[float]:
        if not image_hash:
            raise ValueError("empty image_hash")
        raw: list[float] = []
        buf = hashlib.sha256(image_hash.encode("utf-8")).digest()
        for i in range(self._dim):
            if i > 0 and i % 8 == 0:
                buf = hashlib.sha256(buf).digest()
            off = (i % 8) * 4
            u = int.from_bytes(buf[off : off + 4], "big")
            raw.append(u / 0xFFFFFFFF - 0.5)
        return l2normalize(raw)


class TableEmbedder(Embedder):
    """Precomputed embedding table: {image_hash: [float, ...]} JSON.

    Used when a heavier pipeline (InsightFace etc.) has already produced
    embeddings offline; this repo only loads the vectors.
    """

    def __init__(self, table_path: str | Path, dim: int | None = None) -> None:
        data = json.loads(Path(table_path).read_text())
        if not isinstance(data, dict) or not data:
            raise ValueError(f"empty embedding table: {table_path}")
        self._table = {str(k): [float(x) for x in v] for k, v in data.items()}
        sample = next(iter(self._table.values()))
        self._dim = dim or len(sample)
        for k, v in self._table.items():
            if len(v) != self._dim:
                raise ValueError(f"dim mismatch for {k}: {len(v)} != {self._dim}")
            self._table[k] = l2normalize(v)

    @property
    def name(self) -> str:
        return "table"

    @property
    def dim(self) -> int:
        return self._dim

    def embed(self, image_hash: str, image_path: str | None = None) -> list[float]:
        if image_hash in self._table:
            return list(self._table[image_hash])
        # Fallback: if path given, look up by basename stem.
        if image_path:
            stem = Path(image_path).stem
            if stem in self._table:
                return list(self._table[stem])
        raise KeyError(f"no embedding for {image_hash!r} in table")


class ONNXEmbedder(Embedder):
    """ArcFace/SFace-style ONNX embedder.

    Requires: onnxruntime, and a user-supplied .onnx weights file.
    Optional: numpy for preprocessing. Image bytes are read from image_path;
    if only image_hash is given, raises (real models need pixels).

    This is intentionally a thin adapter — production pipelines usually
    preprocess with InsightFace/RetinaFace outside and pass a face crop.
    Here we accept a raw image path and do minimal centre-crop resize via
    a pure-stdlib PPM/raw fallback, or numpy if present.
    """

    def __init__(self, weights: str | Path, dim: int = ARCFACE_DIM, providers: list[str] | None = None) -> None:
        self._weights = Path(weights)
        if not self._weights.is_file():
            raise FileNotFoundError(
                f"ONNX weights not found: {self._weights}. "
                "Place user-supplied ArcFace/SFace weights there (never commit them)."
            )
        try:
            import onnxruntime as ort  # type: ignore
        except ImportError as e:
            raise ImportError(
                "onnxruntime is required for ONNXEmbedder. "
                "Install in your env: pip install onnxruntime"
            ) from e
        self._ort = ort
        self._session = ort.InferenceSession(
            str(self._weights),
            providers=providers or ["CPUExecutionProvider"],
        )
        self._dim = dim
        self._input_name = self._session.get_inputs()[0].name

    @property
    def name(self) -> str:
        return "onnx"

    @property
    def dim(self) -> int:
        return self._dim

    def embed(self, image_hash: str, image_path: str | None = None) -> list[float]:
        if not image_path:
            raise ValueError("ONNXEmbedder requires image_path (pixels); hash-only is mock territory")
        arr = _load_face_nchw(image_path)
        outputs = self._session.run(None, {self._input_name: arr})
        vec = outputs[0].reshape(-1).tolist()
        if len(vec) != self._dim:
            # Some models emit 512; allow override if actual differs.
            self._dim = len(vec)
        return l2normalize([float(x) for x in vec])


def _load_face_nchw(path: str | Path, size: int = 112) -> list:
    """Load image to NCHW float32 batch for ArcFace (1,3,112,112).

    Prefers numpy+PIL/cv2 if available; otherwise accepts a raw float32
    .npy-less sidecar: a JSON list of length 3*size*size (debug only).
    """
    path = Path(path)
    # JSON tensor sidecar (for offline tests without image codecs).
    side = path if path.suffix == ".json" else path.with_suffix(path.suffix + ".tensor.json")
    if side.is_file():
        data = json.loads(side.read_text())
        flat = [float(x) for x in data]
        expected = 3 * size * size
        if len(flat) != expected:
            raise ValueError(f"tensor sidecar length {len(flat)} != {expected}")
        # Return nested list shaped as numpy would: we need actual ndarray for ORT.
        try:
            import numpy as np  # type: ignore
        except ImportError as e:
            raise ImportError("numpy required to feed ONNX session") from e
        arr = np.asarray(flat, dtype="float32").reshape(1, 3, size, size)
        return arr

    try:
        import numpy as np  # type: ignore
    except ImportError as e:
        raise ImportError("numpy required for ONNX image load") from e

    # Try PIL then cv2.
    img = None
    try:
        from PIL import Image  # type: ignore

        im = Image.open(path).convert("RGB").resize((size, size))
        img = np.asarray(im, dtype="float32")
    except Exception:
        try:
            import cv2  # type: ignore

            bgr = cv2.imread(str(path))
            if bgr is None:
                raise FileNotFoundError(path)
            rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
            img = cv2.resize(rgb, (size, size)).astype("float32")
        except Exception as e:
            raise RuntimeError(
                f"cannot load image {path}: install Pillow or opencv-python-headless, "
                f"or provide a .tensor.json sidecar"
            ) from e

    # ArcFace-style normalize to [-1, 1]
    img = (img - 127.5) / 127.5
    # HWC -> CHW -> NCHW
    chw = np.transpose(img, (2, 0, 1))
    return np.expand_dims(chw, 0)


def make_embedder(mode: str = "mock", **kwargs) -> Embedder:
    """Factory: mode in mock|table|onnx."""
    mode = (mode or "mock").lower().strip()
    if mode == "mock":
        return MockEmbedder(dim=int(kwargs.get("dim", DEFAULT_DIM)))
    if mode == "table":
        path = kwargs.get("table") or kwargs.get("weights")
        if not path:
            raise ValueError("table embedder requires table=/path/to/embeddings.json")
        return TableEmbedder(path, dim=kwargs.get("dim"))
    if mode == "onnx":
        path = kwargs.get("weights")
        if not path:
            raise ValueError("onnx embedder requires weights=/path/to/model.onnx")
        return ONNXEmbedder(path, dim=int(kwargs.get("dim", ARCFACE_DIM)))
    raise ValueError(f"unknown embedder mode {mode!r} (mock|table|onnx)")


def embed_batch(emb: Embedder, items: Iterable[tuple[str, str | None]]) -> list[list[float]]:
    """items: iterable of (image_hash, image_path|None)."""
    return [emb.embed(h, p) for h, p in items]


def write_embedding_table(path: str | Path, mapping: dict[str, list[float]]) -> None:
    """Write a table embedder JSON (normalized)."""
    out = {k: l2normalize([float(x) for x in v]) for k, v in mapping.items()}
    Path(path).write_text(json.dumps(out))


def pack_f32(vec: list[float]) -> bytes:
    """Little-endian float32 blob (for Go external embedder sidecars)."""
    return struct.pack(f"<{len(vec)}f", *vec)
