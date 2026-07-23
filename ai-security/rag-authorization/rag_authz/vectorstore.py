"""A dependency-free vector store using hashed bag-of-words embeddings."""
from __future__ import annotations

import hashlib
import math
import re

DIM = 256
_TOKEN = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def embed(text: str) -> list[float]:
    vec = [0.0] * DIM
    for tok in _tokenize(text):
        idx = int(hashlib.md5(tok.encode()).hexdigest(), 16) % DIM
        vec[idx] += 1.0
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


class VectorStore:
    def __init__(self) -> None:
        self._vectors: dict[str, list[float]] = {}

    def add(self, doc_id: str, text: str) -> None:
        self._vectors[doc_id] = embed(text)

    def remove(self, doc_id: str) -> None:
        self._vectors.pop(doc_id, None)

    def search(self, query: str, k: int = 5) -> list[tuple[str, float]]:
        q = embed(query)
        scored = [(doc_id, cosine(q, vec)) for doc_id, vec in self._vectors.items()]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]
