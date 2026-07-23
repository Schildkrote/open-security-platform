"""Vector stores for RAG authorization.

``VectorStore`` is a dependency-free in-memory store using hashed bag-of-words
embeddings (the offline default / mock). ``PgVectorStore`` is the Real backend:
it stores the same embeddings in a Postgres + pgvector table and runs cosine
similarity in SQL. It takes an already-connected DB-API connection, so this
module stays stdlib-only (the caller supplies e.g. a psycopg connection).
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

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


class VectorStoreProtocol(Protocol):
    """The swappable vector-store contract (Phase 3). Both VectorStore (in-memory
    mock) and PgVectorStore (Real) satisfy it."""

    def add(self, doc_id: str, text: str) -> None: ...
    def remove(self, doc_id: str) -> None: ...
    def search(self, query: str, k: int = 5) -> list[tuple[str, float]]: ...


def _to_pgvector(vec: list[float]) -> str:
    """Render a vector as a pgvector literal, e.g. '[0.1,0.2,...]'."""
    return "[" + ",".join(repr(v) for v in vec) + "]"


class PgVectorStore:
    """Real vector store backed by Postgres + pgvector.

    ``conn`` is a DB-API connection (e.g. psycopg); it is injected so this module
    needs no driver dependency. Embeddings come from the same ``embed`` function
    as the in-memory store, so results are comparable.
    """

    def __init__(self, conn, table: str = "rag_documents", dim: int = DIM) -> None:
        self.conn = conn
        self.table = table
        self.dim = dim
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        self.conn.execute(
            f"CREATE TABLE IF NOT EXISTS {self.table} "
            f"(doc_id TEXT PRIMARY KEY, embedding vector({self.dim}))"
        )

    def add(self, doc_id: str, text: str) -> None:
        self.conn.execute(
            f"INSERT INTO {self.table} (doc_id, embedding) VALUES (%s, %s::vector) "
            f"ON CONFLICT (doc_id) DO UPDATE SET embedding = EXCLUDED.embedding",
            (doc_id, _to_pgvector(embed(text))),
        )

    def remove(self, doc_id: str) -> None:
        self.conn.execute(f"DELETE FROM {self.table} WHERE doc_id = %s", (doc_id,))

    def search(self, query: str, k: int = 5) -> list[tuple[str, float]]:
        q = _to_pgvector(embed(query))
        cur = self.conn.execute(
            f"SELECT doc_id, 1 - (embedding <=> %s::vector) AS score "
            f"FROM {self.table} ORDER BY embedding <=> %s::vector LIMIT %s",
            (q, q, k),
        )
        return [(row[0], float(row[1])) for row in cur.fetchall()]
