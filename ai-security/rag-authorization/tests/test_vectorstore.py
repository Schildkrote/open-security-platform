"""Tests for the vector stores, including the pgvector backend (fake DB conn)."""
from __future__ import annotations

import unittest

from rag_authz.vectorstore import (
    PgVectorStore,
    VectorStore,
    VectorStoreProtocol,
    _to_pgvector,
)


class FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class FakeConn:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        return FakeCursor(self.rows)


def _use(store: VectorStoreProtocol) -> list[tuple[str, float]]:
    store.add("d1", "the quick brown fox")
    return store.search("quick fox", k=2)


class VectorStoreProtocolTests(unittest.TestCase):
    def test_in_memory_satisfies_protocol(self):
        results = _use(VectorStore())
        self.assertEqual(results[0][0], "d1")

    def test_pgvector_satisfies_protocol(self):
        conn = FakeConn(rows=[("d1", 0.91)])
        results = _use(PgVectorStore(conn))
        self.assertEqual(results, [("d1", 0.91)])


class PgVectorStoreTests(unittest.TestCase):
    def test_ensure_schema(self):
        conn = FakeConn()
        PgVectorStore(conn, table="docs")
        sqls = [sql for sql, _ in conn.calls]
        self.assertTrue(any("CREATE EXTENSION IF NOT EXISTS vector" in s for s in sqls))
        self.assertTrue(any("CREATE TABLE IF NOT EXISTS docs" in s for s in sqls))

    def test_add_builds_upsert(self):
        conn = FakeConn()
        store = PgVectorStore(conn, table="docs")
        store.add("d1", "hello world")
        sql, params = conn.calls[-1]
        self.assertIn("INSERT INTO docs", sql)
        self.assertIn("ON CONFLICT (doc_id) DO UPDATE", sql)
        self.assertEqual(params[0], "d1")
        self.assertTrue(params[1].startswith("["))  # pgvector literal

    def test_search_builds_cosine_query(self):
        conn = FakeConn(rows=[("d1", 0.9), ("d2", 0.5)])
        store = PgVectorStore(conn, table="docs")
        results = store.search("hello", k=2)
        self.assertEqual(results, [("d1", 0.9), ("d2", 0.5)])
        sql, _ = conn.calls[-1]
        self.assertIn("<=>", sql)
        self.assertIn("LIMIT", sql)

    def test_remove_builds_delete(self):
        conn = FakeConn()
        store = PgVectorStore(conn, table="docs")
        store.remove("d1")
        sql, params = conn.calls[-1]
        self.assertIn("DELETE FROM docs", sql)
        self.assertEqual(params, ("d1",))

    def test_to_pgvector(self):
        self.assertEqual(_to_pgvector([0.5, 1.0]), "[0.5,1.0]")


if __name__ == "__main__":
    unittest.main()
