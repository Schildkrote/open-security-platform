import json
import tempfile
import unittest
from pathlib import Path

from train.embedder import (
    MockEmbedder,
    TableEmbedder,
    cosine,
    l2normalize,
    make_embedder,
    write_embedding_table,
)


class TestMockEmbedder(unittest.TestCase):
    def test_unit_and_deterministic(self):
        e = MockEmbedder(dim=32)
        a = e.embed("h1")
        b = e.embed("h1")
        self.assertEqual(a, b)
        self.assertAlmostEqual(sum(x * x for x in a), 1.0, places=9)
        self.assertEqual(e.name, "mock")
        self.assertLess(cosine(e.embed("h1"), e.embed("h2")), 0.99)

    def test_empty_hash(self):
        with self.assertRaises(ValueError):
            MockEmbedder().embed("")


class TestTableEmbedder(unittest.TestCase):
    def test_load_and_lookup(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "emb.json"
            write_embedding_table(path, {"a1": [1.0, 0.0, 0.0], "a2": [0.0, 1.0, 0.0]})
            e = TableEmbedder(path)
            self.assertEqual(e.dim, 3)
            v = e.embed("a1")
            self.assertAlmostEqual(v[0], 1.0, places=6)
            with self.assertRaises(KeyError):
                e.embed("missing")

    def test_factory(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "emb.json"
            write_embedding_table(path, {"x": [3.0, 4.0]})
            e = make_embedder("table", table=str(path))
            self.assertEqual(e.name, "table")
            v = e.embed("x")
            self.assertAlmostEqual(sum(x * x for x in v), 1.0, places=6)


class TestL2(unittest.TestCase):
    def test_normalize(self):
        v = l2normalize([3.0, 4.0])
        self.assertAlmostEqual(v[0], 0.6)
        self.assertAlmostEqual(v[1], 0.8)


class TestONNXFactoryMissing(unittest.TestCase):
    def test_missing_weights(self):
        with self.assertRaises(FileNotFoundError):
            make_embedder("onnx", weights="/no/such/model.onnx")

    def test_unknown_mode(self):
        with self.assertRaises(ValueError):
            make_embedder("magic")


if __name__ == "__main__":
    unittest.main()
