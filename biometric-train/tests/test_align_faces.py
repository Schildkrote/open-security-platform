# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Golden tests for the offline embedding path (scripts/align_faces.py).

The fixture ``fixtures/emb_golden.json`` (512-dim, produced by the
deterministic MockEmbedder) is the shared golden vector:
  - this test pins it from the Python side,
  - biometric-rbr/golden_test.go pins the same file from the Go side.
Together they prove the cross-language real-embeddings round trip
(Python table → Go external embedder) without InsightFace installed.
"""
import importlib.util
import json
import math
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent  # repo root
sys.path.insert(0, str(HERE.parent))  # biometric-train/

FIXTURE = HERE / "fixtures" / "emb_golden.json"
SCRIPT = ROOT / "scripts" / "align_faces.py"

# Pinned head of alice-ref-1 as written to the fixture file (matches the
# Go golden test exactly; the file is the golden standard).
WANT_HEAD = [0.05197540671022089, 0.031239172553971815,
             -0.004058767723356431, -0.06314424211775652]


def load_script():
    spec = importlib.util.spec_from_file_location("align_faces", SCRIPT)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestGoldenFixture(unittest.TestCase):
    def test_fixture_present_and_normalized(self):
        self.assertTrue(FIXTURE.exists(), "emb_golden.json missing — regenerate it")
        tbl = json.loads(FIXTURE.read_text())
        self.assertEqual(set(tbl), {"alice-ref-1", "alice-ref-2", "bob-ref-1"})
        for k, v in tbl.items():
            self.assertEqual(len(v), 512)
            n = math.sqrt(sum(x * x for x in v))
            self.assertAlmostEqual(n, 1.0, places=9, msg=f"{k} not unit-norm")
        self.assertEqual(tbl["alice-ref-1"][:4], WANT_HEAD)

    def test_fixture_loads_in_table_embedder(self):
        from train.embedder import TableEmbedder, cosine

        e = TableEmbedder(FIXTURE)
        self.assertEqual(e.dim, 512)
        v1 = e.embed("alice-ref-1")
        self.assertEqual(v1[:4], WANT_HEAD)
        # Same person (different ref) closer than a different person.
        c_same = cosine(v1, e.embed("alice-ref-2"))
        c_diff = cosine(v1, e.embed("bob-ref-1"))
        self.assertGreater(c_same, c_diff)
        self.assertGreater(c_same, 0.0)
        self.assertLess(abs(c_diff), 0.01)


class TestAlignFacesExport(unittest.TestCase):
    def setUp(self):
        self.al = load_script()

    def test_content_key(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.jpg"
            p.write_bytes(b"\xff\xd8fake")
            self.assertEqual(self.al.content_key(p),
                             __import__("hashlib").sha256(b"\xff\xd8fake").hexdigest())

    def test_build_table_writes_json_and_f32(self):
        import json as _json

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "t.json"
            f32 = Path(td) / "f32"
            vec = [0.6, 0.8, 0.0, 0.0]
            stats = self.al.build_table({"img-a": vec}, out, f32)
            self.assertEqual(stats, {"table": 1, "f32": 1})
            # JSON is L2-normalized.
            tbl = _json.loads(out.read_text())
            self.assertAlmostEqual(sum(x * x for x in tbl["img-a"]), 1.0, places=9)
            # f32 blob is the raw (pre-normalization) vector, little-endian.
            raw = (f32 / "img-a.f32").read_bytes()
            self.assertEqual(len(raw), 16)
            got = struct.unpack("<4f", raw)
            self.assertAlmostEqual(got[0], 0.6, places=6)
            self.assertAlmostEqual(got[1], 0.8, places=6)
            self.assertEqual(got[2], 0.0)
            self.assertEqual(got[3], 0.0)

    def test_build_table_without_f32(self):
        import json as _json

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "t.json"
            stats = self.al.build_table({"img-a": [1.0, 0.0]}, out)
            self.assertEqual(stats, {"table": 1, "f32": 0})
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()