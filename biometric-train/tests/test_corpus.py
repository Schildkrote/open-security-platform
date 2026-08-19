import os
import tempfile
import unittest

from train.corpus import (
    Authorization,
    Corpus,
    MockAuthorizedCCTVSource,
    MockClientUploadSource,
    MockResearchDatasetSource,
    MockSyntheticSource,
    open_cctv_policy,
)
from train import Consent, Gallery


class TestCorpusAuth(unittest.TestCase):
    def test_client_upload_needs_consent(self):
        c = Corpus()
        r = c.ingest(MockClientUploadSource("alice"), client_id="alice")
        self.assertFalse(r.basis_ok)
        c.add_authorization(
            Authorization("client_consent", "alice", ("enrolment", "training"))
        )
        r = c.ingest(MockClientUploadSource("alice", n=5), client_id="alice", limit=5)
        self.assertTrue(r.basis_ok)
        self.assertEqual(len(r.accepted), 5)

    def test_cctv_authorized(self):
        c = Corpus(min_quality=0.5)
        c.add_authorization(
            Authorization("owner_consent", "alice", ("enrolment", "training"), notes="lobby NVR")
        )
        r = c.ingest(
            MockAuthorizedCCTVSource("alice", n=10),
            client_id="alice",
            limit=10,
        )
        self.assertTrue(r.basis_ok)
        self.assertGreater(len(r.accepted), 0)
        # Low quality rejected when min_quality high
        c2 = Corpus(min_quality=0.99)
        c2.add_authorization(
            Authorization("owner_consent", "alice", ("training",))
        )
        r2 = c2.ingest(MockAuthorizedCCTVSource("alice", n=10), client_id="alice", limit=10)
        self.assertTrue(r2.basis_ok)
        self.assertEqual(len(r2.accepted), 0)  # all below 0.99 in mock curve? check
        # mock quality goes up to 0.55+0.32=0.87 max — all rejected
        self.assertEqual(len(r2.rejected), 10)

    def test_open_cctv_type_banned(self):
        c = Corpus()

        class Evil:
            name = "evil"
            source_type = "open_cctv"

            def list_candidates(self, limit=100):
                return [{"image_hash": "x"}]

        r = c.ingest(Evil(), client_id="alice")  # type: ignore[arg-type]
        self.assertFalse(r.basis_ok)
        self.assertIn("prohibited", r.basis_reason)

    def test_research_dataset_license(self):
        c = Corpus()
        c.add_authorization(
            Authorization("dataset_license", "synthetic-faces-v1", ("training", "enrolment"))
        )
        r = c.ingest(
            MockResearchDatasetSource(n=8),
            client_id="",  # foundation
            holder="synthetic-faces-v1",
            limit=8,
        )
        self.assertTrue(r.basis_ok)
        self.assertEqual(len(r.accepted), 8)

    def test_synthetic_no_auth(self):
        c = Corpus()
        r = c.ingest(MockSyntheticSource(n=3), client_id="foundation", limit=3)
        self.assertTrue(r.basis_ok)
        self.assertEqual(len(r.accepted), 3)

    def test_promote_to_gallery(self):
        c = Corpus()
        c.add_authorization(
            Authorization("client_consent", "alice", ("enrolment", "training"))
        )
        c.ingest(MockClientUploadSource("alice", n=4), client_id="alice", limit=4)
        g = Gallery()
        g.set_consent(Consent("alice", purposes=("enrolment", "training")))
        n, d = g.enrol_from_corpus("alice", c.export_hashes("alice"))
        self.assertTrue(d.allowed())
        self.assertEqual(n, 4)
        model, d = g.train("alice")
        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model.n_images, 4)

    def test_persist(self):
        c = Corpus()
        c.add_authorization(Authorization("synthetic", "syn", ("training",)))
        c.ingest(MockSyntheticSource(n=2), client_id="f", limit=2)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "c.json")
            c.save(path)
            c2 = Corpus.load(path)
            self.assertEqual(len(c2.items), 2)

    def test_open_cctv_policy_doc(self):
        doc = open_cctv_policy()
        self.assertIn("warning", doc)
        self.assertIn("allowed_cctv_paths", doc)


if __name__ == "__main__":
    unittest.main()
