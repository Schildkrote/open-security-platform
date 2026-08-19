import os
import tempfile
import unittest

from train import Consent, Gallery, cosine, embed_hash


class TestEmbed(unittest.TestCase):
    def test_deterministic_unit(self):
        a = embed_hash("h1")
        b = embed_hash("h1")
        self.assertEqual(a, b)
        self.assertAlmostEqual(sum(x * x for x in a), 1.0, places=9)
        self.assertLess(cosine(embed_hash("h1"), embed_hash("h2")), 0.99)


class TestTrainLoop(unittest.TestCase):
    def test_enrol_requires_consent(self):
        g = Gallery()
        n, d = g.enrol("alice", ["h1", "h2"])
        self.assertEqual(n, 0)
        self.assertEqual(d.outcome, "requires_consent")

    def test_enrol_train_identify(self):
        g = Gallery()
        g.set_consent(Consent("alice", purposes=("enrolment", "training", "targeted_search")))
        n, d = g.enrol("alice", ["alice-img-1", "alice-img-2", "alice-img-3"])
        self.assertEqual(n, 3)
        self.assertTrue(d.allowed())
        model, d = g.train("alice")
        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model.n_images, 3)
        # Same hash family should match centroid reasonably; exact enrolled hash embeds close.
        hits = g.identify("alice-img-1", threshold=0.5)
        self.assertTrue(any(c == "alice" for c, _ in hits))

    def test_revoke_purges(self):
        g = Gallery()
        g.set_consent(Consent("bob", purposes=("enrolment", "training")))
        g.enrol("bob", ["b1", "b2"])
        g.train("bob")
        info = g.revoke("bob")
        self.assertEqual(info["images_purged"], 2)
        self.assertTrue(info["model_purged"])
        self.assertEqual(g.identify("b1"), [])
        # Re-enrol refused while revoked
        n, d = g.enrol("bob", ["b3"])
        self.assertEqual(n, 0)
        self.assertEqual(d.outcome, "requires_consent")

    def test_no_third_party_in_training(self):
        """Training set is only what was enrolled for that client."""
        g = Gallery()
        g.set_consent(Consent("alice", purposes=("enrolment", "training")))
        g.set_consent(Consent("mallory", purposes=("enrolment", "training")))
        g.enrol("alice", ["a1"])
        g.enrol("mallory", ["m1"])
        g.train("alice")
        # alice model must not absorb mallory images
        self.assertEqual(g.models["alice"].n_images, 1)

    def test_persist(self):
        g = Gallery()
        g.set_consent(Consent("alice", purposes=("enrolment", "training")))
        g.enrol("alice", ["a1", "a2"])
        g.train("alice")
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "g.json")
            g.save(path)
            g2 = Gallery.load(path)
            self.assertIn("alice", g2.models)
            self.assertEqual(len(g2.clients["alice"]), 2)

    def test_minor_blocked(self):
        g = Gallery()
        g.set_consent(Consent("kid", purposes=("enrolment", "training")))
        n, d = g.enrol("kid", ["k1"], category="minor")
        self.assertEqual(n, 0)
        self.assertEqual(d.outcome, "requires_dpia")


if __name__ == "__main__":
    unittest.main()
