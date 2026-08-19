import unittest

from pipeline import run_pipeline


class TestPipeline(unittest.TestCase):
    def test_happy_path(self):
        r = run_pipeline("alice", with_consent=True)
        self.assertTrue(r.ok(), r.refused)
        self.assertEqual(r.enrolled, 5)
        self.assertEqual(r.model_version, 1)
        self.assertEqual(r.scraped, 3)
        self.assertGreater(len(r.matches), 0)
        self.assertEqual(r.category, "public_figure")
        # Matches must come from probe hashes that equal enrolled content,
        # not from identify(enrolled_ref) cheats.
        for m in r.matches:
            self.assertIn("probe", m)
            self.assertTrue(m["probe"].startswith("alice-ref-"))

    def test_no_consent_refuses(self):
        r = run_pipeline("bob", with_consent=False)
        self.assertFalse(r.ok())
        self.assertTrue(any("enrol" in x for x in r.refused))


if __name__ == "__main__":
    unittest.main()
