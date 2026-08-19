import unittest

from scrape import Consent, MockSource, decide_basis, run_scrape


class TestBasisMirror(unittest.TestCase):
    def test_untargeted_banned(self):
        d = decide_basis("untargeted_mass_id", has_consent=True)
        self.assertEqual(d.outcome, "prohibited")

    def test_targeted_needs_consent(self):
        d = decide_basis("targeted_search", has_consent=False)
        self.assertEqual(d.outcome, "requires_consent")
        d = decide_basis("targeted_search", has_consent=True)
        self.assertTrue(d.allowed())


class TestScrape(unittest.TestCase):
    def test_refuses_without_consent(self):
        r = run_scrape("alice", None, MockSource())
        self.assertTrue(r.refused)
        self.assertEqual(len(r.crops), 0)

    def test_runs_with_consent(self):
        c = Consent("alice", purposes=("targeted_search",))
        r = run_scrape("alice", c, MockSource(), limit=3)
        self.assertFalse(r.refused)
        self.assertEqual(len(r.crops), 3)
        self.assertTrue(all(x.raw_path == "" for x in r.crops))

    def test_retain_raw_flag_default_off(self):
        c = Consent("bob", purposes=("targeted_search",))
        r = run_scrape("bob", c, MockSource())
        self.assertTrue(all(x.image_hash for x in r.crops))

    def test_consent_revoked(self):
        c = Consent("alice", purposes=("targeted_search",), revoked=True)
        r = run_scrape("alice", c, MockSource())
        self.assertTrue(r.refused)

    def test_wrong_purpose_consent(self):
        c = Consent("alice", purposes=("enrolment",))
        r = run_scrape("alice", c, MockSource(), purpose="targeted_search")
        self.assertTrue(r.refused)


if __name__ == "__main__":
    unittest.main()
