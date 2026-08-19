import unittest

from categorise import Features, SPECIAL, categorise, categorise_batch


class TestCategorise(unittest.TestCase):
    def test_minor_by_age(self):
        r = categorise(Features(age_estimate=12))
        self.assertEqual(r.category, "minor")
        self.assertTrue(r.special)

    def test_adult_general(self):
        r = categorise(Features(age_estimate=30))
        self.assertEqual(r.category, "general")
        self.assertFalse(r.special)

    def test_health(self):
        r = categorise(Features(tags=("hospital", "ward")))
        self.assertEqual(r.category, "health_context")
        self.assertIn(r.category, SPECIAL)

    def test_religion(self):
        r = categorise(Features(source_type="church_stream"))
        self.assertEqual(r.category, "religion_context")

    def test_public_figure(self):
        r = categorise(Features(is_public_figure=True))
        self.assertEqual(r.category, "public_figure")

    def test_employee(self):
        r = categorise(Features(source_type="office_cctv"))
        self.assertEqual(r.category, "employee")

    def test_school_without_age(self):
        r = categorise(Features(source_type="school_cctv"))
        self.assertEqual(r.category, "minor")
        self.assertTrue(r.special)

    def test_priority_minor_over_health(self):
        r = categorise(Features(age_estimate=10, tags=("hospital",)))
        self.assertEqual(r.category, "minor")

    def test_batch(self):
        out = categorise_batch([Features(age_estimate=10), Features(age_estimate=40)])
        self.assertEqual([o.category for o in out], ["minor", "general"])


if __name__ == "__main__":
    unittest.main()
