"""Framework registry and control-library citation validation.

These tests are the regression net for citation rot: if someone edits
DEFAULT_CONTROLS and cites an EU AI Act article that is not in the verified
registry, or an ISO/IEC 42001 Annex A control that does not exist, the suite
fails with the offending control title.
"""
from __future__ import annotations

import unittest

from compliance_hub import controls, db, frameworks


class FrameworkRegistryTests(unittest.TestCase):
    """The validator must reject the citations this library has historically got wrong."""

    def test_rejects_pre_renumbering_incident_article(self):
        # Serious-incident reporting is Article 73 in the OJ-published Act.
        # Article 61/62 are draft-era numbers that circulated widely.
        for bad in ("Article 61", "Article 62"):
            with self.assertRaises(frameworks.CitationError, msg=bad):
                frameworks.validate_eu_ai_act(bad)
        frameworks.validate_eu_ai_act("Article 73")  # must NOT raise

    def test_rejects_nonexistent_iso_annex_a_controls(self):
        for bad in ("A.7.7", "A.8.6", "A.6.2.9", "A.9.5", "A.11.2", "A.1.1"):
            with self.assertRaises(frameworks.CitationError, msg=bad):
                frameworks.validate_iso_42001(bad)

    def test_accepts_real_iso_annex_a_controls_and_clauses(self):
        for good in ("A.6.2.8", "A.7.6", "A.8.5", "A.9.4", "A.10.4", "Clause 9.2"):
            frameworks.validate_iso_42001(good)

    def test_nist_shape_and_bounds(self):
        for good in ("GOVERN-1.1", "MAP-5.1", "MEASURE-2.11", "MANAGE-4", "MANAGE-4.1"):
            frameworks.validate_nist_ai_rmf(good)
        # GOVERN has categories 1-6, MEASURE has 1-4.
        for bad in ("GOVERN-7.1", "MEASURE-5.1", "MAP-9", "GOVERN-1.x", "GOVERN", "gov-1.1"):
            with self.assertRaises(frameworks.CitationError, msg=bad):
                frameworks.validate_nist_ai_rmf(bad)

    def test_soc2_shape_and_bounds(self):
        for good in ("CC2.1", "CC6.8", "A1.1", "P3.1"):
            frameworks.validate_soc2(good)
        for bad in ("CC6.9", "CC10.1", "A2.1", "P9.1", "CC2"):
            with self.assertRaises(frameworks.CitationError, msg=bad):
                frameworks.validate_soc2(bad)

    def test_owasp_allow_list(self):
        frameworks.validate_owasp_llm("LLM01")
        frameworks.validate_owasp_llm("LLM10")
        for bad in ("LLM11", "LLM00", "llm99"):
            with self.assertRaises(frameworks.CitationError, msg=bad):
                frameworks.validate_owasp_llm(bad)

    def test_unknown_framework_rejected(self):
        with self.assertRaises(frameworks.CitationError):
            frameworks.validate_mapping("GDPR", "Article 5")

    def test_error_messages_are_actionable(self):
        # A contributor hitting this must be told exactly what to do.
        with self.assertRaises(frameworks.CitationError) as ctx:
            frameworks.validate_eu_ai_act("Article 62")
        self.assertIn("Article 73", str(ctx.exception))
        with self.assertRaises(frameworks.CitationError) as ctx:
            frameworks.validate_iso_42001("A.7.7")
        self.assertIn("A.7.6", str(ctx.exception))

    def test_validate_mappings_returns_all_errors(self):
        errs = frameworks.validate_mappings(
            {"EU_AI_ACT": ["Article 9", "Article 62"], "ISO_42001": ["A.8.6"]}
        )
        self.assertEqual(len(errs), 2)

    def test_registry_summary_and_catalog(self):
        summary = frameworks.registry_summary()
        self.assertEqual(summary["OWASP_LLM_TOP10"], 10)
        self.assertEqual(len(frameworks.OWASP_LLM_TOP10_IDS), 10)
        catalog = frameworks.framework_catalog()
        for name in frameworks.FRAMEWORKS:
            self.assertIn(name, catalog)
            self.assertIn("references", catalog[name])


class ShippedLibraryValidationTests(unittest.TestCase):
    """The library we actually ship must pass its own validator."""

    def test_default_controls_have_no_invalid_citations(self):
        errors = frameworks.validate_library(controls.DEFAULT_CONTROLS)
        self.assertEqual(errors, [], "\n".join(errors))

    def test_every_control_cites_at_least_one_framework(self):
        for control in controls.DEFAULT_CONTROLS:
            self.assertTrue(
                control.get("mappings"), f"{control['title']} has no framework mappings"
            )

    def test_every_cited_reference_is_registered_for_its_framework(self):
        # Independent second pass: validate through the public mapping validator,
        # not via validate_library, so a refactor of one cannot mask the other.
        for control in controls.DEFAULT_CONTROLS:
            for framework, refs in control["mappings"].items():
                self.assertIn(framework, frameworks.FRAMEWORKS, control["title"])
                for ref in refs:
                    frameworks.validate_mapping(framework, ref)

    def test_known_bad_citations_absent_from_library(self):
        forbidden = {
            frameworks.EU_AI_ACT: {"Article 61", "Article 62"},
            frameworks.ISO_42001: {"A.7.7", "A.8.6", "A.6.2.9", "A.9.5"},
        }
        for control in controls.DEFAULT_CONTROLS:
            for framework, refs in control["mappings"].items():
                for ref in refs:
                    self.assertNotIn(
                        ref,
                        forbidden.get(framework, set()),
                        f"{control['title']} cites known-bad {framework} {ref}",
                    )


class LibraryCoverageTests(unittest.TestCase):
    """Coverage assertions on the stored library, via the mapping engine."""

    def setUp(self):
        self.conn = db.connect(":memory:")
        for control in controls.DEFAULT_CONTROLS:
            controls.add_control(self.conn, **control)

    def test_library_is_substantially_larger_than_the_original_six(self):
        self.assertGreaterEqual(len(controls.DEFAULT_CONTROLS), 40)

    def test_framework_coverage(self):
        coverage = controls.framework_coverage(self.conn)
        # The four long-standing frameworks each get meaningful coverage.
        self.assertGreaterEqual(coverage[frameworks.EU_AI_ACT], 25)
        self.assertGreaterEqual(coverage[frameworks.NIST_AI_RMF], 30)
        self.assertGreaterEqual(coverage[frameworks.ISO_42001], 35)
        self.assertGreaterEqual(coverage[frameworks.SOC2_AI], 20)

    def test_controls_for_framework_returns_only_mapped_controls(self):
        eu = controls.controls_for_framework(self.conn, frameworks.EU_AI_ACT)
        self.assertGreaterEqual(len(eu), 25)
        for control in eu:
            self.assertIn(frameworks.EU_AI_ACT, control["mappings"])
        owasp = controls.controls_for_framework(self.conn, frameworks.OWASP_LLM_TOP10)
        self.assertGreaterEqual(len(owasp), 5)
        for control in owasp:
            self.assertIn(frameworks.OWASP_LLM_TOP10, control["mappings"])

    def test_serious_incident_control_cites_article_73(self):
        incident = next(
            c for c in controls.DEFAULT_CONTROLS if c["title"] == "Serious Incident Reporting"
        )
        self.assertIn("Article 73", incident["mappings"][frameworks.EU_AI_ACT])

    def test_high_risk_requirements_covered(self):
        # Chapter III Section 2 obligations (Arts 8-15) must all appear somewhere.
        cited = {
            ref
            for c in controls.DEFAULT_CONTROLS
            for ref in c["mappings"].get(frameworks.EU_AI_ACT, [])
        }
        for article in (
            "Article 8",
            "Article 9",
            "Article 10",
            "Article 11",
            "Article 12",
            "Article 13",
            "Article 14",
            "Article 15",
        ):
            self.assertIn(article, cited)

    def test_iso_annex_a_objectives_broadly_covered(self):
        cited = {
            ref
            for c in controls.DEFAULT_CONTROLS
            for ref in c["mappings"].get(frameworks.ISO_42001, [])
        }
        for objective in ("A.2", "A.3", "A.4", "A.5", "A.6", "A.7", "A.8", "A.9", "A.10"):
            self.assertTrue(
                any(ref.startswith(objective + ".") for ref in cited),
                f"no control cites ISO 42001 objective {objective}",
            )

    def test_controls_by_family_groups_everything(self):
        by_family = controls.controls_by_family(self.conn)
        total = sum(len(v) for v in by_family.values())
        self.assertEqual(total, len(controls.DEFAULT_CONTROLS))
        self.assertIn("Governance", by_family)
        self.assertIn("Assurance", by_family)

    def test_coverage_gaps_reports_unmapped_controls(self):
        gaps = controls.coverage_gaps(self.conn)
        self.assertEqual(set(gaps), set(frameworks.FRAMEWORKS))
        # SOC2 is deliberately not mapped for some EU-specific controls;
        # the gap report must surface them rather than pretend completeness.
        self.assertGreater(len(gaps[frameworks.SOC2_AI]), 0)
        # OWASP applies only to LLM-specific security controls.
        self.assertGreater(len(gaps[frameworks.OWASP_LLM_TOP10]), 0)

    def test_coverage_gaps_honours_framework_subset(self):
        gaps = controls.coverage_gaps(self.conn, [frameworks.EU_AI_ACT])
        self.assertEqual(list(gaps), [frameworks.EU_AI_ACT])


class RegistryAnchorTests(unittest.TestCase):
    """Non-circular anchors on the registry ITSELF.

    The library-vs-registry tests above are circular: they pass with an
    incorrect registry (all 44 passed while Article 75 was mis-titled as
    sandboxes and Annex A carried an invented A.3.4). These assertions pin
    facts verified against the OJ-published Regulation (EU) 2024/1689 (EU AI
    Act Service Desk / artificialintelligenceact.eu) and ISO/IEC 42001:2023
    Annex A enumerations, so a wrong registry entry fails the build even though
    every control still 'validates' against it.

    If a framework is amended, update BOTH these anchors and the registry, and
    re-verify against the primary source - do not edit one to silence the other.
    """

    # --- EU AI Act: the specific errors that shipped once -----------------
    def test_article_75_is_market_surveillance_not_sandboxes(self):
        title = frameworks.EU_AI_ACT_ARTICLES["Article 75"].lower()
        self.assertIn("mutual assistance", title)
        self.assertNotIn("sandbox", title)

    def test_sandboxes_are_articles_57_and_58(self):
        self.assertIn("sandbox", frameworks.EU_AI_ACT_ARTICLES["Article 57"].lower())
        self.assertIn("sandbox", frameworks.EU_AI_ACT_ARTICLES["Article 58"].lower())

    def test_incident_reporting_is_73_and_post_market_is_72(self):
        self.assertIn(
            "serious incident", frameworks.EU_AI_ACT_ARTICLES["Article 73"].lower()
        )
        self.assertIn(
            "post-market", frameworks.EU_AI_ACT_ARTICLES["Article 72"].lower()
        )

    def test_whistleblower_protection_is_87_and_complaint_right_is_85(self):
        self.assertIn(
            "reporting persons", frameworks.EU_AI_ACT_ARTICLES["Article 87"].lower()
        )
        self.assertIn(
            "complaint", frameworks.EU_AI_ACT_ARTICLES["Article 85"].lower()
        )

    def test_mis_titled_75_is_registered_as_known_bad_for_sandbox_use(self):
        # The exact mistake that shipped once must be caught with guidance.
        self.assertIn("Article 75 for sandboxes", frameworks.EU_AI_ACT_KNOWN_BAD)
        with self.assertRaises(frameworks.CitationError) as ctx:
            frameworks.validate_eu_ai_act("Article 75 for sandboxes")
        self.assertIn("Article 57", str(ctx.exception))

    # --- ISO/IEC 42001: structural invariants ----------------------------
    def test_annex_a_has_exactly_38_controls(self):
        self.assertEqual(len(frameworks.ISO_42001_ANNEX_A), 38)

    def test_annex_a_objective_control_counts(self):
        # Verified against multiple independent full Annex A enumerations:
        # A.2=3, A.3=2, A.4=5, A.5=4, A.6=9, A.7=5, A.8=4, A.9=3, A.10=3 = 38.
        counts: dict[str, int] = {}
        for ref in frameworks.ISO_42001_ANNEX_A:
            objective = ref.split(".")[0] + "." + ref.split(".")[1]
            counts[objective] = counts.get(objective, 0) + 1
        self.assertEqual(
            counts,
            {
                "A.2": 3, "A.3": 2, "A.4": 5, "A.5": 4, "A.6": 9,
                "A.7": 5, "A.8": 4, "A.9": 3, "A.10": 3,
            },
        )

    def test_objective_a3_stops_at_a3_3(self):
        # A.3.4 was invented once and slipped past the circular tests.
        self.assertIn("A.3.3", frameworks.ISO_42001_ANNEX_A)
        self.assertNotIn("A.3.4", frameworks.ISO_42001_ANNEX_A)

    def test_no_annex_a_control_exceeds_its_objective_bound(self):
        """Generic guard against the A.7.7 / A.8.6 error class: no control may
        exceed the highest known leaf in its objective. A.6 is nested
        (A.6.1.x, A.6.2.x); all other objectives are single-level."""
        single = {
            "A.2": (2, 4), "A.3": (2, 3), "A.4": (2, 6), "A.5": (2, 5),
            "A.7": (2, 6), "A.8": (2, 5), "A.9": (2, 4), "A.10": (2, 4),
        }
        nested = {"A.6": {1: (2, 3), 2: (2, 8)}}
        for ref in frameworks.ISO_42001_ANNEX_A:
            parts = ref.split(".")
            objective = ".".join(parts[:2])
            self.assertTrue(
                objective in single or objective in nested,
                f"{ref}: unknown objective {objective}",
            )
            if objective in single:
                self.assertEqual(len(parts), 3, f"{ref}: expected A.x.y form")
                lo, hi = single[objective]
                self.assertTrue(
                    lo <= int(parts[2]) <= hi,
                    f"{ref} outside the known leaf range {lo}-{hi} for {objective}",
                )
            else:
                self.assertEqual(len(parts), 4, f"{ref}: expected A.6.g.y form")
                group, lo_hi = int(parts[2]), nested[objective]
                self.assertIn(group, lo_hi, f"{ref}: unknown A.6 subgroup {group}")
                lo, hi = lo_hi[group]
                self.assertTrue(
                    lo <= int(parts[3]) <= hi,
                    f"{ref} outside the known leaf range {lo}-{hi} for A.6.{group}",
                )

    def test_every_annex_a_entry_looks_like_a_control_id(self):
        import re as _re
        pat = _re.compile(r"^A\.(?:[2-9]|10)\.\d+(?:\.\d+)?$")
        for ref in frameworks.ISO_42001_ANNEX_A:
            self.assertRegex(ref, pat)

    def test_a3_4_is_registered_as_known_bad(self):
        self.assertIn("A.3.4", frameworks.ISO_42001_KNOWN_BAD)

    # --- NIST AI RMF -----------------------------------------------------
    def test_nist_function_category_bounds(self):
        self.assertEqual(
            frameworks.NIST_AI_RMF_CATEGORY_BOUNDS,
            {"GOVERN": 6, "MAP": 5, "MEASURE": 4, "MANAGE": 4},
        )

    # --- registry hygiene ------------------------------------------------
    def test_known_bad_entries_are_not_also_registered_as_valid(self):
        """A citation must not appear in both the valid registry and known-bad
        under the same key - that would make the validator self-contradictory.
        (Note: 'Article 75 for sandboxes' is a distinct guidance key, not a
        bare article reference, so it does not collide with 'Article 75'.)"""
        for bad in frameworks.EU_AI_ACT_KNOWN_BAD:
            self.assertNotIn(bad, frameworks.EU_AI_ACT_ARTICLES)
        for bad in frameworks.ISO_42001_KNOWN_BAD:
            self.assertNotIn(bad, frameworks.ISO_42001_ANNEX_A)
            self.assertNotIn(bad, frameworks.ISO_42001_CLAUSES)

    def test_no_duplicate_or_empty_titles_in_registry(self):
        for table in (
            frameworks.EU_AI_ACT_ARTICLES,
            frameworks.ISO_42001_ANNEX_A,
            frameworks.ISO_42001_CLAUSES,
            frameworks.OWASP_LLM_TOP10_IDS,
        ):
            for ref, title in table.items():
                self.assertTrue(ref.strip(), "empty reference key")
                self.assertTrue(title.strip(), f"empty title for {ref}")


class MalformedMappingsTests(unittest.TestCase):
    """validate_mappings runs on untrusted HTTP bodies: malformed input must
    produce error strings (-> HTTP 400), never an exception (-> HTTP 500)."""

    def test_non_dict_mappings_returns_error_not_raises(self):
        for bad in (["not", "a", "dict"], "a string", 42, 3.5, True):
            errors = frameworks.validate_mappings(bad)
            self.assertEqual(len(errors), 1, f"expected 1 error for {bad!r}")
            self.assertIn("mappings must be an object", errors[0])

    def test_none_and_empty_are_fine(self):
        self.assertEqual(frameworks.validate_mappings(None), [])
        self.assertEqual(frameworks.validate_mappings({}), [])

    def test_non_list_refs_returns_error_not_raises(self):
        errors = frameworks.validate_mappings({"EU_AI_ACT": "Article 9"})
        self.assertEqual(len(errors), 1)
        self.assertIn("references must be a list", errors[0])

    def test_non_string_ref_returns_error_not_raises(self):
        errors = frameworks.validate_mappings({"EU_AI_ACT": [9, None]})
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("must be a string" in e for e in errors))

    def test_non_string_framework_key_returns_error_not_raises(self):
        errors = frameworks.validate_mappings({9: ["Article 9"]})
        self.assertEqual(len(errors), 1)
        self.assertIn("framework key must be a string", errors[0])

    def test_mixed_valid_and_malformed(self):
        errors = frameworks.validate_mappings(
            {"EU_AI_ACT": ["Article 9", 7], "ISO_42001": "A.7.4"}
        )
        self.assertEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
