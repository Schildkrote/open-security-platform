"""Framework reference registry and citation validator.

Why this module exists
----------------------
Control libraries rot: framework identifiers get mis-cited (a draft article
number survives a renumbering, a control ID is invented, an Annex A reference
points at a control that does not exist). In a compliance product a wrong
citation is worse than no citation, because it silently produces evidence
packages an auditor will reject.

So this module is the single source of truth for *which references are legal*
in each supported framework, and ``validate_mapping`` / ``validate_library``
check any control library against it.

Design notes
------------
* ``EU_AI_ACT`` and ``ISO_42001`` use **explicit allow-lists with titles**.
  If a citation is not in the registry it is rejected. Adding a new article or
  Annex A control means adding it here first, with its official title - a
  deliberate forcing function, not an inconvenience.
* ``NIST_AI_RMF`` and ``SOC2_AI`` use **shape + bounds** validation, because
  both are large enumerated ID spaces whose authoritative lists live in the
  source documents (NIST AI RMF 1.0; AICPA TSC). Shape validation catches
  typos and invented families without asserting a possibly-stale exhaustive
  subcategory list.
* ``OWASP_LLM_TOP10`` is an explicit allow-list (only ten IDs).

Validation is **not** enforced inside ``controls.add_control``: that function
must stay permissive so OSCAL catalogs from third parties can be imported.
The shipped library (``controls.DEFAULT_CONTROLS``) is validated in the test
suite instead - see ``tests/test_frameworks.py``.

EU AI Act numbering caveat
--------------------------
The OJ-published Regulation (EU) 2024/1689 numbers differ from earlier draft
numbering. Notably: serious-incident reporting is **Article 73** (not 61/62)
and post-market monitoring is **Article 72**. Anything derived from pre-2024
drafts, blog posts or older GRC exports may still carry the old numbers.
Treat the OJ-published numbers - the ones registered here - as authoritative.

Provenance (so the "verified" claim is auditable)
------------------------------------------------
Registry contents were checked against these sources on **2026-09-20**:

* EU AI Act articles + titles: European Commission **AI Act Service Desk**
  article index (https://ai-act-service-desk.ec.europa.eu/en/ai-act) and
  https://artificialintelligenceact.eu, cross-checked against EUR-Lex
  Regulation (EU) 2024/1689 (https://eur-lex.europa.eu/eli/reg/2024/1689/oj).
* ISO/IEC 42001:2023 Annex A control IDs and titles: multiple independent
  full 38-control enumerations (isms.online, mindsetcyber, riskprofs,
  nemko digital). The per-objective counts asserted in
  ``tests/test_frameworks.py`` are the arithmetic proof of that enumeration
  (3+2+5+4+9+5+4+3+3 = 38).
* NIST AI RMF 1.0 function/category structure: NIST AI RMF 1.0 and the
  NIST AI RMF -> ISO/IEC 42001 crosswalk (airc.nist.gov).
* OWASP Top 10 for LLM Applications: owasp.org LLM Top 10 (2025).
* SOC 2 Trust Services Criteria families: AICPA TSC family numbering.

Those sources are **not** vendored into this repository, and the standards move.
``tests/test_frameworks.py::RegistryAnchorTests`` pins the load-bearing facts so
a stale entry fails the build; re-verify against the primary sources and update
BOTH the registry and the anchors when a framework is amended. ISO 42001 is a
paid standard - the Annex A titles here are from public secondary enumerations,
so confirm against your copy of the standard before relying on them for an audit.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

# Framework identifiers recognised by this hub.
EU_AI_ACT = "EU_AI_ACT"
ISO_42001 = "ISO_42001"
NIST_AI_RMF = "NIST_AI_RMF"
SOC2_AI = "SOC2_AI"
OWASP_LLM_TOP10 = "OWASP_LLM_TOP10"

FRAMEWORKS: tuple[str, ...] = (
    EU_AI_ACT,
    ISO_42001,
    NIST_AI_RMF,
    SOC2_AI,
    OWASP_LLM_TOP10,
)

FRAMEWORK_LABELS: dict[str, str] = {
    EU_AI_ACT: "EU AI Act (Regulation (EU) 2024/1689)",
    ISO_42001: "ISO/IEC 42001:2023 (AI management systems)",
    NIST_AI_RMF: "NIST AI Risk Management Framework 1.0",
    SOC2_AI: "SOC 2 Trust Services Criteria (AI-relevant)",
    OWASP_LLM_TOP10: "OWASP Top 10 for LLM Applications",
}

# --------------------------------------------------------------------------
# EU AI Act - Regulation (EU) 2024/1689, OJ-published numbering.
# Only articles/annexes actually cited by the control library are registered;
# add new ones here (with title) before citing them in a control mapping.
# --------------------------------------------------------------------------
EU_AI_ACT_ARTICLES: dict[str, str] = {
    "Article 4": "AI literacy",
    "Article 5": "Prohibited AI practices",
    "Article 6": "Classification rules for high-risk AI systems",
    "Article 8": "Compliance with the requirements",
    "Article 9": "Risk management system",
    "Article 10": "Data and data governance",
    "Article 11": "Technical documentation",
    "Article 12": "Record-keeping",
    "Article 13": "Transparency and provision of information to deployers",
    "Article 14": "Human oversight",
    "Article 15": "Accuracy, robustness and cybersecurity",
    "Article 16": "Obligations of providers of high-risk AI systems",
    "Article 17": "Quality management system",
    "Article 18": "Documentation keeping",
    "Article 19": "Automatically generated logs",
    "Article 20": "Corrective actions and duty of information",
    "Article 21": "Cooperation with competent national authorities",
    "Article 25": "Responsibilities along the AI value chain",
    "Article 26": "Obligations of deployers of high-risk AI systems",
    "Article 27": "Fundamental rights impact assessment for high-risk AI systems",
    "Article 43": "Conformity assessment",
    "Article 47": "EU declaration of conformity",
    "Article 48": "CE marking",
    "Article 49": "Registration",
    "Article 50": "Transparency obligations for certain AI systems",
    "Article 53": "Obligations for providers of general-purpose AI models",
    "Article 55": "Obligations for providers of GPAI models with systemic risk",
    "Article 56": "Codes of practice",
    "Article 72": "Post-market monitoring",
    "Article 73": "Reporting of serious incidents",
    "Article 57": "AI regulatory sandboxes",
    "Article 58": "Detailed arrangements for, and functioning of, AI regulatory sandboxes",
    "Article 75": "Mutual assistance, market surveillance and control of general-purpose AI systems",
    "Article 87": "Reporting of infringements and protection of reporting persons",
    "Article 85": "Right to lodge a complaint with a market surveillance authority",
    "Article 86": "Right to explanation of individual decision-making",
    "Article 99": "Penalties",
    "Annex III": "High-risk AI systems referred to in Article 6(2)",
    "Annex IV": "Technical documentation referred to in Article 11",
}

# Citations that look plausible but are WRONG, kept so the validator can give a
# specific, actionable error instead of a generic "unknown reference".
EU_AI_ACT_KNOWN_BAD: dict[str, str] = {
    "Article 61": "pre-OJ draft numbering; serious-incident reporting is Article 73 "
    "(Art 61 as published is informed consent to real-world testing)",
    "Article 62": "pre-OJ draft numbering; serious-incident reporting is Article 73 "
    "(Art 62 as published is measures for providers and deployers, in particular SMEs)",
    # Art 75 IS a real article but it is market surveillance/mutual assistance,
    # not sandboxes. Registered as known-bad *for the sandbox use* because this
    # exact mistake shipped once: a citation validator that silently accepted it
    # is worse than no validator.
    "Article 75 for sandboxes": "Article 75 is mutual assistance / market surveillance "
    "of general-purpose AI systems; AI regulatory sandboxes are Article 57 (and Art 58)",
}

# --------------------------------------------------------------------------
# ISO/IEC 42001:2023 - Annex A controls (38 controls, objectives A.2-A.10)
# plus the management-system clauses cited by this library.
# --------------------------------------------------------------------------
ISO_42001_ANNEX_A: dict[str, str] = {
    "A.2.2": "AI policy",
    "A.2.3": "Alignment with other organizational policies",
    "A.2.4": "Review of the AI policy",
    "A.3.2": "AI roles and responsibilities",
    "A.3.3": "Reporting of concerns",
    "A.4.2": "Resource documentation",
    "A.4.3": "Data resources",
    "A.4.4": "Tooling resources",
    "A.4.5": "System and computing resources",
    "A.4.6": "Human resources",
    "A.5.2": "AI system impact assessment process",
    "A.5.3": "Documentation of AI system impact assessments",
    "A.5.4": "Assessing AI system impact on individuals or groups",
    "A.5.5": "Assessing societal impacts of AI systems",
    "A.6.1.2": "Objectives for responsible development of AI systems",
    "A.6.1.3": "Processes for responsible design and development",
    "A.6.2.2": "AI system requirements and specification",
    "A.6.2.3": "Documentation of AI system design and development",
    "A.6.2.4": "AI system verification and validation",
    "A.6.2.5": "AI system deployment",
    "A.6.2.6": "AI system operation and monitoring",
    "A.6.2.7": "AI system technical documentation",
    "A.6.2.8": "AI system recording of event logs",
    "A.7.2": "Data for development and enhancement of AI systems",
    "A.7.3": "Acquisition of data",
    "A.7.4": "Quality of data for AI systems",
    "A.7.5": "Data provenance",
    "A.7.6": "Data preparation",
    "A.8.2": "Information and information for users",
    "A.8.3": "External reporting",
    "A.8.4": "Communication of incidents",
    "A.8.5": "Information for interested parties",
    "A.9.2": "Processes for responsible use of AI systems",
    "A.9.3": "Objectives for responsible use of AI systems",
    "A.9.4": "Intended use of the AI system",
    "A.10.2": "Allocation of responsibilities",
    "A.10.3": "Suppliers",
    "A.10.4": "Customers",
}

ISO_42001_CLAUSES: dict[str, str] = {
    "Clause 5.2": "AI policy",
    "Clause 6.1": "Actions to address risks and opportunities",
    "Clause 7.5": "Documented information",
    "Clause 8.1": "Operational planning and control",
    "Clause 8.2": "AI risk assessment",
    "Clause 8.3": "AI risk treatment",
    "Clause 8.4": "AI system impact assessment",
    "Clause 9.1": "Monitoring, measurement, analysis and evaluation",
    "Clause 9.2": "Internal audit",
    "Clause 9.3": "Management review",
    "Clause 10.1": "Nonconformity and corrective action",
    "Clause 10.2": "Continual improvement",
}

# Citations that look plausible but are WRONG.
ISO_42001_KNOWN_BAD: dict[str, str] = {
    "A.6.2.9": "Annex A objective A.6 ends at A.6.2.8 (event logging)",
    "A.7.7": "Annex A objective A.7 ends at A.7.6 (data preparation)",
    "A.8.6": "Annex A objective A.8 ends at A.8.5 (information for interested parties)",
    "A.9.5": "Annex A objective A.9 ends at A.9.4 (intended use)",
    "A.11.2": "Annex A ends at objective A.10",
    "A.1.1": "Annex A starts at objective A.2 (policies related to AI)",
    "A.3.4": "Annex A objective A.3 has only A.3.2 and A.3.3; top-management "
    "responsibility is a management-system clause, not an Annex A control",
}

# --------------------------------------------------------------------------
# NIST AI RMF 1.0 - four functions with a known number of categories each
# (GOVERN 1-6, MAP 1-5, MEASURE 1-4, MANAGE 1-4). Subcategory depth is shape
# checked; the authoritative subcategory list is the AI RMF 1.0 document.
# --------------------------------------------------------------------------
NIST_AI_RMF_CATEGORY_BOUNDS: dict[str, int] = {
    "GOVERN": 6,
    "MAP": 5,
    "MEASURE": 4,
    "MANAGE": 4,
}

_NIST_RE = re.compile(
    r"^(?P<fn>GOVERN|MAP|MEASURE|MANAGE)-(?P<cat>[1-9])(?:\.(?P<sub>[1-9]\d?))?$"
)

# --------------------------------------------------------------------------
# SOC 2 Trust Services Criteria - family -> highest valid sub-criterion number.
# --------------------------------------------------------------------------
SOC2_TSC_BOUNDS: dict[str, int] = {
    "CC1": 5,
    "CC2": 3,
    "CC3": 4,
    "CC4": 2,
    "CC5": 3,
    "CC6": 8,
    "CC7": 5,
    "CC8": 1,
    "CC9": 2,
    "A1": 3,
    "PI1": 5,
    "C1": 2,
    "P1": 1,
    "P2": 1,
    "P3": 2,
    "P4": 3,
    "P5": 2,
    "P6": 1,
    "P7": 1,
    "P8": 1,
}

_SOC2_RE = re.compile(r"^(?P<fam>CC[1-9]|A1|PI1|C1|P[1-8])\.(?P<num>[1-9])$")

# --------------------------------------------------------------------------
# OWASP Top 10 for LLM Applications - explicit, ten entries.
# --------------------------------------------------------------------------
OWASP_LLM_TOP10_IDS: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


class CitationError(ValueError):
    """Raised when a framework reference is not valid for its framework."""


def validate_eu_ai_act(reference: str) -> None:
    ref = reference.strip()
    if ref in EU_AI_ACT_ARTICLES:
        return
    if ref in EU_AI_ACT_KNOWN_BAD:
        raise CitationError(
            f"EU_AI_ACT {ref!r} is a known-bad citation: {EU_AI_ACT_KNOWN_BAD[ref]}"
        )
    raise CitationError(
        f"EU_AI_ACT {ref!r} is not in the verified registry "
        f"(EU_AI_ACT_ARTICLES in compliance_hub/frameworks.py). Register the "
        f"article with its official title before citing it."
    )


def validate_iso_42001(reference: str) -> None:
    ref = reference.strip()
    if ref in ISO_42001_ANNEX_A or ref in ISO_42001_CLAUSES:
        return
    if ref in ISO_42001_KNOWN_BAD:
        raise CitationError(
            f"ISO_42001 {ref!r} is a known-bad citation: {ISO_42001_KNOWN_BAD[ref]}"
        )
    raise CitationError(
        f"ISO_42001 {ref!r} is not a valid Annex A control or registered clause. "
        f"Annex A objectives run A.2-A.10 (38 controls); clauses are listed in "
        f"ISO_42001_CLAUSES."
    )


def validate_nist_ai_rmf(reference: str) -> None:
    ref = reference.strip().upper()
    m = _NIST_RE.match(ref)
    if not m:
        raise CitationError(
            f"NIST_AI_RMF {reference!r} does not match FUNCTION-CATEGORY[.SUB] "
            f"where FUNCTION is one of {sorted(NIST_AI_RMF_CATEGORY_BOUNDS)}"
        )
    fn, cat = m.group("fn"), int(m.group("cat"))
    bound = NIST_AI_RMF_CATEGORY_BOUNDS[fn]
    if cat > bound:
        raise CitationError(
            f"NIST_AI_RMF {reference!r}: {fn} has categories 1-{bound}, got {cat}"
        )


def validate_soc2(reference: str) -> None:
    ref = reference.strip().upper()
    m = _SOC2_RE.match(ref)
    if not m:
        raise CitationError(
            f"SOC2_AI {reference!r} does not match FAMILY.N "
            f"(families: {', '.join(sorted(SOC2_TSC_BOUNDS))})"
        )
    fam, num = m.group("fam"), int(m.group("num"))
    bound = SOC2_TSC_BOUNDS[fam]
    if num > bound:
        raise CitationError(
            f"SOC2_AI {reference!r}: {fam} runs to {fam}.{bound}, got .{num}"
        )


def validate_owasp_llm(reference: str) -> None:
    ref = reference.strip().upper()
    if ref in OWASP_LLM_TOP10_IDS:
        return
    raise CitationError(
        f"OWASP_LLM_TOP10 {reference!r} is not one of "
        f"{', '.join(sorted(OWASP_LLM_TOP10_IDS))}"
    )


_VALIDATORS = {
    EU_AI_ACT: validate_eu_ai_act,
    ISO_42001: validate_iso_42001,
    NIST_AI_RMF: validate_nist_ai_rmf,
    SOC2_AI: validate_soc2,
    OWASP_LLM_TOP10: validate_owasp_llm,
}


def validate_mapping(framework: str, reference: str) -> None:
    """Validate one framework reference; raise CitationError if invalid."""
    if framework not in _VALIDATORS:
        raise CitationError(
            f"unknown framework {framework!r}; supported: {', '.join(FRAMEWORKS)}"
        )
    _VALIDATORS[framework](reference)


def validate_mappings(mappings: Any) -> list[str]:
    """Validate a whole mapping dict; return a list of error strings (empty = ok).

    Tolerates malformed input instead of raising: this is called on
    untrusted HTTP request bodies, where ``mappings`` may arrive as a list,
    string or null. A non-mapping (or a mapping whose values are not iterable
    strings) yields a descriptive error rather than an AttributeError, so the
    API returns 400 instead of 500.
    """
    errors: list[str] = []
    if mappings is None:
        return errors
    if not isinstance(mappings, dict):
        return [
            f"mappings must be an object of framework -> list of references, "
            f"got {type(mappings).__name__}"
        ]
    for framework, refs in mappings.items():
        if not isinstance(framework, str):
            errors.append(f"framework key must be a string, got {type(framework).__name__}")
            continue
        if isinstance(refs, str) or not isinstance(refs, Iterable):
            errors.append(
                f"{framework}: references must be a list of strings, "
                f"got {type(refs).__name__}"
            )
            continue
        for ref in refs:
            if not isinstance(ref, str):
                errors.append(f"{framework}: reference must be a string, got {type(ref).__name__}")
                continue
            try:
                validate_mapping(framework, ref)
            except CitationError as exc:
                errors.append(str(exc))
    return errors


def validate_library(controls: Iterable[dict[str, Any]]) -> list[str]:
    """Validate a control library (e.g. ``controls.DEFAULT_CONTROLS``).

    Returns one error string per bad citation, prefixed with the control title
    so a contributor can find it. Empty list means the library is clean.
    """
    errors: list[str] = []
    seen_titles: set[str] = set()
    for control in controls:
        title = control.get("title", "<untitled>")
        if title in seen_titles:
            errors.append(f"{title}: duplicate control title in the library")
        seen_titles.add(title)
        if not control.get("family"):
            errors.append(f"{title}: missing 'family'")
        for err in validate_mappings(control.get("mappings") or {}):
            errors.append(f"{title}: {err}")
    return errors


def registry_summary() -> dict[str, Any]:
    """Counts of registered references per framework (used by tests and /frameworks)."""
    return {
        EU_AI_ACT: len(EU_AI_ACT_ARTICLES),
        ISO_42001: len(ISO_42001_ANNEX_A) + len(ISO_42001_CLAUSES),
        NIST_AI_RMF: sum(NIST_AI_RMF_CATEGORY_BOUNDS.values()),
        SOC2_AI: sum(SOC2_TSC_BOUNDS.values()),
        OWASP_LLM_TOP10: len(OWASP_LLM_TOP10_IDS),
    }


def framework_catalog() -> dict[str, dict[str, Any]]:
    """Human-readable catalog of what each registry covers."""
    return {
        EU_AI_ACT: {
            "label": FRAMEWORK_LABELS[EU_AI_ACT],
            "validation": "explicit allow-list",
            "references": EU_AI_ACT_ARTICLES,
        },
        ISO_42001: {
            "label": FRAMEWORK_LABELS[ISO_42001],
            "validation": "explicit allow-list",
            "references": {**ISO_42001_CLAUSES, **ISO_42001_ANNEX_A},
        },
        NIST_AI_RMF: {
            "label": FRAMEWORK_LABELS[NIST_AI_RMF],
            "validation": "shape + category bounds",
            "references": dict(NIST_AI_RMF_CATEGORY_BOUNDS),
        },
        SOC2_AI: {
            "label": FRAMEWORK_LABELS[SOC2_AI],
            "validation": "shape + family bounds",
            "references": dict(SOC2_TSC_BOUNDS),
        },
        OWASP_LLM_TOP10: {
            "label": FRAMEWORK_LABELS[OWASP_LLM_TOP10],
            "validation": "explicit allow-list",
            "references": OWASP_LLM_TOP10_IDS,
        },
    }
