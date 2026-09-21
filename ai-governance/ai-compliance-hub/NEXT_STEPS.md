# Next Steps — ai-compliance-hub

## Evidence automation
- **Connectors** that auto-collect evidence from cloud, MLOps, logs, code repos
  (e.g. "model approval recorded", "eval passed", "access review done").
- **Continuous control monitoring**: map live telemetry to controls and flag gaps.
- Pull evidence from sibling projects (`open-ai-gateway` audit log,
  `ai-access-broker` access decisions, `ai-redteam-evals` reports).

## Frameworks & reporting
- ~~Expand the control library to full EU AI Act / NIST AI RMF / ISO 42001 sets.~~
  **Done (2026-09-20), with an honest caveat:** 46 controls across 8 families
  citing 146 distinct references — 35 EU AI Act articles/annexes, ISO 42001
  Annex A objectives A.2–A.10 plus 12 clauses, NIST AI RMF across all four
  functions, SOC 2 TSC families, and OWASP LLM Top 10. This is a *working*
  library, not a complete transcription of any framework; `GET /controls/gaps`
  reports what is unmapped instead of implying coverage.
- **Citation registry + validator** (`frameworks.py`): EU AI Act and ISO 42001
  use explicit allow-lists with official titles; NIST/SOC 2 use shape + bounds;
  OWASP is an explicit 10-entry list. Known-bad citations are registered *with
  the reason they are wrong* so the error names the correct reference
  (`Article 62` → `Article 73`, `A.7.7` → ends at `A.7.6`). Enforced by
  `tests/test_frameworks.py` and at the `POST /controls` boundary; deliberately
  NOT enforced in `controls.add_control` so third-party OSCAL imports stay
  permissive.
  - **Fixed a real bug while building this:** the original 6-control library
    cited `EU_AI_ACT Article 62` for incident reporting (pre-OJ draft
    numbering; it is Article 73) and non-existent `ISO_42001` controls `A.7.7`
    and `A.8.6` (A.7 ends at A.7.6, A.8 at A.8.5), plus `A.8.2` for risk
    assessment (A.8.2 is "information for users"). All corrected and now
    guarded by regression tests.
  - **An independent review then caught three errors in the NEW registry
    itself** (2026-09-20), which is the important lesson: library-vs-registry
    tests are *circular* and passed while the registry was wrong. Corrected:
    (i) `Article 75` was mis-titled "AI regulatory sandboxes" — in the
    OJ-published Act Art 75 is *mutual assistance, market surveillance and
    control of GPAI systems*; sandboxes are **Articles 57/58**. The validator
    was actively rejecting the correct citation. (ii) An invented `A.3.4`
    "Responsibilities of top management" made Annex A 39 entries, not 38 —
    a registry built to catch invented controls contained one. (iii)
    "Reporting of AI Concerns" cited `Article 85` (an affected person's right
    to complain) where **Article 87** (reporting of infringements / protection
    of reporting persons, importing Directive (EU) 2019/1937) is correct; both
    are now cited since the control covers internal channels and the external
    complaint route. Also hardened: `validate_mappings` on a non-dict input
    raised `AttributeError` (HTTP 500) instead of returning errors (HTTP 400).
    `RegistryAnchorTests` now pins externally verified registry facts so the
    circularity cannot hide a wrong entry again.
  - "AI Policy" now cites `Article 17` (QMS incl. documented compliance
    strategy) instead of `Article 4` (AI literacy — a staff-competence duty,
    not a policy artifact); literacy has its own control. Still weak and worth
    revisiting: "AI Supply Chain" → `Article 53` (GPAI provider obligations).
- **Remaining registry work:** ISO 42001 Clause 5 (Leadership / top-management
  responsibility) is not registered, so "AI Roles, Responsibilities and
  Accountability" cites only `A.3.2` — register the Clause 5 references after
  verifying them against the standard. Add EU AI Act Arts 59-63 (real-world
  testing / informed consent / SME measures), Arts 74-81 (market surveillance
  procedures), Arts 95-97 (codes of practice/conduct, confidentiality), and
  Annex I (harmonised standards). Consider allow-listing full NIST AI RMF
  subcategory IDs rather than shape-checking only.
- **Conformity assessment** templates for high-risk systems. *Partially
  covered:* a "Conformity Assessment and CE Marking" control now maps Arts
  43/47/48/49, but there is still no assessment *workflow* (questionnaire,
  evidence checklist, sign-off record).
- **Assurance report generator** (SOC 2 / ISO / EU AI Act style PDFs). Still
  not built — only the Markdown system/model cards exist.
- **Regulatory change monitor** that maps new rules to controls. Not built. The
  registry is now a good substrate for it: a new article must be registered with
  a title before any control can cite it, so "which controls cite Article X" is
  queryable and diffable across releases.

## Risk & governance
- **AI DPIA / impact assessment** guided questionnaires.
- **Vendor & third-party model risk** questionnaires and scoring.
- **Human oversight / approval workflows** and ethics review.
- **AI incident reporting** with regulatory timelines.

## Platform
- Web UI for inventory, controls, risks, and evidence.
- RBAC, Postgres backend, multi-tenant workspaces.
- Import/export (CSV, OSCAL, OpenControl) for interoperability.
