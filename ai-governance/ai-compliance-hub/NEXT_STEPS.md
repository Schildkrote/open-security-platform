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
- Remaining citation gaps to close: EU AI Act Arts 76-78 (market surveillance),
  Art 95-97 (codes of conduct/confidentiality), Annex I harmonised standards;
  ISO 42001 A.6.1.1 and A.6.2.1 (not in Annex A numbering used here — verify
  against the standard before adding); full NIST AI RMF subcategory IDs
  (currently shape-validated only, not allow-listed).

## Risk & governance
- **AI DPIA / impact assessment** guided questionnaires.
- **Vendor & third-party model risk** questionnaires and scoring.
- **Human oversight / approval workflows** and ethics review.
- **AI incident reporting** with regulatory timelines.

## Platform
- Web UI for inventory, controls, risks, and evidence.
- RBAC, Postgres backend, multi-tenant workspaces.
- Import/export (CSV, OSCAL, OpenControl) for interoperability.
