# Changelog

All notable changes to open-security-platform are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ai-governance/ai-compliance-hub`: framework citation registry + validator
  (`frameworks.py`) covering EU AI Act (39 articles/annexes, OJ-published
  numbering), ISO/IEC 42001 (38 Annex A controls + 12 clauses), NIST AI RMF
  (shape + category bounds), SOC 2 TSC and OWASP LLM Top 10. Known-bad
  citations are rejected with the correct reference named. Registry provenance
  (source + verification date per framework) is recorded in the module
  docstring and README so the "verified" claim is auditable; it also notes that
  ISO/IEC 42001 titles come from public secondary enumerations (paid standard)
  and should be confirmed against the standard before audit use.
- `ai-compliance-hub`: control library expanded 6 → 46 controls across 8
  families (147 distinct framework citations), plus coverage/gap reporting and
  new API endpoints `/frameworks`, `/controls/coverage`, `/controls/gaps`,
  `/controls/validate`. `POST /controls` now rejects invalid citations with 400.

### Fixed
- `ai-compliance-hub`: corrected mis-cited framework references in the control
  library — EU AI Act `Article 62` → `Article 73` (serious-incident reporting;
  61/62 are pre-OJ draft numbers), and removed non-existent ISO/IEC 42001
  controls `A.7.7`, `A.8.6` plus a wrong `A.8.2` mapping. Now guarded by
  regression tests so citation rot fails the build.
- `ai-compliance-hub`: an **independent review** then caught three errors in the
  new registry itself, exposing that library-vs-registry tests are circular
  (they passed while the registry was wrong). Corrected: `Article 75` was
  mis-titled "AI regulatory sandboxes" (in the OJ Act Art 75 is mutual
  assistance / market surveillance of GPAI; sandboxes are **Arts 57/58**, now
  registered); a non-existent ISO/IEC 42001 `A.3.4` was removed (Annex A is
  exactly 38 controls); "Reporting of AI Concerns" now cites **Article 87**
  (reporting of infringements / protection of reporting persons, importing
  Directive (EU) 2019/1937) alongside Art 85; and "AI Policy" cites Article 17
  (QMS) instead of Article 4 (AI literacy). `validate_mappings` on non-dict
  input no longer raises `AttributeError` (was HTTP 500, now a 400 with
  details). Added `RegistryAnchorTests` pinning externally verified registry
  facts (per-objective Annex A counts, Art 72/73/75/85/87 titles) so a wrong
  entry fails the build despite the circularity. Test count 44 → 64.

## [0.1.0] - 2026-07-23

### Added
- Monorepo consolidating 16 components across five portfolios: `identity/`,
  `ai-security/`, `ai-governance/`, `offensive/`, and `soc/`.
- `identity/oiaf` imported via `git subtree` (history preserved).
- Shared tooling: fan-out `Makefile`, `go.work`, npm workspaces, per-Python
  `pyproject.toml`, GitHub Actions CI (per-language test matrix), mkdocs docs,
  and governance docs.
- Root `AGENTS.md`: build/test/lint commands, toolchain conventions, safety
  model, and the `identity/oiaf` subtree warning.
- Python lint (ruff, `ruff.toml`) and TypeScript lint (Biome, `biome.json`)
  wired into the Lint CI workflow.
- All components licensed under AGPL-3.0-only.

### Changed
- Go module paths normalized from `github.com/example/*` to
  `github.com/Schildkrote/*` (`open-ai-gateway`, `open-pam-jit`, `attack-path`).
- `.github/CODEOWNERS` now references the real repository owner; per-portfolio
  team rules are commented out until those GitHub teams exist. `MAINTAINERS.md`
  updated to match.

### Components (initial MVPs)
- identity: oiaf, open-pam-jit, agent-identity
- ai-security: open-ai-gateway, ai-access-broker, mcp-security-gateway,
  rag-authorization, agent-sandbox
- ai-governance: ai-compliance-hub, ai-redteam-evals, ai-redteam-platform
- offensive: pentest-manager, purple-team, attack-path, agent-redteam-range
- soc: open-soar
