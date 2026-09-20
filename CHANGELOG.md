# Changelog

All notable changes to open-security-platform are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ai-governance/ai-compliance-hub`: framework citation registry + validator
  (`frameworks.py`) covering EU AI Act (36 articles/annexes, OJ-published
  numbering), ISO/IEC 42001 (38 Annex A controls + 12 clauses), NIST AI RMF
  (shape + category bounds), SOC 2 TSC and OWASP LLM Top 10. Known-bad
  citations are rejected with the correct reference named.
- `ai-compliance-hub`: control library expanded 6 → 46 controls across 8
  families (146 distinct framework citations), plus coverage/gap reporting and
  new API endpoints `/frameworks`, `/controls/coverage`, `/controls/gaps`,
  `/controls/validate`. `POST /controls` now rejects invalid citations with 400.

### Fixed
- `ai-compliance-hub`: corrected mis-cited framework references in the control
  library — EU AI Act `Article 62` → `Article 73` (serious-incident reporting;
  61/62 are pre-OJ draft numbers), and removed non-existent ISO/IEC 42001
  controls `A.7.7`, `A.8.6` plus a wrong `A.8.2` mapping. Now guarded by
  regression tests so citation rot fails the build.

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
