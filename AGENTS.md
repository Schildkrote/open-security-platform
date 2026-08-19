# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## What this repo is

`open-security-platform` is a polyglot Apache-2.0 security monorepo: 20 components (plus `platform/` + `integration/`)
across five portfolios — `identity/`, `ai-security/`, `ai-governance/`,
`offensive/`, and `soc/`. Non-oiaf components are self-contained MVPs with mock/in-memory backends.
A **subset** is proven on the `integration/` spine (redteam → pentest → compliance
+ pam-jit/sandbox webhooks); other cross-component wiring in READMEs is aspirational.
Tag the monorepo **v0.1-scaffold** until durable stores and wider spine adoption land.

## Build / test / lint commands

The root `Makefile` fans out across languages. Prefer it over invoking tools
per-directory.

```bash
make list          # show components grouped by language
make test          # test everything (Go + Node + Python)
make test-go       # Go only
make test-node     # Node/TS only
make test-python   # Python only
make lint          # go vet + gofmt check across Go components
make fmt           # gofmt -w across Go components
make verify        # lint + test (run this before finishing work)
make docs          # serve mkdocs site (if mkdocs installed)
```

Per-component equivalents (when working in a single component):

```bash
# Go (identity/oiaf, identity/open-pam-jit, ai-security/open-ai-gateway, offensive/attack-path)
go test ./... && go build ./... && go vet ./...

# Node/TS (identity/agent-identity, ai-security/ai-access-broker,
#          ai-security/mcp-security-gateway, offensive/pentest-manager, soc/open-soar)
npm test

# Python (ai-security/rag-authorization, ai-security/agent-sandbox,
#         ai-governance/ai-compliance-hub, ai-governance/ai-redteam-evals,
#         ai-governance/ai-redteam-platform, offensive/purple-team,
#         offensive/agent-redteam-range)
python3 -m unittest discover -s tests
```

**Always run `make verify` (or the relevant per-language commands) after making
changes and ensure it passes.**

## Toolchain conventions

- **Go:** 1.25/1.26. Four modules tied by root `go.work`. Module paths use
  `github.com/Schildkrote/<component>` (oiaf is `github.com/Schildkrote/oiaf`).
  `gofmt` formatting is enforced (CI fails on unformatted files); `.golangci.yml`
  enables govet, ineffassign, unused, gosimple, staticcheck, misspell.
- **Node/TS:** Node >= 22.6, npm workspaces, run with
  `node --experimental-strip-types`. **Zero npm runtime dependencies** — do not
  add runtime deps; tests use the built-in `node:test` runner. Linted with Biome
  (`biome.json`, formatter/import-sort off, lint only): `npm run lint:ts`.
- **Python:** >= 3.11, **stdlib only** — do not add third-party runtime
  dependencies; tests use `unittest`. Linted with ruff (`ruff.toml`):
  `ruff check <component-dirs>` (runs on the whole repo in CI).

> Go lint runs via `make lint`; Python (ruff) and TS (Biome) lint run in the
> `.github/workflows/lint.yml` CI workflow. Biome is a root **devDependency**
> only — runtime dependencies remain zero.

## Safety model (do not violate)

- **Offensive components** must keep authorized-scope gates, make no external
  network calls, use no destructive payloads, perform no real exfiltration,
  redact/hash evidence, and write tamper-evident audit logs.
- **`offensive/agent-redteam-range`** targets bind localhost-only and use fake
  secrets. They are intentionally insecure and out of scope for SECURITY.md
  reporting.
- **Everything must keep working offline with mocks.** Tests depend on the
  offline/mock model — never break it. Connector interfaces live in the OSS
  core; each ships a real implementation (public API, user-supplied credentials)
  plus a mock implementation for offline dev/tests.
- Go sources require the Apache-2.0 license header (enforced by
  `.licenserc.yaml`), **except** `identity/oiaf/**` which is excluded.


### `--live` gate: policy exceptions for state-changing or PII-touching work

Four classes of offensive work would violate the safety model if run by
default. Each is a **policy exception** implemented by the shared
`platform/livegate` package: default **OFF**, opt-in per invocation via
`--live <feature>` (comma-separated), and CI/test suites run mock-only with no
features enabled. The gate is printed in every run's output so the audit trail
shows exactly which exceptions were active.

| # | Feature | Flag | Exception conditions (enforced) |
|---|---------|------|---------------------------------|
| 6 | **Active attack-surface scanning** (port/service probes, HTTP requests, vulnerability templates) | `--live active-scanning` | explicit scope list per invocation; only read-only probes (GET/HEAD/OPTIONS, no exploit/auth-bypass/DoS templates); per-host rate limit (default 5 req/s); redacted evidence + tamper-evident audit log; 5-minute run cap. |
| 7 | **Account-recovery & account-existence probing** (reset flows, masked email/phone reveal, account-existence differentials) | `--live recovery-probing` | explicit target + identifier list; ≤ 1 state-changing request per identifier (one reset request / one reveal); global cap 10 identifiers per run; no credential submission; differential results audit-logged; at-least-daily cadence per identifier. |
| 8 | **People-search / background-check aggregation** (people finders, voter records, contact aggregators) | `--live people-search` | explicit `--consent` subject-consent flag required at run time; read-only GETs to a source whitelist; results cached and redacted (names hashed in the audit log); PII hidden from stdout unless `-verbose`; data minimization: one query per source per run. |
| 9 | **Authenticated platform scraping / contact harvesting** (emails/phones via user-supplied session) | `--live authenticated-scrape` | user-supplied credential in memory or env var only (never argv, never the audit log); read-only access, no posts or profile edits; per-platform rate limit (default 1 req/5s); harvested PII written redacted by default; session discarded at run end. |

Rules for adding new live features:

1. Register the feature in `platform/livegate` (constant + `Exceptions` entry)
   before any code may enable it; unknown features are rejected by `Parse`.
2. The feature's mock path must remain fully offline; the real path is only
   reachable when the gate is enabled **and** a scope/credential is supplied.
3. Every live action writes to the component's tamper-evident audit log with
   the active gate state; PII is redacted or hashed in logs and default
   output.
4. `SECURITY.md` documents the gate for reporters; the exception table above
   is the canonical list.

## `identity/oiaf` is a git subtree — do NOT edit directly

`identity/oiaf` is a `git subtree` import of the standalone repo
`https://github.com/Schildkrote/oiaf.git` (the canonical home). **Do not edit
files under `identity/oiaf/` directly in the monorepo** — the next subtree pull
will conflict. Make oiaf changes in the standalone repo, then pull them in:

```bash
git subtree pull --prefix identity/oiaf https://github.com/Schildkrote/oiaf.git main --squash -m "chore: sync identity/oiaf from upstream"
```

Because it is a subtree, `identity/oiaf` is also excluded from license-header
checks and may carry its own conventions (module path `github.com/Schildkrote/oiaf`).

## Repo layout & docs

- Each component has a `README.md` and an honest `NEXT_STEPS.md` (mock-vs-real
  status). Read these before extending a component.
- Governance: `GOVERNANCE.md`, `MAINTAINERS.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`.
- Docs site: mkdocs (`mkdocs.yml`, `docs/`), published via GitHub Pages.
- Deploy: `deploy/docker-compose.yml` aggregates oiaf + redteam-range targets,
  bound to 127.0.0.1 only.
- CI: `.github/workflows/ci.yml` (per-language test matrix), `lint.yml`,
  `security-scan.yml` (govulncheck + npm audit, continue-on-error), `docs.yml`.
