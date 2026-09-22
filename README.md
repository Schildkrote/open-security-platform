# open-security-platform

[![CI](https://github.com/Schildkrote/open-security-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/Schildkrote/open-security-platform/actions/workflows/ci.yml)
[![Lint](https://github.com/Schildkrote/open-security-platform/actions/workflows/lint.yml/badge.svg)](https://github.com/Schildkrote/open-security-platform/actions/workflows/lint.yml)
[![Docs](https://github.com/Schildkrote/open-security-platform/actions/workflows/docs.yml/badge.svg)](https://schildkrote.github.io/open-security-platform/)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25%2F1.26-00ADD8?logo=go&logoColor=white)](go.work)
[![Node](https://img.shields.io/badge/Node-%E2%89%A522.6-339933?logo=nodedotjs&logoColor=white)](package.json)
[![Python](https://img.shields.io/badge/Python-%E2%89%A53.11-3776AB?logo=python&logoColor=white)](ruff.toml)

> An open-source security platform: a monorepo of self-hostable, developer-friendly
> security products spanning identity, AI security, AI governance, offensive
> security, and security operations.

> [!NOTE]
> Independent open-source projects. Not affiliated with or endorsed by any
> commercial security vendor. Each component is self-contained (own manifest,
> tests, README, and `NEXT_STEPS.md`) and runs offline with zero or minimal
> dependencies.

## Ecosystem

```
                +----------------------------------------------+
                |          open-security-platform              |
                +----------------------------------------------+
   identity/        ai-security/      ai-governance/    offensive/        soc/
   ---------        ------------      --------------    ----------        ----
   oiaf             open-ai-gateway   ai-compliance-hub pentest-manager   open-soar
   open-pam-jit     ai-access-broker  ai-redteam-evals  purple-team
   agent-identity   mcp-security-gw   ai-redteam-plat.  attack-path
                    rag-authorization                   agent-redteam-range
                    agent-sandbox

```

The components are designed to interoperate: `ai-redteam-platform` embeds
`ai-redteam-evals` as its test engine and attacks the `agent-redteam-range`
targets; findings flow to `pentest-manager`; technique mapping aligns with
`purple-team`; evidence is compatible with `ai-compliance-hub`; privileged
actions can be brokered through `open-pam-jit` and run inside `agent-sandbox`.

### Shared platform layer

- [`platform/`](platform/) — the shared core: `audit` (tamper-evident hash-chained
  audit), `auth` (OIDC/JWT, Go/Python/Node), `rbac` (roles/scopes/multi-tenancy),
  `events` (integration-event emitter), `telemetry` (metrics/spans), a persistence
  convention, and the common event/audit JSON schemas.
- [`integration/`](integration/) — the integration control plane: an orchestrated
  end-to-end flow plus a **native webhook spine** where components emit/consume
  `IntegrationEvent`s directly, with a subscription/registry broker. Run it with
  `make integration`.

## What each component replaces

Honest vendor comparisons live on the [docs site](https://schildkrote.github.io/open-security-platform/comparison/).
Every component is a self-contained **v0.1-scaffold MVP** (mock/in-memory
backends) — see the [comparison overview](docs/comparison.md) for the maturity
legend. Only the integration-spine subset (`ai-redteam-platform` →
`pentest-manager` → `ai-compliance-hub` + `open-pam-jit`/`agent-sandbox`, and
`oiaf` as spine producer) is proven end-to-end today.

### Proving the Mock→Real seam locally

[`live/`](live/README.md) is a self-contained proof harness that exercises the
components' **Real** connector code paths — not their mocks — against local
containerized instances of Keycloak, Wazuh, DefectDojo, OpenBao and Ollama. This
is the part of the project that a unit test cannot cover: the seam where a
component stops talking to an in-memory fake and starts talking to a real product
over the network.

It requires Docker plus `go`, `node` (>= 22.6), `python3`, `curl` and `openssl`
on the host, and it is deliberately **excluded** from the root `make test` /
`make verify` fan-out so offline CI stays offline. All published ports bind to
**127.0.0.1 only**; credentials are random local-only values generated into
`live/.env` (git-ignored) and real credentials must never be committed. See
[`live/README.md`](live/README.md) for the proof scripts and the `make` targets.

| Portfolio | Component(s) | Category it targets | Full comparison |
|---|---|---|---|
| identity/ | `open-pam-jit`, `agent-identity` | PAM/JIT access (Teleport, CyberArk, Britive), agent identity (Astrix, Aembit, SPIFFE) | [comparison-identity.md](docs/comparison-identity.md) |
| ai-security/ | `open-ai-gateway`, `mcp-security-gateway`, `rag-authorization`, `agent-sandbox`, `ai-access-broker` | LLM gateways (LiteLLM, Portkey, Kong), MCP security (Lasso, Invariant Labs), RAG authz (Oso, OpenFGA), agent sandboxes (E2B, Daytona), AI access (Zscaler AI, Netskope) | [comparison-ai-security.md](docs/comparison-ai-security.md) |
| ai-governance/ | `ai-compliance-hub`, `ai-redteam-evals`, `ai-redteam-platform` | AI compliance (Vanta, Drata, Credo AI), AI red teaming (Garak, promptfoo, PyRIT, HiddenLayer) | [comparison-ai-governance.md](docs/comparison-ai-governance.md) |
| offensive/ | `pentest-manager`, `purple-team`, `attack-path`, `live-recon`, `username-enum`, `credential-intel`, `agent-redteam-range` | Pentest mgmt (DefectDojo, PlexTrac), BAS/purple team (CALDERA, AttackIQ), attack paths (BloodHound, XM Cyber), OSINT (Sherlock, SpiderFoot, HIBP), vulnerable AI ranges (Gandalf, DVWA-analog) | [comparison-offensive.md](docs/comparison-offensive.md) |
| soc/ | `open-soar` | SOAR/IR automation (XSOAR, Tines, Shuffle, TheHive) | [comparison-soc.md](docs/comparison-soc.md) |

## Portfolios

### identity/ — human, machine, and agent identity
| Component | Lang | What it does |
|---|---|---|
| [oiaf](identity/oiaf/) | Go | Open Identity Access Firewall: risk-based access control + adaptive MFA |
| [open-pam-jit](identity/open-pam-jit/) | Go | PAM / JIT access broker: approvals, temp creds, encrypted vault, session recording |
| [agent-identity](identity/agent-identity/) | Node/TS | Agent identity & permissions: scoped JWT, delegation chains, JIT, revocation |

### ai-security/ — AI/agent runtime security
| Component | Lang | What it does |
|---|---|---|
| [open-ai-gateway](ai-security/open-ai-gateway/) | Go | LLM/agent gateway + firewall: policy, redaction, rate limits, registry, audit |
| [ai-access-broker](ai-security/ai-access-broker/) | Node/TS | Employee AI access broker: SSO, app catalog, approvals, DLP, residency |
| [mcp-security-gateway](ai-security/mcp-security-gateway/) | Node/TS | MCP security gateway: registry, allowlists, policy, poisoning detection |
| [rag-authorization](ai-security/rag-authorization/) | Python | RAG authorization engine: ACL retrieval filtering, classification, overexposure |
| [agent-sandbox](ai-security/agent-sandbox/) | Python | Agent runtime sandbox: confined fs/net/shell, limits, recording, rollback |

### ai-governance/ — AI GRC and red teaming
| Component | Lang | What it does |
|---|---|---|
| [ai-compliance-hub](ai-governance/ai-compliance-hub/) | Python | AI compliance evidence hub: control library, framework mapping, risk, cards |
| [ai-redteam-evals](ai-governance/ai-redteam-evals/) | Python | AI red-team eval harness: attack library, scoring, regression, reports |
| [ai-redteam-platform](ai-governance/ai-redteam-platform/) | Python | AI red-team platform: registry, safe runner, evidence, compliance, reports |

### offensive/ — red team / pentest / purple team
| Component | Lang | What it does |
|---|---|---|
| [pentest-manager](offensive/pentest-manager/) | Node/TS | Pentest management: scope/ROE, findings (CVSS/EPSS/KEV), evidence, reports, retests |
| [purple-team](offensive/purple-team/) | Python | Purple team: ATT&CK library, safe tests, detection coverage, gap analysis |
| [attack-path](offensive/attack-path/) | Go | Attack path management: graph, path finding, risk scoring, choke points |
| [agent-redteam-range](offensive/agent-redteam-range/) | Python | Vulnerable-by-design AI targets (chatbot/RAG/MCP/agent/codegen) for testing/training |

### soc/ — security operations
| Component | Lang | What it does |
|---|---|---|
| [open-soar](soc/open-soar/) | Node/TS | SOAR / IR automation: playbook DAG engine, cases, enrichment, response, AI triage |

## Quickstart

```bash
make help        # show targets
make list        # list components by language
make test        # run every component's test suite (Go + Node + Python)
make build       # build Go components
make lint        # go vet + gofmt check
make docs        # serve the docs site (requires mkdocs)
```

Run an individual component from its directory (see its README), e.g.:

```bash
(cd ai-security/open-ai-gateway && go run .)                 # Go
(cd soc/open-soar && npm start)                              # Node/TS
(cd ai-governance/ai-redteam-platform && python3 examples/run_campaign.py)  # Python
```

## Repository layout

- `<portfolio>/<component>/` — each component is self-contained.
- `platform/` — shared core (audit, auth, rbac, events, telemetry, persistence,
  schemas). See [`platform/README.md`](platform/README.md).
- `integration/` — integration control plane + native webhook spine + e2e tests.
  See [`integration/README.md`](integration/README.md).
- `Makefile` — fan-out orchestration across languages (`make verify`,
  `make integration`).
- `go.work` — Go workspace tying the Go modules (module paths are unchanged).
- `package.json` — npm workspaces for the Node/TS components.
- `docs/` + `mkdocs.yml` — aggregated documentation site.
- `deploy/` — aggregate Docker Compose for the containerized components.
- `.github/` — CI (per-language test matrix + integration job), lint, docs, scan.

## Safety & acceptable use

Offensive-security components (`offensive/`, `ai-redteam-platform`) are built
for **authorized testing only**: scope/authorization gates, no external calls,
no destructive payloads, no real exfiltration, redacted + hashed evidence, and
tamper-evident audit logs. `agent-redteam-range` targets are intentionally
vulnerable **training** apps that bind to localhost and use fake secrets — never
deploy them publicly. See each component's README and [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0-only](LICENSE). © open-security-platform Authors.

## Governance

[Code of Conduct](CODE_OF_CONDUCT.md) · [Contributing](CONTRIBUTING.md) ·
[Governance](GOVERNANCE.md) · [Maintainers](MAINTAINERS.md) ·
[Security](SECURITY.md) · [Support](SUPPORT.md) · [Roadmap](ROADMAP.md) ·
[Changelog](CHANGELOG.md)
