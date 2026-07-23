# open-security-platform

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

[Apache-2.0](LICENSE). © open-security-platform Authors.

## Governance

[Code of Conduct](CODE_OF_CONDUCT.md) · [Contributing](CONTRIBUTING.md) ·
[Governance](GOVERNANCE.md) · [Maintainers](MAINTAINERS.md) ·
[Security](SECURITY.md) · [Support](SUPPORT.md) · [Roadmap](ROADMAP.md) ·
[Changelog](CHANGELOG.md)
