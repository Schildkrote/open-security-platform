# Vendor Comparison

How the open-security-platform components relate to the commercial and
open-source products in the same category — portfolio by portfolio.

!!! warning "Not a drop-in replacement — yet"
    Every component in this repository is a **self-contained MVP** with
    mock/in-memory backends, tagged **v0.1-scaffold**. The comparisons below
    describe *category* overlap ("what it would replace for you *if* it were
    production-grade"), not feature parity. Only a subset of components
    (`ai-redteam-platform` → `pentest-manager` → `ai-compliance-hub`, with
    `open-pam-jit` and `agent-sandbox`, plus `oiaf` as a spine producer) is
    proven on the [`integration/`](https://github.com/Schildkrote/open-security-platform/tree/main/integration)
    webhook spine; other cross-component wiring is aspirational.

## Maturity legend

| Level | Meaning |
|---|---|
| 🟥 **Scaffold (v0.1)** | Self-contained MVP, mock/in-memory backends, offline tests pass. Not production-hardened. |
| 🟨 **Spine-proven subset** | Scaffold maturity, but proven end-to-end on the `integration/` webhook spine with a verified hash-chained audit trail. |

Nothing in this repository is above these levels today. Vendors listed
alongside are mature, production products — the honest framing is "here is the
category we are building toward", not "use this instead of CyberArk".

## Per-portfolio comparisons

| Portfolio | Components compared | Page |
|---|---|---|
| Identity | `open-pam-jit`, `agent-identity` | [comparison-identity.md](comparison-identity.md) |
| AI Security | `open-ai-gateway`, `mcp-security-gateway`, `rag-authorization`, `agent-sandbox`, `ai-access-broker` | [comparison-ai-security.md](comparison-ai-security.md) |
| AI Governance | `ai-compliance-hub`, `ai-redteam-evals`, `ai-redteam-platform` | [comparison-ai-governance.md](comparison-ai-governance.md) |
| Offensive | `pentest-manager`, `purple-team`, `attack-path`, `live-recon`, `username-enum`, `credential-intel`, `agent-redteam-range` | [comparison-offensive.md](comparison-offensive.md) |
| SOC | `open-soar` | [comparison-soc.md](comparison-soc.md) |

## Shared platform layer

The [`platform/`](https://github.com/Schildkrote/open-security-platform/tree/main/platform)
layer (hash-chained audit, OIDC/JWT auth, RBAC, telemetry, integration events)
sits in the same category as: Casbin/OpenFGA (authz), OpenTelemetry
(telemetry), Keycloak/Authentik (OIDC), and immudb/OpenTimestamps
(tamper-evidence). It is scaffold-grade: conventions and working offline
implementations, not a hardened replacement for any of them.

## Independence

These are independent open-source projects. Not affiliated with, endorsed by,
or benchmarked against any commercial vendor listed — vendor names are used
descriptively to position the category. Claims about vendor products are based
on their public positioning; nothing here is a partnership statement.
