# Roadmap

A high-level, non-committal roadmap for open-security-platform. Each component
has its own detailed `NEXT_STEPS.md`.

## Done

- **Monorepo + tooling:** 16 components consolidated with a fan-out `Makefile`,
  `go.work`, npm workspaces, per-language CI matrix, mkdocs docs, governance docs.
- **Platform backbone (Phase 1):** shared `platform/audit` (hash-chained audit),
  `platform/auth` (OIDC/JWT HS256, Go/Python/Node), `platform/rbac` (roles/scopes/
  multi-tenancy), `platform/telemetry` (Noop/InMemory/OTLP), `platform/events`
  (Go integration-event emitter), and a persistence convention + repository
  interface (`open-soar` pilot).
- **Integration spine (Phase 2):** orchestrated end-to-end flow + a **native
  webhook spine** (`integration/`): components emit/consume `IntegrationEvent`s
  directly (`ai-redteam-platform → pentest-manager → ai-compliance-hub`, plus
  `open-pam-jit` `access.granted` and `agent-sandbox` `action.executed`), with a
  subscription/registry broker for dynamic routing. Cross-language hash chaining.
- **Phase 3 connectors (Mock + Real):** LLM providers (OpenAI/Anthropic/Ollama),
  DefectDojo, Wazuh/OpenCTI/Cortex, OpenBao, Presidio redaction, pgvector, real
  MCP Streamable-HTTP transport, Garak/promptfoo engine adapters.
- **Phase 4 breadth:** SARIF/Nuclei importers, SIEM webhook ingestion, ATT&CK→Sigma
  mapping, OSCAL import/export, BloodHound/Prowler graph importers.

## Now

- **Enforce the backbone in-component:** adopt the repository interfaces, OIDC/RBAC
  middleware, and telemetry across the remaining components; add Postgres backends.
- **Exercise Real connector paths** against local instances (docker-compose) of
  Keycloak/Wazuh/DefectDojo/OpenBao; confirm the Mock↔Real seam end to end.
- Publish per-component documentation in the aggregated docs site.
- **Offensive OSINT expansion:** `offensive/username-enum` (username
  enumeration), Shodan dorks in `offensive/attack-path`,
  `offensive/credential-intel` (breach lookups), passive domain intelligence +
  OSINT source taxonomy, and IP/phone geo enrichment — all mock-first with
  real connectors behind the `--live` gate where egress is required.
- **`--live` gate rollout:** implement the four policy exceptions (active
  scanning, recovery probing, people search, authenticated scraping) with
  `platform/livegate`; each ships a mock mode that runs offline and a real
  mode gated behind `--live <feature>` with per-feature conditions (see
  AGENTS.md safety model).

## Next

- **Hardening:** replace regex detectors with ML classifiers (Llama Guard/NeMo/
  Presidio); real sandboxing (gVisor/Firecracker); stdio MCP transport.
- **Attack path expansion:** cloud IAM and Active Directory ingestion (BloodHound)
  for `attack-path`; probabilistic path scoring; what-if simulation.
- **Continuous validation:** schedule safe tests in CI/CD; detection-coverage
  trends; AI purple teaming.

## Later

- **Platform concerns:** web UIs, multi-tenancy enforcement, packaging (Helm,
  images), and a unified release process; hosted control plane (separate repo).

## Contributing to the roadmap

Open an issue to propose direction. Significant changes follow the
[governance](GOVERNANCE.md) process.
