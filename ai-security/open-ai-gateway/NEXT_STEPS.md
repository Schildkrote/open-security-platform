# Next Steps — open-ai-gateway

The MVP is a working, dependency-free gateway. To grow it into a production
AI security control plane:

## Core hardening
- **Streaming (SSE) support**: currently buffers full responses; add
  chunk-by-chunk redaction for `stream: true`.
- **Real upstream auth**: forward/rotate provider API keys from a secrets
  store instead of trusting client-supplied keys.
- **Persistent stores**: replace in-memory limiter/registry with SQLite/Postgres
  so state survives restarts and scales across replicas.
- **Distributed rate limiting**: Redis-backed counters for multi-instance deploys.
- **mTLS / OIDC** for client authentication instead of static API keys.

## Detection quality
- Swap regex redaction for **NER models** (Presidio, GLiNER) for higher recall.
  > **Blocking prerequisite: fix fail-open first.** `redactor.Presidio.Redact`
  > returns the input unchanged on ANY error — a downed service, a non-2xx
  > response, a decode failure — so PII transits upstream while the audit trail
  > records no redactions. That is not a false record, but it means the gateway's
  > core function can be silently off. The `Redactor` interface
  > (`Redact(text) (string, []string)`) has no error channel, so "backend
  > unreachable" is indistinguishable from "nothing sensitive". Wiring Presidio in
  > therefore requires an interface change across every implementation, and the new
  > backend must fail CLOSED like the response-shape guards do. This is latent
  > rather than live today: the shipped binary only constructs `Regex{}`, which has
  > no failure mode, and no config knob selects a backend. The moment one does,
  > this becomes blocker-class for a PII-removal product.
- Add **prompt-injection / jailbreak classifiers** to the policy engine.
- **DLP dictionaries** and custom sensitive-data patterns per tenant.

## Platform expansion (the roadmap)
- **Agent identity**: issue scoped tokens per agent (see `agent-identity`).
- **MCP security gateway**: deep JSON-RPC inspection (see `mcp-security-gateway`).
- **AI DLP / redaction service** as a standalone mode.
- **Observability**: export OpenTelemetry traces + Prometheus metrics.
- **Model routing / fallback / caching** across multiple providers.
- **Compliance evidence**: feed audit log into `ai-compliance-hub`.

## Ops
- Container image + Helm chart.
- Config hot-reload and a management UI.
- Multi-tenancy with per-tenant policy and budgets.
