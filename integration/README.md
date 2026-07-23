# integration

The Phase-2 **integration layer**: the piece that makes the components talk to
each other. It provides **two complementary integration paths**, both offline
and both verified by `make integration`:

1. **Orchestrated flow** (`flow.run_flow`) — a stdlib-only Python control plane
   drives each component's existing public HTTP API, bridges their data models,
   brokers a privileged action through `open-pam-jit`, executes it inside
   `agent-sandbox`, and records the whole flow on a common hash-chained event
   schema. No component changes required.
2. **Native webhook spine** (`flow.run_flow_native`) — the components emit and
   consume integration events **themselves** over HTTP webhooks (shared schema
   contract + small idiomatic per-component webhook code), cascading directly
   without an external mapper.

This is the concrete deliverable behind `.context/PLAN.md` Phase 2 ("first
end-to-end integration flow — the proof") and the "components don't talk to
each other" gap named in `.context/market-gap-analysis.md`.

## The flow

```
ai-redteam-platform  --findings-->  pentest-manager
                     --evidence-->  ai-compliance-hub
privileged action    --brokered-->  open-pam-jit  --executed-->  agent-sandbox
```

1. **Red-team campaign** (`ai-redteam-platform`): register + authorize a target,
   run an (unguarded mock) campaign → findings.
2. **Findings → `pentest-manager`**: create a client + engagement, map each
   red-team `Finding` onto a pentest `FindingInput` and push it.
3. **Evidence → `ai-compliance-hub`**: register a system + control, map each
   finding (and the sandbox record) onto compliance evidence rows.
4. **Privileged action → `open-pam-jit`**: request + approve a JIT credential
   for a seeded target (fully audited).
5. **Execution → `agent-sandbox`**: run the (simulated) remediation command
   confined + recorded, then store the record as compliance evidence.

Every step appends an `IntegrationEvent`
([`platform/schemas/integration_event.schema.json`](../platform/schemas/integration_event.schema.json))
to a tamper-evident hash chain; the test verifies that chain plus each
component's own audit/evidence chain.

## Native webhook spine

The components themselves emit and consume `IntegrationEvent`s (same schema) via
HTTP webhooks — no external mapper. Wiring is opt-in config (empty by default, so
offline behaviour is unchanged):

```
ai-redteam-platform  --campaign.complete-->  pentest-manager  --finding.created-->  ai-compliance-hub
open-pam-jit         --access.granted----->  (subscribers)        [Go, platform/events]
agent-sandbox        --action.executed---->  (subscribers)        [on_execute hook]
```

- **`ai-redteam-platform`** (`ai_redteam_platform/webhook.py`): `Platform(...,
  webhook_urls=[...])` emits `campaign.complete` (with findings) after a campaign.
- **`pentest-manager`** (`src/webhook.ts`): `POST /webhook` consumes
  `campaign.complete` → auto-provisions a client + engagement + findings, then
  emits `finding.created`. Outbound URLs via `OSP_WEBHOOK_URLS` env.
- **`ai-compliance-hub`** (`compliance_hub/webhook.py`): `POST /webhook` consumes
  `finding.created` → records tamper-evident evidence (auto-provisions a system +
  control).
- **`open-pam-jit`** (Go, shared `platform/events` emitter): emits
  `access.granted` on approve / break-glass. Outbound URLs via `-webhooks` flag.
- **`agent-sandbox`**: `Sandbox.on_execute` hook fires with the `SessionRecord`
  after every execution; wire it to an emitter (e.g. `integration.events.HttpEmitter`)
  to publish `action.executed`.

**Canonical hash form (cross-language):** every emitter hashes over **compact,
sorted-key, raw-UTF-8 JSON** with the `hash` field zeroed — Python
(`json.dumps(sort_keys=True, separators=(",",":"))`), Go (`platform/events`
`marshalCanonical`), and Node (`stableStringify`) all produce identical bytes for
the same event, so a chain emitted in one language verifies in another.

Emission is best-effort and hash-chained; a down subscriber never breaks the
producer. `tests/test_webhooks.py` proves both: the campaign cascade
(Python → Node → Python) and the privileged-action emission (Go `access.granted`
+ Python `action.executed`), verifying each per-source chain **and recomputing
the hashes cross-language**.

## Modules

- `events.py` — `IntegrationEvent` envelope + `EventChain` (mirrors the
  `platform/audit.Chain` hashing algorithm).
- `clients.py` — thin HTTP clients for the five components + the field mappers
  (red-team `Finding` → pentest `FindingInput`; finding / sandbox record →
  compliance evidence).
- `servers.py` — start/stop helpers: Python servers in-thread, Node + Go as
  health-checked subprocesses on free localhost ports.
- `flow.py` — `run_flow(...)` (orchestrated) and `run_flow_native(...)` (native
  webhook cascade); both return ids + verifications.
- `tests/test_e2e.py` — the orchestrated end-to-end proof (five components).
- `tests/test_webhooks.py` — the native webhook cascade proof.

The per-component webhook code lives in the components themselves:
`ai-governance/ai-redteam-platform/ai_redteam_platform/webhook.py`,
`offensive/pentest-manager/src/webhook.ts`,
`ai-governance/ai-compliance-hub/compliance_hub/webhook.py`,
`identity/open-pam-jit/internal/api/api.go` (uses the shared Go emitter
`platform/events`), and the `ai-security/agent-sandbox` `on_execute` hook.

## Run

```bash
make integration        # builds open-pam-jit, starts all five, runs the flow
```

Requires `go`, `node` and `python3` on `PATH`. Everything binds `127.0.0.1`
only and uses mock/in-memory backends — no network, no external services.

## Scope notes

- Two paths coexist: the **orchestrated** flow (control plane maps + calls) and
  the **native webhook spine** (components emit/consume directly). Native
  emission covers the campaign cascade (`ai-redteam-platform → pentest-manager →
  ai-compliance-hub`) plus privileged-action emission (`open-pam-jit`
  `access.granted`, `agent-sandbox` `action.executed`). Next: a shared
  subscription/registry so components discover subscribers, and Phase-3 real
  connectors.
- `agent-sandbox` is a library (no server), so it is embedded in-process by the
  harness rather than called over HTTP.
- The shared contract is the event **schema** + chaining algorithm; each
  component carries a small idiomatic webhook implementation (consistent with the
  "self-contained component" principle and the per-language audit chains).
- Real connector backends (Keycloak, Wazuh, DefectDojo, ...) are Phase 3; this
  increment proves the integration spine offline.
