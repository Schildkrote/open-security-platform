# integration

The Phase-2 **integration control plane**: the piece that makes the components
talk to each other. It is a stdlib-only Python package that drives each
component's **existing public HTTP API** (no component changes required),
bridges their data models, brokers a privileged action through `open-pam-jit`,
executes it inside `agent-sandbox`, and records the whole flow on a common
hash-chained event schema.

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

## Modules

- `events.py` — `IntegrationEvent` envelope + `EventChain` (mirrors the
  `platform/audit.Chain` hashing algorithm).
- `clients.py` — thin HTTP clients for the five components + the field mappers
  (red-team `Finding` → pentest `FindingInput`; finding / sandbox record →
  compliance evidence).
- `servers.py` — start/stop helpers: Python servers in-thread, Node + Go as
  health-checked subprocesses on free localhost ports.
- `flow.py` — `run_flow(...)`, the orchestrator; returns all ids + verifications.
- `tests/test_e2e.py` — the offline end-to-end proof.

## Run

```bash
make integration        # builds open-pam-jit, starts all five, runs the flow
```

Requires `go`, `node` and `python3` on `PATH`. Everything binds `127.0.0.1`
only and uses mock/in-memory backends — no network, no external services.

## Scope notes

- The control plane records the cross-component event stream. Pushing event
  emission *into* each component (native outbound webhooks) is a follow-up;
  today the orchestrator emits on their behalf via their public APIs.
- `agent-sandbox` is a library (no server), so it is embedded in-process by the
  harness rather than called over HTTP.
- Real connector backends (Keycloak, Wazuh, DefectDojo, ...) are Phase 3; this
  increment proves the integration spine offline.
