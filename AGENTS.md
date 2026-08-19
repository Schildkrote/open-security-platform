# AGENTS.md

## Mission
Build a **decision-centric ontology OS**: typed digital twin + policy +
actions + audit. Connect OSP and OBP; add LE-gated ALPR-style modules.
Not a Palantir clone; not a Flock clone; not untargeted surveillance.

## Hard rules
1. **Policy before read/write/action.** Every path calls `policy.Evaluate`.
2. **Mock-first.** CI offline. Real sensors/APIs behind explicit config.
3. **No open-internet camera discovery.** ALPR/CCTV only allowlisted or
   agency-owned feeds with basis.
4. **Warrant/case context** for historical ALPR pattern queries by default.
5. **No credentials in git.** Env / secret managers only.
6. **Apache-2.0**, polyglot monorepo, each component has tests + NEXT_STEPS.
7. Prefer connecting existing OSP/OBP tools over reimplementing them.
8. Biometric payloads stay pseudonymous; raw face bytes do not live in ODP.

## Stack conventions
- Go 1.22+ for platform core; Python only if a connector truly needs it.
- `make verify` must pass offline.
- Fixture-driven integration tests.

## Out of scope
- Building or marketing a civilian mass-ALPR network
- Kill-chain automation without human approval gates
- Classified multi-level security (document only; no fake SCIF claims)

## Scaffold honesty (v0.1)

- Tag: **v0.1-scaffold**. `make verify` green ≠ production Ontology OS.
- Durable store is **in-memory + JSON snapshot** only (no SQLite/Postgres yet).
- Jurisdiction **packs** load in tests/e2e demos; `connectors/alpr`, `platform/actions`,
  and `apps/webhook` default paths use core `policy.Evaluate` **without** packing
  packs into the hot path. Wire `packs.Engine` before claiming pack enforcement everywhere.
- OSP/OBP connectors are **normalize-in libraries + fixtures**; no live bus to those repos.
- `deploy/` is **not shipped** (Apollo/air-gap notes are aspirational).
- Prefer connecting OSP/OBP over reimplementing them.

## Build

```bash
make verify   # offline unit + integration e2e
```
