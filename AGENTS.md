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
- Durable store is **in-memory + JSON snapshot + SQLite** (`.sqlite` store path
  auto-selected by `apps/webhook`; `ontology.SaveSQLite/LoadSQLite`, pure-Go
  `modernc.org/sqlite`). No Postgres yet.
- Jurisdiction **packs** are wired into the hot path: `connectors/alpr`,
  `platform/actions`, and `apps/webhook` each accept an optional `packs.Engine`
  (nil = core `policy.Evaluate`, backward compatible); `apps/webhook` loads
  packs via `--packs <dir>` and gates every event with `--purpose`/`--role`
  policy context. Integration tests pin pack outcomes against core-policy
  controls.
- OBP biometric match hits arrive via the typed `connector-obp` path
  (BiometricHit + Person(pseudo), no raw pixels); see OBP `docs/obp-odp-bridge.md`.
- OSP/OBP connectors are **normalize-in libraries + fixtures**; no live bus to those repos.
- `deploy/` is **not shipped** (Apollo/air-gap notes are aspirational).
- Prefer connecting OSP/OBP over reimplementing them.

## Build

```bash
make verify   # offline unit + integration e2e
```
