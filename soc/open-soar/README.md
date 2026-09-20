# open-soar

An open **SOAR / IR Automation** platform: a playbook DAG engine, case
management, enrichment, response actions, AI-assisted triage, and a
tamper-evident audit trail. Zero runtime dependencies (Node 22 stdlib + `node:sqlite`).

## Features (MVP)

- **Playbook DAG engine** — define steps with dependencies; validated for
  cycles/unknown deps; independent steps run **in parallel** per level; failed
  steps cause dependents to be skipped
- **Node library** — enrichment (`enrich.ip/domain/user`), response actions
  (`action.block_ip/disable_user/create_ticket`), `transform.set`, `ai.triage`;
  extensible via `registerNode`
- **Case management** — create cases, attach alerts & evidence, status,
  assignment, classification, and a timeline
- **AI-assisted triage** — pluggable `TriageFn` (offline heuristic included)
  that classifies and scores severity
- **Playbook runs** attach results as evidence to cases
- **Hash-chained audit log** with integrity verification

## Quickstart

```bash
npm start   # listens on :8086
```

```bash
# Create a case
curl -X POST localhost:8086/cases -d '{"title":"phishing email reported","alert":{"ip":"1.2.3.4"}}'

# AI triage (sets classification + severity)
curl -X POST localhost:8086/cases/<CASE_ID>/triage -d '{}'

# Run the sample phishing-response playbook
curl -X POST localhost:8086/playbooks/pb-phishing/run \
  -d '{"input":{"ip":"1.2.3.4","title":"phishing email reported"},"case_id":"<CASE_ID>"}'

curl localhost:8086/cases/<CASE_ID>     # evidence now includes the playbook run
curl localhost:8086/audit/verify        # {"valid":true}
curl localhost:8086/playbooks           # list playbooks
```

## Tests

```bash
npm test
```

## Persistence backends

Cases and the audit chain sit behind repository interfaces
(`src/repository.ts`), so the storage backend swaps without touching callers:

- **SQLite (default, offline):** `SqliteCaseRepository` on the built-in
  `node:sqlite` — no setup; used by `npm start` and the tests.
- **Postgres (production):** `PostgresCaseRepository` talks to a
  [PostgREST](https://postgrest.org)-style REST gateway in front of Postgres via
  `src/pg_gateway.ts` (global `fetch`, zero runtime dependencies). Apply
  `migrations/0001_init.sql`, run a gateway against the database, and select it
  with `OSP_SOAR_GATEWAY=http://…` (optional `OSP_SOAR_GATEWAY_TOKEN`). Because
  `node:sqlite` is sync and HTTP is async, the Postgres repositories are an async
  mirror of the SQLite interface; wiring them into the HTTP server is in progress
  (see `NEXT_STEPS.md`).

## License

AGPL-3.0-only
