# Hardening Gap Analysis — offensive components

Date: 2026-10-07 · Branch: `agent/hardening-offensive` · Scope: `offensive/attack-path` (Go),
`offensive/pentest-manager` (Node/TS). Security review of the platform ITSELF: these
components hold client engagement data, evidence with PII, scopes/ROE, and
third-party API credentials, so the bar is: no credential leakage, no injection,
no cross-tenant writes, no unauthenticated mutation of engagement state.

Verified baselines before any change: attack-path `go test ./...` +
`go vet ./...` clean; pentest-manager `npm test` 23/23 pass.

---

## 1. Scaffold vs. real

### offensive/attack-path — real core, single live connector, CLI-only
Real, tested, non-trivial:
- Graph engine, depth-bounded cycle-safe path enumeration, risk scoring,
  choke-point/remediation ranking (`internal/graph`, `internal/path`,
  `internal/analysis`).
- Strict scenario ingestion with schema validation (`internal/ingest`: node id
  required, edge endpoints must exist).
- Three importers (native JSON, BloodHound CE, Prowler) with tests.
- One real external-data path: Shodan host/search client
  (`internal/shodan/source.go:112-184`), read-only GET, 5-result cap, 10s timeout.

Not present (and not claimed): HTTP API, persistence, multi-tenancy, shell/exec.
No code-execution surface at all — output rendering is `%q`/`json.Marshal` based
(no templating).

### offensive/pentest-manager — real MVP on embedded SQLite
Real, tested:
- Engagement workflow incl. ROE, consent, time window, kill switch and a
  scope/authorization gate (`src/engagements.ts:91-105`).
- Findings with CVSS/EPSS/KEV prioritization, retest workflow.
- Evidence vault: regex redaction (email/SSN/card/API keys/private keys),
  SHA-256 content hash, hash-chained chain of custody (`src/evidence.ts`).
- Reports, DefectDojo sink (real REST v2 client, live-gated via
  `--live=external-findings-push` + env creds), inbound/outbound webhook spine
  with hash-chained events (`src/webhook.ts`).
- Storage is `node:sqlite` (real, file-backed capable), not a mock.

Both components keep the offline/mock model intact; nothing requires network.

## 2. Attack-surface map

attack-path (CLI, single-shot):
- Inputs: `-scenario` file path, `-geo-table`, `-domain-table` (local file reads);
  `-shodan` dork string; `-shodan-source` selector; `-shodan-key` / `SHODAN_API_KEY`;
  `-maxdepth`, `-top` ints.
- Outbound network: exactly one — Shodan API GET, keyed.
- Exec: none (no shell, no eval, no templates, no containers).

pentest-manager (long-running HTTP server, default :8087):
- Routes (all in `src/server.ts`): `/healthz`; `/clients` GET/POST;
  `/engagements` GET/POST; `/engagements/{id}/{roe,consent,window,status,kill-switch}`
  POST; `/engagements/{id}/scope` GET/POST; `/engagements/{id}/scope/check` POST;
  `/engagements/{id}/findings` GET/POST; `/findings/{id}/status|evidence|retest`
  POST; `/findings/{id}/retest/resolve` POST; `/engagements/{id}/report` GET;
  `/evidence/verify` GET; `/portal/{clientId}/findings` GET;
  `/portal/{clientId}/findings/{findingId}/proof` POST; `/webhook` POST.
- Body handling: `readBody` accumulates the request with no size limit and
  `JSON.parse`s it (`src/server.ts:18-24`).
- Outbound network: DefectDojo push (env URL + token, live-gated), webhook
  emission (`OSP_WEBHOOK_URLS`).
- Secrets: `OSP_AUTH_SECRET` (JWT HS256), `DEFECTDOJO_API_KEY`, webhook URLs.
- Exec: none (no shell, no eval, no docker socket).

## 3. Ranked security gaps

### P0 — fix now

- **PM-1 · Auth is opt-in and scope-less; sensitive routes categorically exempt.**
  `src/server.ts:49` — auth runs only when `OSP_AUTH_SECRET` is set, only on
  POST, and `/webhook` plus both `/portal/*` routes are always unauthenticated.
  `authorized()` is called with no scope argument (`src/server.ts:49`), so any
  valid token from any component grants every mutation — including
  `kill-switch` and `status`. A deployed instance is a write-open API for
  engagement state, ROE, consent flags and scope targets.
  Fix: enforce the platform scope model per route family
  (`findings:write`, `evidence:write`, `engagements:write`, `actions:run`),
  extend optional auth to `/portal/*`, and optional HMAC-signature verification
  for `/webhook` (only enforced when a webhook secret is configured — the
  offline default stays open per AGENTS.md).

- **PM-2 · Malformed JSON body crashes the process; unbounded body size.**
  `src/server.ts:18-24` — `JSON.parse` throws inside the `req.on("end")`
  callback, outside the promise chain, so a single POST with invalid JSON
  raises an uncaught exception and kills the server (availability bug a client
  portal user or scanner can trigger accidentally). `data += c` also grows
  without a cap (memory DoS).
  Fix: catch parse errors → return 400; cap body size (e.g. 1 MiB) → 413.

- **AP-1 · Credential on the command line.** `main.go:34` accepts the Shodan
  API key via `-shodan-key`; argv is visible in `ps`/shell history and the
  AGENTS.md safety model explicitly requires credentials "only in memory or an
  env var (never argv, never the audit log)".
  Fix: read the key from `SHODAN_API_KEY` only; drop the argv flag and update
  docs/help text.

### P1 — fix next

- **AP-2 · Live outbound path bypasses the `--live` gate.** Every other live
  capability in the repo (Go and Node twins) is gated behind
  `platform/livegate`, but `-shodan-source shodan` performs keyed outbound
  requests with no gate, no audit line, and no rate/cap awareness
  (`main.go:58-78`, `internal/shodan/source.go:132`).
  Fix: import `platform/livegate` (attack-path is in `go.work`), require
  `--live active-scanning` for the Shodan source, print the gate summary, and
  audit-log the action with redacted parameters.

- **AP-3 · No audit trail for the live/credentialed action.** The component
  with an outbound credentialed path writes no tamper-evident audit record.
  Fix: add a small `internal/auditlog` package implementing the
  `platform/audit` hash-chain algorithm (JSONL, 0600 file via `AUDIT_PATH`,
  stderr otherwise); record live enrichment events (source, dork, device count
  — no key material).

- **PM-8 · Cross-client write in the portal proof route.**
  `src/server.ts:137-142` — `/portal/{clientId}/findings/{findingId}/proof`
  does not check that `findingId` belongs to an engagement of `clientId`; any
  caller can attach proof-of-fix evidence and force a retest on any finding id.
  Fix: verify the owning engagement's `client_id` before writing.

- **PM-5 · No rate limiting or audit on mutating endpoints.** Any loop can
  hammer engagement/finding writes; there is no audit record of who mutated
  what (the evidence hash chain records content, not actor/action).
  Fix: lightweight in-memory per-principal rate limiter on mutating routes
  (429 on excess) + a hash-chained audit event per mutation (principal, route,
  target id) written to `AUDIT_PATH` when configured.

### P2 — hygiene

- **AP-5 · Resource limits in analysis.** Path enumeration is depth-bounded
  but has no cap on total paths or scenario size; a hostile/huge scenario can
  burn unbounded CPU/memory. Fix: cap results (e.g. 10k paths) and reject
  scenarios above a node/edge budget; validate edge weights (NaN/Inf) in
  `ingest.Build`.
- **AP-4 / PM-6 · Config-supplied URLs.** `shodan.API.BaseURL` and
  `DEFECTDOJO_URL`/`OSP_WEBHOOK_URLS` accept any scheme/host — SSRF by config,
  not by attacker input (operator-controlled). Document; enforce https unless
  the host is localhost.
- **PM-3 · Weak field validation.** Severity/status accept arbitrary strings
  (breaks prioritization semantics downstream); add enum validation and length
  caps on text fields.
- **PM-9 · Server binds all interfaces.** `listen(port)` binds `::`; the repo
  convention (`deploy/docker-compose.yml`) is 127.0.0.1. Respect a `HOST` env
  with `127.0.0.1` default.

## 4. oiaf PAM / access-evaluate wiring assessment

The integration spine (`integration/`) carries redteam → pentest-manager →
compliance-hub via webhooks, and brokered privileged execution through
`identity/open-pam-jit` + `agent-sandbox` — but pentest-manager itself executes
nothing, so PAM-enforced execution is not on its critical path today.
`oiaf /v1/access/evaluate` (bearer-protected) is the right enforcement point for
any future exec/jump-host capability, and both components already accept the
shared `platform/auth` claim shape, so tokens from the platform IdP (incl. oiaf's
mock IdP) work as-is. Recommendation: defer direct oiaf wiring until a real
execution path exists in these components; the JWT/scope hardening in PM-1 is
the correct seam to plug it into later. This follows AGENTS.md honesty rule —
not wiring oiaf in where it would be decorative.

## 5. Planned fixes (next change set)

1. PM-1: per-route scope enforcement + portal auth + webhook HMAC option (Node).
2. PM-2: safe body parsing with size cap (Node).
3. PM-8: cross-client proof check (Node).
4. PM-5: rate limiter + audit events on mutations (Node).
5. AP-1: key from env only (Go).
6. AP-2 + AP-3: livegate gating + hash-chained audit for live enrichment (Go).
7. AP-5: path/result caps + weight validation (Go).
8. PM-3/PM-9: enum validation, HOST binding (Node).
Tests for each; `make verify` must stay green; offline default (no auth secret,
mock-only) unchanged.
