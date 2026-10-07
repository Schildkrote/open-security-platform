# Hardening Changes — offensive components

Date: 2026-10-07 · Branch: `agent/hardening-offensive` · Implements the planned
fixes from `docs/hardening-gap-analysis.md` §5. Each fix is a separate commit
with its own tests; `make verify` stayed green throughout.

## Verified before/after

- Baseline (before any change): attack-path `go test ./...` + `go vet ./...`
  clean; pentest-manager `npm test` 23/23 pass.
- After: pentest-manager `npm test` 36/36 pass; attack-path 11/11 packages
  `go test ./...` + `go vet ./...` + `gofmt` clean; full `make verify` green.
- Offline/no-auth default unchanged: with no `OSP_AUTH_SECRET`,
  `OSP_WEBHOOK_SECRET`, `AUDIT_PATH` and no `--live` features, every route
  behaves exactly as before and nothing new is written to disk.

## Commits (in implementation order)

### 1. `fix(security): per-route scope enforcement on pentest-manager (PM-1)`

Files: `offensive/pentest-manager/src/{server,auth,webhook}.ts`,
`test/authz.test.ts`, `package.json`

- `auth.authenticate()` returns verified claims (not just a boolean); the
  server derives authorization per route family following the platform/rbac
  `<resource>:<action>` model: `engagements:write`, `findings:write`,
  `evidence:write`, `cases:read`, `findings:read`, `evidence:read`,
  `actions:run` (scope/check).
- `*` scope grants all (admin role expansion), matching `rbac.Can`.
- `/portal/*` routes are no longer categorically exempt: they require a valid
  token + `findings:read` (list) / `findings:write` (proof).
- `/webhook` optionally verifies an `OSP-Signature` HMAC (sha256, hex,
  constant-time) over the raw body when `OSP_WEBHOOK_SECRET` is configured.
- `/healthz` stays probe-open; no secret configured = open (offline default).
- Tests: scope table, kill-switch scoping (wrong-family tokens rejected),
  wildcard grant, portal auth, webhook HMAC positive/negative.

### 2. `fix(security): crash-safe bounded body parsing in pentest-manager (PM-2)`

Files: `offensive/pentest-manager/src/server.ts`, `test/body.test.ts`

- `JSON.parse` previously threw inside `req.on("end")` — outside the promise
  chain — so one POST with invalid JSON killed the process (uncaught
  exception). Now: malformed JSON → 400.
- Body size is capped (1 MiB) with the socket drained on excess:
  oversized → 413 (previously `data += c` grew unbounded — memory DoS).
- Stream errors → 400. Server stays alive through all of them.
- Tests: 400 + liveness, 413 + liveness, empty-body parity.

### 3. `fix(security): cross-client guard on portal proof route (PM-8)`

Files: `offensive/pentest-manager/src/server.ts`, `test/portal-proof.test.ts`

- `/portal/{clientId}/findings/{findingId}/proof` now resolves the finding and
  verifies the owning engagement's `client_id` before writing.
- Unknown finding → 404; foreign finding → 403 with no write side effects.
- Tests: cross-client 403 (verifies no retest was created), 404, legitimate
  owner still 201 + retest requested.

### 4. `fix(security): per-principal rate limit + audit trail on mutations (PM-5)`

Files: `offensive/pentest-manager/src/audit.ts` (new),
`src/server.ts`, `test/audit-rate.test.ts`, `package.json`

- Fixed-window in-memory `RateLimiter`: default 120 mutations/min/principal,
  429 on excess; opportunistic stale-window eviction bounds the map.
- `AuditTrail` implements the platform/audit hash-chain algorithm: canonical
  JSON (sorted keys, mirroring the Go/Python chains), sha256 over the
  pre-hash content, `prev_hash` linkage, one JSON object per line.
- Written to `AUDIT_PATH` when configured (0600, parent dirs created);
  in-memory only when unset (offline default). Events carry
  principal/route/target — no secrets, no PII.
- Anonymous callers are rate-limited under a shared `anonymous` principal;
  every mutation is audited with `sub` when auth is on.
- Tests: limiter unit (window, rollover, isolation, unlimited mode), trail
  unit (chain, JSONL, no key material), endpoint integration (2 allowed +
  429, `healthz` exempt, exact audit records).

### 5. `fix(security): Shodan API key from env only, never argv (AP-1)`

Files: `offensive/attack-path/main.go`, `main_test.go`

- Drops the `-shodan-key` flag; the key is read from `SHODAN_API_KEY` only
  (argv is visible in `ps`/history; the safety model requires credentials
  "only in memory or an env var").
- CLI flags refactored into a testable `newFlagSet()` constructor; source
  selection extracted into `newShodanSource(selector, key)`.
- Tests: mock needs no key, live requires env key, env read/rollback,
  flag-set registers no `-shodan-key`.

### 6. `fix(security): livegate gating + hash-chained audit for live enrichment (AP-2, AP-3)`

Files: `offensive/attack-path/main.go`, `main_test.go`, `go.mod`,
`internal/auditlog/` (new)

- `go.mod` now requires `github.com/Schildkrote/platform` (relative replace,
  same as the Go twins); `-shodan-source shodan` is gated behind
  `--live active-scanning` via `platform/livegate` (single source of truth,
  unknown features rejected).
- The gate summary prints at the start of every run; `-live-help` shows the
  policy table and exits.
- New `internal/auditlog` package implements the platform/audit hash-chain
  algorithm for enrichment events: JSONL 0600 via `-audit-path` (in-memory
  when unset), records source/dork/device-count/gate-state — never key
  material — with `prev_hash` linkage and sha256 integrity.
- Mock path remains fully offline and ungated (default unchanged).
- Tests: live source rejected without the feature, gate-enabled passes, mock
  ungated; auditlog chain + JSONL, in-memory default, tamper detection, no
  key leakage, bad-path error.

### 7. `fix(security): resource limits in analysis (AP-5)`

Files: `offensive/attack-path/internal/path/{path,path_test}.go`,
`internal/ingest/{ingest,ingest_test}.go`

- `path.FindPaths` stops at 10k results (hostile/huge scenarios can produce
  combinatorial path counts).
- `ingest.Build` rejects scenarios above `maxNodes` (10k) / `maxEdges` (50k)
  and edge weights that are NaN or Inf (previously normalized silently to 1,
  hiding broken data).
- Tests: enumeration cap respected on a diamond scenario, NaN/Inf rejected,
  finite accepted, node budget enforced.

## Deliberately not in this change set

- PM-3/PM-9 (enum validation, HOST binding) and PM-6/AP-4 (URL schemes) are
  P2 hygiene items from §3 — planned separately.
- oiaf PAM/access-evaluate wiring: deferred per §4 until a real execution
  path exists (the PM-1 scope seam is where it will plug in).
