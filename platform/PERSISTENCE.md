# Persistence convention

How `open-security-platform` components persist state, and the migration path
from in-memory/SQLite to a shared Postgres backbone (Phase 1).

## Principles

1. **Storage sits behind a repository interface.** Component code depends on an
   interface (e.g. `CaseRepository`), never on raw SQL. The backend is injected.
   This is what makes the SQLite → Postgres swap a per-component backend change,
   not a rewrite.
2. **SQLite is the offline default; Postgres is the production target.** Every
   component runs offline on SQLite (`:memory:` for tests, a file for `start`).
   A Postgres backend implements the same interface for production/HA.
3. **One schema convention across components** so the platform can later share a
   database and tooling.
4. **Audit trails are tamper-evident and hash-chained** (see `platform/audit`
   for Go; Python/Node components carry an equivalent chain). The audit chain is
   part of the repository surface (`AuditRepository.verify()`).

## Schema conventions

- **Primary keys:** `id TEXT` (UUIDv4), assigned by the application.
- **Timestamps:** `created_at TEXT NOT NULL DEFAULT (datetime('now'))` (UTC). Use
  RFC3339 strings; avoid DB-specific datetime types so SQLite and Postgres agree.
- **Structured fields:** store as `TEXT` JSON (e.g. `alerts`, `evidence`,
  `timeline`). Keeps the schema stable and portable; query with JSON functions
  where needed.
- **Enums:** store as `TEXT` with application-level validation (e.g. `status`,
  `severity`), not DB enum types.
- **Audit log:** an append-only table with `prev_hash`/`hash` forming a hash
  chain seeded at `"genesis"`.

## Repository pattern (reference: `soc/open-soar`)

`soc/open-soar/src/repository.ts` is the reference implementation:

```ts
export interface CaseRepository {
  create(title, opts?): Case;
  get(id): Case | undefined;
  list(): Case[];
  addAlert(id, alert): Case;
  // ...
}
export class SqliteCaseRepository implements CaseRepository { /* node:sqlite */ }
```

Callers depend on `CaseRepository`; today they get `SqliteCaseRepository`. A
`PostgresCaseRepository` implementing the same interface is the production
backend — no caller changes.

## Per-language backends

- **Node/TS:** `node:sqlite` (`DatabaseSync`, built into Node ≥22.6) for the
  SQLite backend; `pg` (or a thin HTTP client to a Postgres REST gateway) for
  Postgres. Zero-dep constraint applies to *runtime* deps — the SQLite backend
  uses only the built-in module.
- **Python:** stdlib `sqlite3` for SQLite; `psycopg`/`asyncpg` for Postgres
  (optional dependency, gated behind the Real backend).
- **Go:** `database/sql` with a driver. The stdlib-only Go components keep
  in-memory/file stores behind a repository interface; a Postgres backend adds a
  driver dependency (acceptable for the production backend, as oiaf already does).

## Migration path (Phase 1 → production)

1. Define the repository interface(s) for the component (done for open-soar).
2. Keep the SQLite backend as the offline/test default.
3. Add a Postgres backend implementing the same interface + per-component
   migrations (SQL files under `<component>/migrations/`).
4. Select the backend via config/env (e.g. `OSP_DB=postgres://…`); default stays
   SQLite so `make verify` remains green offline.

## Status

- **open-soar:** `CaseRepository` + `SqliteCaseRepository` (+ `AuditRepository`)
  — reference implementation, tested.
- Other components: most already persist to SQLite/single-node stores; adopting
  the explicit repository interface is incremental follow-up work. Shared
  Postgres + multi-tenancy land with the production backend.
