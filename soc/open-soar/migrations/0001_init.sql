-- open-soar Postgres schema (Phase 1 persistence backend).
--
-- Mirrors the SQLite schema in soc/open-soar/src/db.ts using the platform
-- conventions in platform/PERSISTENCE.md: TEXT primary keys (app-assigned
-- UUIDv4), TEXT RFC3339 timestamps, TEXT JSON for structured fields, TEXT
-- enums validated in the application, and a hash-chained append-only audit log.
--
-- The Postgres backend (src/pg_gateway.ts) reaches this schema through a
-- PostgREST-style REST gateway. Applied by the operator, e.g.:
--   psql "$OSP_DB" -f migrations/0001_init.sql
-- The offline SQLite default needs no migration step.

CREATE TABLE IF NOT EXISTS cases (
  id             TEXT PRIMARY KEY,
  title          TEXT NOT NULL,
  severity       TEXT NOT NULL DEFAULT 'medium',
  status         TEXT NOT NULL DEFAULT 'open',
  assignee       TEXT,
  classification TEXT,
  alerts         TEXT NOT NULL DEFAULT '[]',
  evidence       TEXT NOT NULL DEFAULT '[]',
  timeline       TEXT NOT NULL DEFAULT '[]',
  created_at     TEXT NOT NULL DEFAULT to_char((now() AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
);

CREATE TABLE IF NOT EXISTS executions (
  id         TEXT PRIMARY KEY,
  playbook   TEXT NOT NULL,
  case_id    TEXT,
  status     TEXT NOT NULL,
  result     TEXT,
  created_at TEXT NOT NULL DEFAULT to_char((now() AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts        TEXT NOT NULL DEFAULT to_char((now() AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  actor     TEXT,
  event     TEXT,
  detail    TEXT,
  prev_hash TEXT,
  hash      TEXT
);
