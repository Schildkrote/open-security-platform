import { DatabaseSync } from "node:sqlite";

export type DB = DatabaseSync;

export function openDB(path = ":memory:"): DB {
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner TEXT,
      agent_type TEXT,
      base_scopes TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS revocations (
      jti TEXT PRIMARY KEY,
      reason TEXT,
      revoked_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS grants (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      scopes TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      approved_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS elevation_requests (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      scopes TEXT NOT NULL,
      justification TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      decided_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT NOT NULL,
      agent_id TEXT,
      detail TEXT,
      ts TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  return db;
}
