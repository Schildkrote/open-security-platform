import { DatabaseSync } from "node:sqlite";

export type DB = DatabaseSync;

let _db: DB | null = null;

export function getDB(path = ":memory:"): DB {
  if (_db) return _db;
  _db = new DatabaseSync(path);
  migrate(_db);
  return _db;
}

export function openDB(path = ":memory:"): DB {
  const db = new DatabaseSync(path);
  migrate(db);
  return db;
}

function migrate(db: DB): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS apps (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT,
      vendor TEXT,
      risk TEXT NOT NULL DEFAULT 'medium',
      data_residency TEXT,
      sso_enabled INTEGER NOT NULL DEFAULT 1,
      approval_required INTEGER NOT NULL DEFAULT 1,
      upstream_url TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    );
    CREATE TABLE IF NOT EXISTS access_requests (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      app_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      justification TEXT,
      decided_by TEXT,
      decided_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS usage_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      app_id TEXT,
      bytes_in INTEGER,
      bytes_out INTEGER,
      redactions INTEGER NOT NULL DEFAULT 0,
      cost_usd REAL NOT NULL DEFAULT 0,
      ts TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}
