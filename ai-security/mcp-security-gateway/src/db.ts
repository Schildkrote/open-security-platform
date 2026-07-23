import { DatabaseSync } from "node:sqlite";

export type DB = DatabaseSync;

export function openDB(path = ":memory:"): DB {
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE IF NOT EXISTS servers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      endpoint TEXT,
      risk TEXT NOT NULL DEFAULT 'medium',
      allowed INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS tools (
      name TEXT PRIMARY KEY,
      server_id TEXT NOT NULL,
      description TEXT,
      risk TEXT NOT NULL DEFAULT 'medium',
      allowed INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS secrets (
      name TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL DEFAULT (datetime('now')),
      principal TEXT,
      method TEXT,
      tool TEXT,
      decision TEXT,
      reason TEXT,
      prev_hash TEXT,
      hash TEXT
    );
  `);
  return db;
}
