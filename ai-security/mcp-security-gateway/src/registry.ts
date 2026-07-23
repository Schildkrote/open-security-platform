import type { DB } from "./db.ts";

export interface McpServer {
  id: string;
  name: string;
  endpoint: string | null;
  risk: string;
  allowed: number;
}

export interface McpTool {
  name: string;
  server_id: string;
  description: string | null;
  risk: string;
  allowed: number;
}

export function registerServer(
  db: DB,
  s: { id: string; name: string; endpoint?: string; risk?: string; allowed?: boolean },
): McpServer {
  db.prepare(
    `INSERT OR REPLACE INTO servers (id,name,endpoint,risk,allowed) VALUES (?,?,?,?,?)`,
  ).run(s.id, s.name, s.endpoint ?? null, s.risk ?? "medium", s.allowed === false ? 0 : 1);
  return getServer(db, s.id)!;
}

export function getServer(db: DB, id: string): McpServer | undefined {
  return db.prepare(`SELECT * FROM servers WHERE id=?`).get(id) as McpServer | undefined;
}

export function registerTool(
  db: DB,
  t: { name: string; server_id: string; description?: string; risk?: string; allowed?: boolean },
): McpTool {
  db.prepare(
    `INSERT OR REPLACE INTO tools (name,server_id,description,risk,allowed) VALUES (?,?,?,?,?)`,
  ).run(t.name, t.server_id, t.description ?? null, t.risk ?? "medium", t.allowed === false ? 0 : 1);
  return getTool(db, t.name)!;
}

export function getTool(db: DB, name: string): McpTool | undefined {
  return db.prepare(`SELECT * FROM tools WHERE name=?`).get(name) as McpTool | undefined;
}

export function listTools(db: DB, onlyAllowed = false): McpTool[] {
  const sql = onlyAllowed
    ? `SELECT t.* FROM tools t JOIN servers s ON s.id=t.server_id WHERE t.allowed=1 AND s.allowed=1 ORDER BY t.name`
    : `SELECT * FROM tools ORDER BY name`;
  return db.prepare(sql).all() as McpTool[];
}

export function setToolAllowed(db: DB, name: string, allowed: boolean): boolean {
  const res = db.prepare(`UPDATE tools SET allowed=? WHERE name=?`).run(allowed ? 1 : 0, name);
  return Number(res.changes) > 0;
}
