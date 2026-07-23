import type { DB } from "./db.ts";

export interface Agent {
  id: string;
  name: string;
  owner: string | null;
  agent_type: string | null;
  base_scopes: string[];
  status: string;
}

function rowToAgent(row: Record<string, unknown>): Agent {
  return {
    id: row.id as string,
    name: row.name as string,
    owner: row.owner as string | null,
    agent_type: row.agent_type as string | null,
    base_scopes: JSON.parse((row.base_scopes as string) || "[]"),
    status: row.status as string,
  };
}

export function registerAgent(
  db: DB,
  input: { id: string; name: string; owner?: string; agent_type?: string; base_scopes?: string[] },
): Agent {
  db.prepare(
    `INSERT INTO agents (id,name,owner,agent_type,base_scopes) VALUES (?,?,?,?,?)`,
  ).run(
    input.id,
    input.name,
    input.owner ?? null,
    input.agent_type ?? null,
    JSON.stringify(input.base_scopes ?? []),
  );
  return getAgent(db, input.id)!;
}

export function getAgent(db: DB, id: string): Agent | undefined {
  const row = db.prepare(`SELECT * FROM agents WHERE id=?`).get(id) as
    | Record<string, unknown>
    | undefined;
  return row ? rowToAgent(row) : undefined;
}

export function listAgents(db: DB): Agent[] {
  return (db.prepare(`SELECT * FROM agents ORDER BY name`).all() as Record<string, unknown>[]).map(
    rowToAgent,
  );
}

export function setStatus(db: DB, id: string, status: string): boolean {
  const res = db.prepare(`UPDATE agents SET status=? WHERE id=?`).run(status, id);
  return Number(res.changes) > 0;
}
