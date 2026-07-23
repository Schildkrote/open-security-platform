import type { DB } from "./db.ts";

export function audit(db: DB, event: string, agentId?: string, detail?: unknown): void {
  db.prepare(`INSERT INTO audit_log (event, agent_id, detail) VALUES (?,?,?)`).run(
    event,
    agentId ?? null,
    detail === undefined ? null : JSON.stringify(detail),
  );
}

export function recentAudit(db: DB, limit = 100): Array<Record<string, unknown>> {
  return db
    .prepare(`SELECT * FROM audit_log ORDER BY id DESC LIMIT ?`)
    .all(limit) as Array<Record<string, unknown>>;
}
