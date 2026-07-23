import type { DB } from "./db.ts";
import { randomUUID } from "node:crypto";
import { audit } from "./audit.ts";

export interface Case {
  id: string;
  title: string;
  severity: string;
  status: string;
  assignee: string | null;
  classification: string | null;
  alerts: unknown[];
  evidence: unknown[];
  timeline: unknown[];
  created_at: string;
}

function rowToCase(row: Record<string, unknown>): Case {
  return {
    id: row.id as string,
    title: row.title as string,
    severity: row.severity as string,
    status: row.status as string,
    assignee: row.assignee as string | null,
    classification: row.classification as string | null,
    alerts: JSON.parse((row.alerts as string) || "[]"),
    evidence: JSON.parse((row.evidence as string) || "[]"),
    timeline: JSON.parse((row.timeline as string) || "[]"),
    created_at: row.created_at as string,
  };
}

function push(db: DB, id: string, column: "alerts" | "evidence" | "timeline", item: unknown): void {
  const c = getCase(db, id);
  if (!c) throw new Error("unknown case");
  const arr = c[column] as unknown[];
  arr.push(item);
  db.prepare(`UPDATE cases SET ${column}=? WHERE id=?`).run(JSON.stringify(arr), id);
}

export function createCase(
  db: DB,
  title: string,
  opts: { severity?: string; assignee?: string; alert?: unknown } = {},
): Case {
  const id = randomUUID();
  const timeline = [{ at: new Date().toISOString(), event: "case_created", by: opts.assignee ?? "system" }];
  db.prepare(
    `INSERT INTO cases (id,title,severity,status,assignee,timeline) VALUES (?,?,?,?,?,?)`,
  ).run(id, title, opts.severity ?? "medium", "open", opts.assignee ?? null, JSON.stringify(timeline));
  if (opts.alert) push(db, id, "alerts", opts.alert);
  audit(db, opts.assignee ?? "system", "case_created", { id, title });
  return getCase(db, id)!;
}

export function getCase(db: DB, id: string): Case | undefined {
  const row = db.prepare(`SELECT * FROM cases WHERE id=?`).get(id) as Record<string, unknown> | undefined;
  return row ? rowToCase(row) : undefined;
}

export function listCases(db: DB): Case[] {
  return (db.prepare(`SELECT * FROM cases ORDER BY created_at`).all() as Record<string, unknown>[]).map(rowToCase);
}

export function addAlert(db: DB, id: string, alert: unknown): Case {
  push(db, id, "alerts", alert);
  audit(db, "system", "alert_added", { id });
  return getCase(db, id)!;
}

export function addEvidence(db: DB, id: string, evidence: unknown): Case {
  push(db, id, "evidence", { ...({} as object), ...(evidence as object), at: new Date().toISOString() });
  audit(db, "system", "evidence_added", { id });
  return getCase(db, id)!;
}

export function setStatus(db: DB, id: string, status: string, actor = "system"): Case {
  const c = getCase(db, id);
  if (!c) throw new Error("unknown case");
  db.prepare(`UPDATE cases SET status=? WHERE id=?`).run(status, id);
  push(db, id, "timeline", { at: new Date().toISOString(), event: `status:${status}`, by: actor });
  audit(db, actor, "case_status", { id, status });
  return getCase(db, id)!;
}

export function assign(db: DB, id: string, assignee: string): Case {
  db.prepare(`UPDATE cases SET assignee=? WHERE id=?`).run(assignee, id);
  push(db, id, "timeline", { at: new Date().toISOString(), event: `assigned:${assignee}`, by: "system" });
  audit(db, "system", "case_assigned", { id, assignee });
  return getCase(db, id)!;
}

export function setClassification(db: DB, id: string, classification: string, severity?: string): Case {
  if (severity) db.prepare(`UPDATE cases SET classification=?, severity=? WHERE id=?`).run(classification, severity, id);
  else db.prepare(`UPDATE cases SET classification=? WHERE id=?`).run(classification, id);
  return getCase(db, id)!;
}
