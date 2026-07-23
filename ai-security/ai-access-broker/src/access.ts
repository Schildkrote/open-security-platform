import type { DB } from "./db.ts";
import { randomUUID } from "node:crypto";
import { getApp } from "./catalog.ts";

export type RequestStatus = "pending" | "approved" | "denied";

export interface AccessRequest {
  id: string;
  user_id: string;
  app_id: string;
  status: RequestStatus;
  justification: string | null;
  decided_by: string | null;
  decided_at: string | null;
  created_at: string;
}

export function ensureUser(db: DB, email: string, role = "user"): string {
  const existing = db
    .prepare(`SELECT id FROM users WHERE email = ?`)
    .get(email) as { id: string } | undefined;
  if (existing) return existing.id;
  const id = randomUUID();
  db.prepare(`INSERT INTO users (id,email,role) VALUES (?,?,?)`).run(
    id,
    email,
    role,
  );
  return id;
}

export function requestAccess(
  db: DB,
  userId: string,
  appId: string,
  justification?: string,
): AccessRequest {
  const app = getApp(db, appId);
  if (!app) throw new Error("unknown app");
  // Apps that don't require approval are auto-approved.
  const status: RequestStatus = app.approval_required ? "pending" : "approved";
  const id = randomUUID();
  db.prepare(
    `INSERT INTO access_requests (id,user_id,app_id,status,justification)
     VALUES (?,?,?,?,?)`,
  ).run(id, userId, appId, status, justification ?? null);
  return getRequest(db, id)!;
}

export function decide(
  db: DB,
  requestId: string,
  approverId: string,
  approve: boolean,
): AccessRequest {
  const req = getRequest(db, requestId);
  if (!req) throw new Error("unknown request");
  if (req.status !== "pending") throw new Error("already decided");
  const status: RequestStatus = approve ? "approved" : "denied";
  db.prepare(
    `UPDATE access_requests SET status=?, decided_by=?, decided_at=datetime('now') WHERE id=?`,
  ).run(status, approverId, requestId);
  return getRequest(db, requestId)!;
}

export function hasAccess(db: DB, userId: string, appId: string): boolean {
  const row = db
    .prepare(
      `SELECT 1 FROM access_requests WHERE user_id=? AND app_id=? AND status='approved' LIMIT 1`,
    )
    .get(userId, appId);
  return !!row;
}

export function getRequest(db: DB, id: string): AccessRequest | undefined {
  return db
    .prepare(`SELECT * FROM access_requests WHERE id = ?`)
    .get(id) as AccessRequest | undefined;
}

export function listRequests(db: DB, status?: RequestStatus): AccessRequest[] {
  if (status) {
    return db
      .prepare(`SELECT * FROM access_requests WHERE status=? ORDER BY created_at`)
      .all(status) as AccessRequest[];
  }
  return db
    .prepare(`SELECT * FROM access_requests ORDER BY created_at`)
    .all() as AccessRequest[];
}
