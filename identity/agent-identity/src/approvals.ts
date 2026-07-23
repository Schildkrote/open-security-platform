import type { DB } from "./db.ts";
import { grantJIT } from "./tokens.ts";
import { audit } from "./audit.ts";

export interface ElevationRequest {
  id: string;
  agent_id: string;
  scopes: string[];
  justification: string | null;
  status: string;
  decided_by: string | null;
}

function rowToReq(row: Record<string, unknown>): ElevationRequest {
  return {
    id: row.id as string,
    agent_id: row.agent_id as string,
    scopes: JSON.parse((row.scopes as string) || "[]"),
    justification: row.justification as string | null,
    status: row.status as string,
    decided_by: row.decided_by as string | null,
  };
}

export function requestElevation(
  db: DB,
  agentId: string,
  scopes: string[],
  justification?: string,
): ElevationRequest {
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO elevation_requests (id,agent_id,scopes,justification) VALUES (?,?,?,?)`,
  ).run(id, agentId, JSON.stringify(scopes), justification ?? null);
  audit(db, "elevation_requested", agentId, { scopes });
  return getRequest(db, id)!;
}

export function approveElevation(
  db: DB,
  requestId: string,
  approver: string,
  ttlSeconds = 3600,
): { request: ElevationRequest; grant: { id: string; expires_at: string } } {
  const req = getRequest(db, requestId);
  if (!req) throw new Error("unknown request");
  if (req.status !== "pending") throw new Error("already decided");
  db.prepare(
    `UPDATE elevation_requests SET status='approved', decided_by=? WHERE id=?`,
  ).run(approver, requestId);
  const grant = grantJIT(db, req.agent_id, req.scopes, ttlSeconds, approver);
  audit(db, "elevation_approved", req.agent_id, { request: requestId });
  return { request: getRequest(db, requestId)!, grant };
}

export function denyElevation(db: DB, requestId: string, approver: string): ElevationRequest {
  const req = getRequest(db, requestId);
  if (!req) throw new Error("unknown request");
  db.prepare(
    `UPDATE elevation_requests SET status='denied', decided_by=? WHERE id=?`,
  ).run(approver, requestId);
  audit(db, "elevation_denied", req.agent_id, { request: requestId });
  return getRequest(db, requestId)!;
}

export function getRequest(db: DB, id: string): ElevationRequest | undefined {
  const row = db.prepare(`SELECT * FROM elevation_requests WHERE id=?`).get(id) as
    | Record<string, unknown>
    | undefined;
  return row ? rowToReq(row) : undefined;
}

export function listRequests(db: DB): ElevationRequest[] {
  return (
    db.prepare(`SELECT * FROM elevation_requests ORDER BY created_at`).all() as Record<
      string,
      unknown
    >[]
  ).map(rowToReq);
}
