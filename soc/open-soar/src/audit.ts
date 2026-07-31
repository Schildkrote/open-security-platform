import { createHash } from "node:crypto";
import type { DB } from "./db.ts";

// auditHash and auditPayload are the single source of truth for the hash-chain
// algorithm. They are shared by every backend (SQLite here, the Postgres
// gateway in pg_gateway.ts) so a chain written by one backend verifies in
// another. The hashed content is the compact JSON of {actor, event, detail}
// chained over `${prev}|${content}`.

export function auditHash(content: string, prev: string): string {
  return createHash("sha256").update(`${prev}|${content}`).digest("hex");
}

export interface AuditPayload {
  actor: string | null;
  event: string;
  detail: string | null;
}

export function auditPayload(actor: string | null, event: string, detail?: unknown): AuditPayload {
  return { actor: actor ?? null, event, detail: detail === undefined ? null : JSON.stringify(detail) };
}

// AuditRecord is a stored audit-log row (seq assigned by the backend).
export interface AuditRecord {
  seq?: number;
  actor: string | null;
  event: string;
  detail: string | null;
  prev_hash: string;
  hash: string;
}

export function audit(db: DB, actor: string | null, event: string, detail?: unknown): void {
  const prev = db.prepare(`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).get() as
    | { hash: string }
    | undefined;
  const prevHash = prev?.hash ?? "genesis";
  const p = auditPayload(actor, event, detail);
  db.prepare(
    `INSERT INTO audit_log (actor,event,detail,prev_hash,hash) VALUES (?,?,?,?,?)`,
  ).run(p.actor, p.event, p.detail, prevHash, auditHash(JSON.stringify(p), prevHash));
}

export function verifyAuditRows(rows: AuditRecord[]): { valid: boolean; brokenAt?: number } {
  let prevHash = "genesis";
  for (const row of rows) {
    const p: AuditPayload = { actor: row.actor ?? null, event: row.event, detail: row.detail ?? null };
    if (row.prev_hash !== prevHash || row.hash !== auditHash(JSON.stringify(p), prevHash)) {
      return { valid: false, brokenAt: row.seq === undefined ? undefined : Number(row.seq) };
    }
    prevHash = row.hash;
  }
  return { valid: true };
}

export function verifyChain(db: DB): { valid: boolean; brokenAt?: number } {
  const rows = db.prepare(`SELECT * FROM audit_log ORDER BY seq`).all() as Array<Record<string, unknown>>;
  return verifyAuditRows(
    rows.map((row) => ({
      seq: Number(row.seq),
      actor: (row.actor as string | null) ?? null,
      event: row.event as string,
      detail: (row.detail as string | null) ?? null,
      prev_hash: row.prev_hash as string,
      hash: row.hash as string,
    })),
  );
}
