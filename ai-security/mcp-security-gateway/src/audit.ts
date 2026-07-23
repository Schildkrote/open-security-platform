import { createHash } from "node:crypto";
import type { DB } from "./db.ts";

export interface AuditInput {
  principal?: string;
  method: string;
  tool?: string;
  decision: string;
  reason?: string;
}

function hash(content: string, prev: string): string {
  return createHash("sha256").update(`${prev}|${content}`).digest("hex");
}

// canonical builds the exact object that is hashed, so write-time and
// verify-time serialization are identical (undefined normalized to null).
function canonical(input: AuditInput) {
  return {
    principal: input.principal ?? null,
    method: input.method,
    tool: input.tool ?? null,
    decision: input.decision,
    reason: input.reason ?? null,
  };
}

export function audit(db: DB, input: AuditInput): void {
  const prev = db.prepare(`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).get() as
    | { hash: string }
    | undefined;
  const prevHash = prev?.hash ?? "genesis";
  const c = canonical(input);
  db.prepare(
    `INSERT INTO audit_log (principal,method,tool,decision,reason,prev_hash,hash) VALUES (?,?,?,?,?,?,?)`,
  ).run(c.principal, c.method, c.tool, c.decision, c.reason, prevHash, hash(JSON.stringify(c), prevHash));
}

export function verifyChain(db: DB): { valid: boolean; brokenAt?: number } {
  let prevHash = "genesis";
  const rows = db
    .prepare(`SELECT * FROM audit_log ORDER BY seq`)
    .all() as Array<Record<string, unknown>>;
  for (const row of rows) {
    const c = {
      principal: row.principal ?? null,
      method: row.method,
      tool: row.tool ?? null,
      decision: row.decision,
      reason: row.reason ?? null,
    };
    if (row.prev_hash !== prevHash || row.hash !== hash(JSON.stringify(c), prevHash)) {
      return { valid: false, brokenAt: Number(row.seq) };
    }
    prevHash = row.hash as string;
  }
  return { valid: true };
}

export function recent(db: DB, limit = 100): Array<Record<string, unknown>> {
  return db.prepare(`SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?`).all(limit) as Array<
    Record<string, unknown>
  >;
}
