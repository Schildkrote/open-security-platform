import { createHash } from "node:crypto";
import type { DB } from "./db.ts";

function hash(content: string, prev: string): string {
  return createHash("sha256").update(`${prev}|${content}`).digest("hex");
}

export function audit(db: DB, actor: string | null, event: string, detail?: unknown): void {
  const prev = db.prepare(`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).get() as
    | { hash: string }
    | undefined;
  const prevHash = prev?.hash ?? "genesis";
  const c = { actor: actor ?? null, event, detail: detail === undefined ? null : JSON.stringify(detail) };
  db.prepare(
    `INSERT INTO audit_log (actor,event,detail,prev_hash,hash) VALUES (?,?,?,?,?)`,
  ).run(c.actor, c.event, c.detail, prevHash, hash(JSON.stringify(c), prevHash));
}

export function verifyChain(db: DB): { valid: boolean; brokenAt?: number } {
  let prevHash = "genesis";
  const rows = db.prepare(`SELECT * FROM audit_log ORDER BY seq`).all() as Array<Record<string, unknown>>;
  for (const row of rows) {
    const c = { actor: row.actor ?? null, event: row.event, detail: row.detail ?? null };
    if (row.prev_hash !== prevHash || row.hash !== hash(JSON.stringify(c), prevHash)) {
      return { valid: false, brokenAt: Number(row.seq) };
    }
    prevHash = row.hash as string;
  }
  return { valid: true };
}
