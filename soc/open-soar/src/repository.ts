import { randomUUID } from "node:crypto";
import type { Case } from "./cases.ts";
import * as audit from "./audit.ts";
import * as cases from "./cases.ts";
import type { DB } from "./db.ts";
import { HttpPgGateway, type CaseRow, type PgGateway } from "./pg_gateway.ts";

// Repository interfaces are the platform persistence contract (Phase 1). Each
// component exposes its storage behind an interface so the backend can be
// swapped (SQLite today -> Postgres tomorrow) without touching callers. See
// platform/PERSISTENCE.md for the cross-component convention.

export interface CaseRepository {
  create(title: string, opts?: { severity?: string; assignee?: string; alert?: unknown }): Case;
  get(id: string): Case | undefined;
  list(): Case[];
  addAlert(id: string, alert: unknown): Case;
  addEvidence(id: string, evidence: unknown): Case;
  setStatus(id: string, status: string, actor?: string): Case;
  assign(id: string, assignee: string): Case;
  setClassification(id: string, classification: string, severity?: string): Case;
}

export interface AuditRepository {
  verify(): { valid: boolean; brokenAt?: number };
}

// SqliteCaseRepository is the SQLite backend (node:sqlite) for CaseRepository.
export class SqliteCaseRepository implements CaseRepository {
  private db: DB;

  constructor(db: DB) {
    this.db = db;
  }

  create(title: string, opts?: { severity?: string; assignee?: string; alert?: unknown }): Case {
    return cases.createCase(this.db, title, opts);
  }

  get(id: string): Case | undefined {
    return cases.getCase(this.db, id);
  }

  list(): Case[] {
    return cases.listCases(this.db);
  }

  addAlert(id: string, alert: unknown): Case {
    return cases.addAlert(this.db, id, alert);
  }

  addEvidence(id: string, evidence: unknown): Case {
    return cases.addEvidence(this.db, id, evidence);
  }

  setStatus(id: string, status: string, actor?: string): Case {
    return cases.setStatus(this.db, id, status, actor);
  }

  assign(id: string, assignee: string): Case {
    return cases.assign(this.db, id, assignee);
  }

  setClassification(id: string, classification: string, severity?: string): Case {
    return cases.setClassification(this.db, id, classification, severity);
  }
}

// SqliteAuditRepository exposes the tamper-evident audit chain verification.
export class SqliteAuditRepository implements AuditRepository {
  private db: DB;

  constructor(db: DB) {
    this.db = db;
  }

  verify(): { valid: boolean; brokenAt?: number } {
    return audit.verifyChain(this.db);
  }
}

// --- Postgres backend (async) ---------------------------------------------
//
// The SQLite repositories above are synchronous because node:sqlite is sync.
// Postgres is reached over HTTP (pg_gateway.ts), which is inherently async, so
// the Postgres backend implements async mirror interfaces. The row mapping
// (cases.rowToCase) and the hash-chain algorithm (audit.*) are shared, so a
// chain written by either backend verifies in the other. See
// platform/PERSISTENCE.md.

export interface AsyncCaseRepository {
  create(title: string, opts?: { severity?: string; assignee?: string; alert?: unknown }): Promise<Case>;
  get(id: string): Promise<Case | undefined>;
  list(): Promise<Case[]>;
  addAlert(id: string, alert: unknown): Promise<Case>;
  addEvidence(id: string, evidence: unknown): Promise<Case>;
  setStatus(id: string, status: string, actor?: string): Promise<Case>;
  assign(id: string, assignee: string): Promise<Case>;
  setClassification(id: string, classification: string, severity?: string): Promise<Case>;
}

export interface AsyncAuditRepository {
  verify(): Promise<{ valid: boolean; brokenAt?: number }>;
}

export class PostgresCaseRepository implements AsyncCaseRepository {
  private gw: PgGateway;

  constructor(gw: PgGateway) {
    this.gw = gw;
  }

  private async appendAudit(actor: string | null, event: string, detail?: unknown): Promise<void> {
    const last = await this.gw.lastAudit();
    const prevHash = last?.hash ?? "genesis";
    const p = audit.auditPayload(actor, event, detail);
    await this.gw.insertAudit({
      actor: p.actor,
      event: p.event,
      detail: p.detail,
      prev_hash: prevHash,
      hash: audit.auditHash(JSON.stringify(p), prevHash),
    });
  }

  async create(
    title: string,
    opts: { severity?: string; assignee?: string; alert?: unknown } = {},
  ): Promise<Case> {
    const id = randomUUID();
    const timeline = [{ at: new Date().toISOString(), event: "case_created", by: opts.assignee ?? "system" }];
    const alerts: unknown[] = [];
    if (opts.alert) alerts.push(opts.alert);
    const row = await this.gw.insertCase({
      id,
      title,
      severity: opts.severity ?? "medium",
      status: "open",
      assignee: opts.assignee ?? null,
      classification: null,
      alerts: JSON.stringify(alerts),
      evidence: "[]",
      timeline: JSON.stringify(timeline),
    });
    await this.appendAudit(opts.assignee ?? "system", "case_created", { id, title });
    return cases.rowToCase(row);
  }

  async get(id: string): Promise<Case | undefined> {
    const row = await this.gw.getCase(id);
    return row ? cases.rowToCase(row) : undefined;
  }

  async list(): Promise<Case[]> {
    return (await this.gw.listCases()).map(cases.rowToCase);
  }

  async addAlert(id: string, alert: unknown): Promise<Case> {
    const c = await this.get(id);
    if (!c) throw new Error("unknown case");
    c.alerts.push(alert);
    await this.gw.updateCase(id, { alerts: JSON.stringify(c.alerts) });
    await this.appendAudit("system", "alert_added", { id });
    return (await this.get(id))!;
  }

  async addEvidence(id: string, evidence: unknown): Promise<Case> {
    const c = await this.get(id);
    if (!c) throw new Error("unknown case");
    c.evidence.push({ ...({} as object), ...(evidence as object), at: new Date().toISOString() });
    await this.gw.updateCase(id, { evidence: JSON.stringify(c.evidence) });
    await this.appendAudit("system", "evidence_added", { id });
    return (await this.get(id))!;
  }

  async setStatus(id: string, status: string, actor = "system"): Promise<Case> {
    const c = await this.get(id);
    if (!c) throw new Error("unknown case");
    c.timeline.push({ at: new Date().toISOString(), event: `status:${status}`, by: actor });
    await this.gw.updateCase(id, { status, timeline: JSON.stringify(c.timeline) });
    await this.appendAudit(actor, "case_status", { id, status });
    return (await this.get(id))!;
  }

  async assign(id: string, assignee: string): Promise<Case> {
    const c = await this.get(id);
    if (!c) throw new Error("unknown case");
    c.timeline.push({ at: new Date().toISOString(), event: `assigned:${assignee}`, by: "system" });
    await this.gw.updateCase(id, { assignee, timeline: JSON.stringify(c.timeline) });
    await this.appendAudit("system", "case_assigned", { id, assignee });
    return (await this.get(id))!;
  }

  async setClassification(id: string, classification: string, severity?: string): Promise<Case> {
    const patch: Partial<CaseRow> = severity ? { classification, severity } : { classification };
    await this.gw.updateCase(id, patch);
    return (await this.get(id))!;
  }
}

export class PostgresAuditRepository implements AsyncAuditRepository {
  private gw: PgGateway;

  constructor(gw: PgGateway) {
    this.gw = gw;
  }

  async verify(): Promise<{ valid: boolean; brokenAt?: number }> {
    return audit.verifyAuditRows(await this.gw.listAudit());
  }
}

// Persistence backend selection (Phase 1). The offline default is SQLite;
// setting OSP_SOAR_GATEWAY (optionally OSP_SOAR_GATEWAY_TOKEN) selects the
// Postgres gateway backend. Wiring this into server.ts — which currently serves
// the sync SQLite repositories — is the follow-up "fully wire" step.
export type PersistenceBackend = { kind: "sqlite" } | { kind: "postgres"; gateway: PgGateway };

export function persistenceFromEnv(env: Record<string, string | undefined> = process.env): PersistenceBackend {
  const url = env.OSP_SOAR_GATEWAY;
  if (url) return { kind: "postgres", gateway: new HttpPgGateway(url, { token: env.OSP_SOAR_GATEWAY_TOKEN }) };
  return { kind: "sqlite" };
}
