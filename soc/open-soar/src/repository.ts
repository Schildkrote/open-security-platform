import type { Case } from "./cases.ts";
import * as audit from "./audit.ts";
import * as cases from "./cases.ts";
import type { DB } from "./db.ts";

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
