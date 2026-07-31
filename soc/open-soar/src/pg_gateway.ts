// Postgres gateway client for open-soar (Phase 1 persistence backend).
//
// open-soar persists behind the CaseRepository/AuditRepository interfaces (see
// platform/PERSISTENCE.md). The offline default is SqliteCaseRepository
// (node:sqlite). This module is the production backend: a zero-runtime-dep HTTP
// client to a PostgREST-style REST gateway in front of Postgres. It uses only
// global fetch (no npm deps), consistent with the repo's zero-dep rule and the
// Mock+Real connector pattern in connectors.ts. The Postgres schema lives in
// migrations/0001_init.sql.
//
// node:sqlite is synchronous, so the SQLite repositories are sync; Postgres
// access over HTTP is inherently async, so the repositories built on this
// gateway implement the async mirror interfaces in repository.ts.

import type { AuditRecord } from "./audit.ts";

// CaseRow is the raw stored row: structured fields are TEXT JSON, matching the
// SQLite row shape so cases.rowToCase maps both backends identically. Declared
// as a type alias (not interface) so it is assignable to Record<string, unknown>.
export type CaseRow = {
  id: string;
  title: string;
  severity: string;
  status: string;
  assignee: string | null;
  classification: string | null;
  alerts: string;
  evidence: string;
  timeline: string;
  created_at: string;
};

// NewCaseRow omits created_at: the database assigns it from the column default
// and returns it via Prefer: return=representation.
export type NewCaseRow = Omit<CaseRow, "created_at">;

export interface PgGateway {
  listCases(): Promise<CaseRow[]>;
  getCase(id: string): Promise<CaseRow | undefined>;
  insertCase(row: NewCaseRow): Promise<CaseRow>;
  updateCase(id: string, patch: Partial<CaseRow>): Promise<void>;
  lastAudit(): Promise<AuditRecord | undefined>;
  listAudit(): Promise<AuditRecord[]>;
  insertAudit(row: AuditRecord): Promise<void>;
}

// HttpPgGateway speaks PostgREST conventions: row filtering via `?col=eq.val`,
// ordering via `?order=col.asc`, and `Prefer: return=representation` to read
// back written rows.
export class HttpPgGateway implements PgGateway {
  private baseUrl: string;
  private auth?: string;

  constructor(baseUrl: string, opts: { token?: string } = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.auth = opts.token ? `Bearer ${opts.token}` : undefined;
  }

  private headers(withBody: boolean): Record<string, string> {
    const h: Record<string, string> = { accept: "application/json" };
    if (this.auth) h.authorization = this.auth;
    if (withBody) {
      h["content-type"] = "application/json";
      h.prefer = "return=representation";
    }
    return h;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(body !== undefined),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!resp.ok) throw new Error(`pg-gateway: ${method} ${path} failed (${resp.status})`);
    const text = await resp.text();
    return (text ? JSON.parse(text) : []) as T;
  }

  async listCases(): Promise<CaseRow[]> {
    return this.request<CaseRow[]>("GET", "/cases?order=created_at.asc");
  }

  async getCase(id: string): Promise<CaseRow | undefined> {
    const rows = await this.request<CaseRow[]>("GET", `/cases?id=eq.${encodeURIComponent(id)}&limit=1`);
    return rows[0];
  }

  async insertCase(row: NewCaseRow): Promise<CaseRow> {
    const rows = await this.request<CaseRow[]>("POST", "/cases", row);
    return rows[0] ?? { ...row, created_at: new Date().toISOString() };
  }

  async updateCase(id: string, patch: Partial<CaseRow>): Promise<void> {
    await this.request<CaseRow[]>("PATCH", `/cases?id=eq.${encodeURIComponent(id)}`, patch);
  }

  async lastAudit(): Promise<AuditRecord | undefined> {
    const rows = await this.request<AuditRecord[]>("GET", "/audit_log?order=seq.desc&limit=1");
    return rows[0];
  }

  async listAudit(): Promise<AuditRecord[]> {
    return this.request<AuditRecord[]>("GET", "/audit_log?order=seq.asc");
  }

  async insertAudit(row: AuditRecord): Promise<void> {
    await this.request<AuditRecord[]>("POST", "/audit_log", row);
  }
}
