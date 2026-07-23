// SOC connectors for open-soar (Phase 3): Wazuh (alert ingest), OpenCTI
// (threat-intel enrichment), Cortex (response actions). Each ships a Mock
// (offline dev/tests) and a Real client (public API, user credentials), per the
// build-vs-integrate plan. Zero runtime dependencies (uses global fetch).
//
// The Real clients implement representative request construction for each API;
// exact endpoints/payloads should be confirmed against the target version at
// deploy time (noted in the plan's "confirm-at-integration" caveat).

import type { NodeFn } from "./nodes.ts";

export interface Alert {
  id: string;
  rule: string;
  severity: string;
  src?: string;
  [key: string]: unknown;
}

export interface Intel {
  reputation: string;
  [key: string]: unknown;
}

export interface ActionResult {
  action: string;
  status: string;
  [key: string]: unknown;
}

export interface AlertSource {
  fetchAlerts(): Promise<Alert[]>;
}

export interface Enricher {
  enrichIp(ip: string): Promise<Intel>;
  enrichDomain(domain: string): Promise<Intel>;
}

export interface Responder {
  blockIp(ip: string): Promise<ActionResult>;
  disableUser(user: string): Promise<ActionResult>;
}

// --- Mock implementations (offline default) -------------------------------

export class MockWazuh implements AlertSource {
  async fetchAlerts(): Promise<Alert[]> {
    return [
      { id: "w-1", rule: "ssh brute force", severity: "high", src: "1.2.3.4" },
      { id: "w-2", rule: "malware callback", severity: "critical", src: "5.6.7.8" },
    ];
  }
}

export class MockOpenCTI implements Enricher {
  async enrichIp(ip: string): Promise<Intel> {
    return { ip, geo: "RU", asn: "AS123", reputation: ip === "8.8.8.8" ? "clean" : "malicious" };
  }
  async enrichDomain(domain: string): Promise<Intel> {
    return { domain, reputation: "suspicious", age_days: 3 };
  }
}

export class MockCortex implements Responder {
  actions: ActionResult[] = [];
  async blockIp(ip: string): Promise<ActionResult> {
    const r = { action: "block_ip", ip, status: "blocked" };
    this.actions.push(r);
    return r;
  }
  async disableUser(user: string): Promise<ActionResult> {
    const r = { action: "disable_user", user, status: "disabled" };
    this.actions.push(r);
    return r;
  }
}

// --- Real clients ----------------------------------------------------------

function basic(user: string, password: string): string {
  return `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`;
}

// Wazuh ingests SIEM alerts via the Wazuh REST API.
export class Wazuh implements AlertSource {
  private baseUrl: string;
  private auth: string;

  constructor(baseUrl: string, user: string, password: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.auth = basic(user, password);
  }

  async fetchAlerts(): Promise<Alert[]> {
    const resp = await fetch(`${this.baseUrl}/alerts?limit=50&sort=-timestamp`, {
      headers: { authorization: this.auth },
    });
    if (!resp.ok) throw new Error(`wazuh: fetch alerts failed (${resp.status})`);
    const data = (await resp.json()) as {
      data?: { items?: Array<{ id: string; rule?: { description?: string; level?: number }; data?: { srcip?: string } }> };
    };
    return (data.data?.items ?? []).map((item) => ({
      id: item.id,
      rule: item.rule?.description ?? "unknown",
      severity: (item.rule?.level ?? 0) >= 12 ? "critical" : (item.rule?.level ?? 0) >= 7 ? "high" : "medium",
      src: item.data?.srcip,
    }));
  }
}

// OpenCTI enriches observables via its GraphQL API.
export class OpenCTI implements Enricher {
  private baseUrl: string;
  private token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
  }

  private async query(q: string): Promise<unknown> {
    const resp = await fetch(`${this.baseUrl}/graphql`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
      body: JSON.stringify({ query: q }),
    });
    if (!resp.ok) throw new Error(`opencti: query failed (${resp.status})`);
    return resp.json();
  }

  async enrichIp(ip: string): Promise<Intel> {
    await this.query(`{ ipv4Addr(value: "${ip}") { value } }`);
    return { ip, reputation: "unknown", source: "opencti" };
  }

  async enrichDomain(domain: string): Promise<Intel> {
    await this.query(`{ domainName(value: "${domain}") { value } }`);
    return { domain, reputation: "unknown", source: "opencti" };
  }
}

// Cortex runs analyzers/responders (e.g. block an IP, disable a user).
export class Cortex implements Responder {
  private baseUrl: string;
  private token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
  }

  private async run(responder: string, dataType: string, data: unknown): Promise<ActionResult> {
    const resp = await fetch(`${this.baseUrl}/api/connector/run/${responder}/${dataType}`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
      body: JSON.stringify({ data }),
    });
    if (!resp.ok) throw new Error(`cortex: responder ${responder} failed (${resp.status})`);
    return { action: responder, status: "executed" };
  }

  async blockIp(ip: string): Promise<ActionResult> {
    return this.run("block_ip", "ip", ip);
  }
  async disableUser(user: string): Promise<ActionResult> {
    return this.run("disable_user", "username", user);
  }
}

// registerConnectorNodes wires connector-backed nodes into the playbook engine
// (opt-in; the built-in mock nodes remain the offline default).
export function registerConnectorNodes(
  register: (type: string, fn: NodeFn) => void,
  deps: { alertSource?: AlertSource; enricher?: Enricher; responder?: Responder },
): void {
  if (deps.alertSource) {
    const src = deps.alertSource;
    register("wazuh.fetch", async () => src.fetchAlerts());
  }
  if (deps.enricher) {
    const en = deps.enricher;
    register("opencti.enrich.ip", async (_ctx, params) => en.enrichIp(String(params.ip)));
    register("opencti.enrich.domain", async (_ctx, params) => en.enrichDomain(String(params.domain)));
  }
  if (deps.responder) {
    const re = deps.responder;
    register("cortex.block_ip", async (_ctx, params) => re.blockIp(String(params.ip)));
    register("cortex.disable_user", async (_ctx, params) => re.disableUser(String(params.user)));
  }
}
