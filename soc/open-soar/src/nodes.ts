import type { TriageFn, TriageInput } from "./triage.ts";

export interface StepContext {
  input: Record<string, unknown>;
  outputs: Record<string, unknown>; // stepId -> result
  vars: Record<string, unknown>;
  caseId?: string;
  triage: TriageFn;
}

export type NodeFn = (ctx: StepContext, params: Record<string, unknown>) => Promise<unknown> | unknown;

function pick(ctx: StepContext, params: Record<string, unknown>, key: string): unknown {
  return (params[key] as unknown) ?? ctx.input[key];
}

// Mock enrichment data (offline). Real integrations would call threat-intel APIs.
const IP_INTEL: Record<string, unknown> = {
  "1.2.3.4": { geo: "RU", asn: "AS123", reputation: "malicious" },
  "8.8.8.8": { geo: "US", asn: "AS15169", reputation: "clean" },
};

export const NODES: Record<string, NodeFn> = {
  "enrich.ip": (ctx, params) => {
    const ip = pick(ctx, params, "ip") as string;
    const intel = IP_INTEL[ip] ?? { geo: "unknown", asn: "unknown", reputation: "unknown" };
    return { ip, ...intel };
  },

  "enrich.domain": (_ctx, params) => {
    const domain = params.domain as string;
    return { domain, age_days: 3, registrar: "shady-registrar", reputation: "suspicious" };
  },

  "enrich.user": (_ctx, params) => {
    const user = params.user as string;
    return { user, risk_score: 0.7, recent_failed_logins: 12, department: "finance" };
  },

  "action.block_ip": (ctx, params) => {
    const ip = (pick(ctx, params, "ip") as string) ?? (ctx.outputs[params.from as string] as any)?.ip;
    return { action: "block_ip", ip, status: "blocked" };
  },

  "action.disable_user": (_ctx, params) => {
    return { action: "disable_user", user: params.user, status: "disabled" };
  },

  "action.create_ticket": (ctx, params) => {
    return { action: "create_ticket", ticket: `TICKET-${Math.floor(Math.random() * 1e6)}`, summary: params.summary ?? ctx.input.title };
  },

  "transform.set": (_ctx, params) => params.value,

  "ai.triage": (ctx, params) => {
    const input: TriageInput = (params.input as TriageInput) ?? (ctx.input as TriageInput);
    return ctx.triage(input);
  },
};

export function registerNode(type: string, fn: NodeFn): void {
  NODES[type] = fn;
}
