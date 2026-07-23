import type { DB } from "./db.ts";
import { hasAccess } from "./access.ts";
import { residencyAllowed, type App } from "./catalog.ts";
import { redact } from "./redact.ts";

export type UpstreamFetch = (
  url: string,
  body: string,
) => Promise<{ status: number; body: string }>;

export interface BrokerContext {
  db: DB;
  userId: string;
  app: App;
  allowedRegions: string[];
  upstreamFetch: UpstreamFetch;
  costPerKB?: number;
}

export interface BrokerResult {
  status: number;
  body: string;
  redactions: number;
  reason?: string;
}

// brokerRequest is the core access-broker decision + DLP pipeline for one
// proxied call to an AI app.
export async function brokerRequest(
  ctx: BrokerContext,
  body: string,
): Promise<BrokerResult> {
  const { db, userId, app } = ctx;

  if (!hasAccess(db, userId, app.id)) {
    return { status: 403, body: JSON.stringify({ error: "access not approved" }), redactions: 0, reason: "no_access" };
  }
  if (!residencyAllowed(app, ctx.allowedRegions)) {
    return { status: 403, body: JSON.stringify({ error: "data residency violation", residency: app.data_residency }), redactions: 0, reason: "residency" };
  }

  const { output, findings } = redact(body);
  const redactions = findings.reduce((n, f) => n + f.count, 0);

  const url = app.upstream_url ?? "mock://app";
  const upstream = await ctx.upstreamFetch(url, output);

  const bytesIn = Buffer.byteLength(body);
  const bytesOut = Buffer.byteLength(upstream.body);
  const cost = ((bytesIn + bytesOut) / 1024) * (ctx.costPerKB ?? 0.001);
  db.prepare(
    `INSERT INTO usage_log (user_id,app_id,bytes_in,bytes_out,redactions,cost_usd) VALUES (?,?,?,?,?,?)`,
  ).run(userId, app.id, bytesIn, bytesOut, redactions, cost);

  return { status: upstream.status, body: upstream.body, redactions };
}

// mockUpstream is an offline stand-in for a real AI SaaS app.
export const mockUpstream: UpstreamFetch = async (_url, body) => {
  return { status: 200, body: JSON.stringify({ app_reply: `processed: ${body}` }) };
};
