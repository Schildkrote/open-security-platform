import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { getDB, type DB } from "./db.ts";
import { verify, type Claims } from "./jwt.ts";
import { issueCode, exchangeCode } from "./idp.ts";
import { listApps, registerApp, getApp } from "./catalog.ts";
import {
  ensureUser,
  requestAccess,
  decide,
  listRequests,
  type RequestStatus,
} from "./access.ts";
import { brokerRequest, mockUpstream } from "./proxy.ts";

const ALLOWED_REGIONS = (process.env.ALLOWED_REGIONS ?? "us,eu").split(",");

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
  });
}

function auth(req: IncomingMessage): Claims | null {
  const h = req.headers.authorization ?? "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return null;
  try {
    return verify(token);
  } catch {
    return null;
  }
}

export function buildHandler(db: DB) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    try {
      // --- Mock IdP (SSO) ---
      if (method === "POST" && path === "/idp/login") {
        const { email, role } = JSON.parse((await readBody(req)) || "{}");
        if (!email) return json(res, 400, { error: "email required" });
        return json(res, 200, { code: issueCode(email, role ?? "user") });
      }
      if (method === "POST" && path === "/idp/token") {
        const { code } = JSON.parse((await readBody(req)) || "{}");
        try {
          const { id_token } = exchangeCode(code);
          return json(res, 200, { id_token, token_type: "Bearer" });
        } catch (e) {
          return json(res, 400, { error: (e as Error).message });
        }
      }

      // --- App catalog ---
      if (path === "/apps" && method === "GET") {
        return json(res, 200, listApps(db));
      }
      if (path === "/apps" && method === "POST") {
        const claims = auth(req);
        if (claims?.role !== "admin") return json(res, 403, { error: "admin only" });
        const body = JSON.parse((await readBody(req)) || "{}");
        return json(res, 201, registerApp(db, body));
      }

      // --- Access requests ---
      if (path === "/access-requests" && method === "POST") {
        const claims = auth(req);
        if (!claims) return json(res, 401, { error: "auth required" });
        const userId = ensureUser(db, claims.sub, claims.role);
        const { app_id, justification } = JSON.parse((await readBody(req)) || "{}");
        try {
          return json(res, 201, requestAccess(db, userId, app_id, justification));
        } catch (e) {
          return json(res, 400, { error: (e as Error).message });
        }
      }
      if (path === "/access-requests" && method === "GET") {
        const status = url.searchParams.get("status") as RequestStatus | null;
        return json(res, 200, listRequests(db, status ?? undefined));
      }
      const decideMatch = path.match(/^\/access-requests\/([^/]+)\/decide$/);
      if (decideMatch && method === "POST") {
        const claims = auth(req);
        if (claims?.role !== "admin") return json(res, 403, { error: "admin only" });
        const approverId = ensureUser(db, claims.sub, claims.role);
        const { approve } = JSON.parse((await readBody(req)) || "{}");
        try {
          return json(res, 200, decide(db, decideMatch[1], approverId, !!approve));
        } catch (e) {
          return json(res, 400, { error: (e as Error).message });
        }
      }

      // --- Proxied AI app access (DLP + residency + usage) ---
      const proxyMatch = path.match(/^\/proxy\/([^/]+)$/);
      if (proxyMatch && method === "POST") {
        const claims = auth(req);
        if (!claims) return json(res, 401, { error: "auth required" });
        const app = getApp(db, proxyMatch[1]);
        if (!app) return json(res, 404, { error: "unknown app" });
        const userId = ensureUser(db, claims.sub, claims.role);
        const body = await readBody(req);
        const result = await brokerRequest(
          { db, userId, app, allowedRegions: ALLOWED_REGIONS, upstreamFetch: mockUpstream },
          body,
        );
        return json(res, result.status, {
          ...safeParse(result.body),
          redactions: result.redactions,
          reason: result.reason,
        });
      }

      // --- Usage / spend ---
      if (path === "/usage" && method === "GET") {
        const claims = auth(req);
        if (claims?.role !== "admin") return json(res, 403, { error: "admin only" });
        const rows = db
          .prepare(
            `SELECT app_id, COUNT(*) calls, SUM(redactions) redactions, ROUND(SUM(cost_usd),4) cost_usd
             FROM usage_log GROUP BY app_id`,
          )
          .all();
        return json(res, 200, rows);
      }

      if (path === "/healthz") return json(res, 200, { ok: true });
      return json(res, 404, { error: "not found" });
    } catch (e) {
      return json(res, 500, { error: (e as Error).message });
    }
  };
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return { raw: s };
  }
}

const isMain = process.argv[1]?.endsWith("server.ts");
if (isMain) {
  const db = getDB(process.env.DB_PATH ?? ":memory:");
  const port = Number(process.env.PORT ?? 8081);
  createServer(buildHandler(db)).listen(port, () => {
    console.log(`ai-access-broker listening on :${port}`);
  });
}
