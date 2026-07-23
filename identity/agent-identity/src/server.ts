import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { openDB, type DB } from "./db.ts";
import * as registry from "./registry.ts";
import * as tokens from "./tokens.ts";
import * as approvals from "./approvals.ts";
import { recentAudit } from "./audit.ts";

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data ? JSON.parse(data) : {}));
  });
}

export function buildHandler(db: DB) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const method = req.method ?? "GET";
    try {
      const body = method === "POST" ? await readBody(req) : {};

      if (path === "/healthz") return json(res, 200, { ok: true });

      if (path === "/agents" && method === "POST")
        return json(res, 201, registry.registerAgent(db, body as never));
      if (path === "/agents" && method === "GET")
        return json(res, 200, registry.listAgents(db));

      let m = path.match(/^\/agents\/([^/]+)\/(enable|disable)$/);
      if (m && method === "POST") {
        const ok = registry.setStatus(db, m[1], m[2] === "enable" ? "active" : "disabled");
        return ok ? json(res, 200, { status: m[2] }) : json(res, 404, { error: "unknown agent" });
      }

      if (path === "/tokens" && method === "POST") {
        const token = tokens.issueToken(db, body.agent_id as string, {
          scopes: body.scopes as string[] | undefined,
          ttl: body.ttl as number | undefined,
          onBehalfOf: body.on_behalf_of as string | undefined,
        });
        return json(res, 201, { token });
      }
      if (path === "/tokens/verify" && method === "POST") {
        const claims = tokens.verifyToken(db, body.token as string);
        return json(res, 200, { valid: true, claims, delegation_depth: tokens.delegationDepth(claims) });
      }
      if (path === "/tokens/delegate" && method === "POST") {
        const token = tokens.delegateToken(db, body.token as string, body.to_agent_id as string, {
          scopes: body.scopes as string[] | undefined,
          ttl: body.ttl as number | undefined,
        });
        return json(res, 201, { token });
      }
      if (path === "/tokens/revoke" && method === "POST") {
        tokens.revoke(db, body.jti as string, body.reason as string | undefined);
        return json(res, 200, { revoked: true });
      }

      if (path === "/jit-grants" && method === "POST") {
        const grant = tokens.grantJIT(
          db,
          body.agent_id as string,
          (body.scopes as string[]) ?? [],
          (body.ttl as number) ?? 3600,
          body.approved_by as string | undefined,
        );
        return json(res, 201, grant);
      }

      if (path === "/elevation-requests" && method === "POST")
        return json(res, 201, approvals.requestElevation(db, body.agent_id as string, (body.scopes as string[]) ?? [], body.justification as string | undefined));
      if (path === "/elevation-requests" && method === "GET")
        return json(res, 200, approvals.listRequests(db));

      m = path.match(/^\/elevation-requests\/([^/]+)\/(approve|deny)$/);
      if (m && method === "POST") {
        if (m[2] === "approve") {
          const r = approvals.approveElevation(db, m[1], (body.approver as string) ?? "admin", (body.ttl as number) ?? 3600);
          return json(res, 200, r);
        }
        return json(res, 200, approvals.denyElevation(db, m[1], (body.approver as string) ?? "admin"));
      }

      if (path === "/audit" && method === "GET") return json(res, 200, recentAudit(db));

      return json(res, 404, { error: "not found" });
    } catch (e) {
      return json(res, 400, { error: (e as Error).message });
    }
  };
}

const isMain = process.argv[1]?.endsWith("server.ts");
if (isMain) {
  const db = openDB(process.env.DB_PATH ?? ":memory:");
  const port = Number(process.env.PORT ?? 8083);
  createServer(buildHandler(db)).listen(port, () =>
    console.log(`agent-identity listening on :${port}`),
  );
}
