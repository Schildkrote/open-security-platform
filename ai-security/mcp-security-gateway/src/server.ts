import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { openDB, type DB } from "./db.ts";
import { Gateway } from "./gateway.ts";
import { PolicyEngine } from "./policy.ts";
import * as registry from "./registry.ts";
import { setSecret } from "./secrets.ts";
import * as audit from "./audit.ts";
import type { JsonRpcRequest } from "./jsonrpc.ts";

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

function principalOf(req: IncomingMessage): string | null {
  const h = req.headers.authorization ?? "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

// A sensible default policy: block shell execution, require approval for payments.
export const defaultPolicy = new PolicyEngine([
  { name: "deny-shell", toolPattern: "^(shell|exec|run_command)$", decision: "deny", reason: "shell disabled" },
  { name: "approve-payments", toolPattern: "^payment", decision: "approve", reason: "financial action" },
]);

export function buildHandler(db: DB, gateway: Gateway) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const method = req.method ?? "GET";
    try {
      if (path === "/healthz") return json(res, 200, { ok: true });

      if (path === "/mcp" && method === "POST") {
        const rpc = JSON.parse(await readBody(req)) as JsonRpcRequest;
        const response = await gateway.handle(db, rpc, principalOf(req));
        return json(res, 200, response);
      }

      if (path === "/admin/servers" && method === "POST")
        return json(res, 201, registry.registerServer(db, JSON.parse(await readBody(req))));
      if (path === "/admin/tools" && method === "POST")
        return json(res, 201, registry.registerTool(db, JSON.parse(await readBody(req))));
      if (path === "/admin/secrets" && method === "POST") {
        const { name, value } = JSON.parse(await readBody(req));
        setSecret(db, name, value);
        return json(res, 201, { stored: name });
      }
      if (path === "/admin/audit" && method === "GET") return json(res, 200, audit.recent(db));
      if (path === "/admin/audit/verify" && method === "GET") return json(res, 200, audit.verifyChain(db));

      return json(res, 404, { error: "not found" });
    } catch (e) {
      return json(res, 400, { error: (e as Error).message });
    }
  };
}

const isMain = process.argv[1]?.endsWith("server.ts");
if (isMain) {
  const db = openDB(process.env.DB_PATH ?? ":memory:");
  const gateway = new Gateway(db, defaultPolicy, {
    allowedDomains: (process.env.ALLOWED_DOMAINS ?? "").split(",").filter(Boolean),
    requireAuth: process.env.REQUIRE_AUTH === "1",
  });
  const port = Number(process.env.PORT ?? 8084);
  createServer(buildHandler(db, gateway)).listen(port, () =>
    console.log(`mcp-security-gateway listening on :${port}`),
  );
}
