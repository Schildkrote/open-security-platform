import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { openDB, type DB } from "./db.ts";
import { Gateway, type GatewayOptions } from "./gateway.ts";
import { PolicyEngine } from "./policy.ts";
import * as registry from "./registry.ts";
import { setSecret } from "./secrets.ts";
import * as audit from "./audit.ts";
import { CompositeTransport, HttpTransport, makeExecutor } from "./transport.ts";
import { StdioTransport } from "./stdio.ts";
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

export function buildHandler(db: DB, gateway: Gateway, adminToken?: string) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const method = req.method ?? "GET";
    try {
      if (path === "/healthz") return json(res, 200, { ok: true });

      // The /admin/* surface can register arbitrary upstream servers — including
      // `stdio:` endpoints that spawn local processes — so it must never be
      // reachable unauthenticated on a network interface. When an admin token
      // is configured, every /admin/* call must present it as a bearer token.
      // Constant-time-ish comparison is unnecessary here (the value is a shared
      // secret compared once per request), but we do compare full strings.
      if (path.startsWith("/admin/") && adminToken) {
        if (principalOf(req) !== adminToken) {
          return json(res, 401, { error: "unauthorized: admin token required" });
        }
      }

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
  const options: GatewayOptions = {
    allowedDomains: (process.env.ALLOWED_DOMAINS ?? "").split(",").filter(Boolean),
    requireAuth: process.env.REQUIRE_AUTH === "1",
  };
  // Phase 3: real MCP transports. MCP_TRANSPORT selects the executor:
  //   http  — all servers with an endpoint are called over Streamable-HTTP/SSE
  //   stdio — all servers with a `stdio:<command> [args...]` endpoint are
  //           proxied over newline-delimited JSON-RPC on a child process
  //   auto  — per-upstream-server choice by endpoint scheme (CompositeTransport):
  //           `stdio:` prefix → stdio child, http(s) URL → Streamable-HTTP, so
  //           one gateway can front both kinds at once
  //   unset — the offline mock executor (default; keeps tests hermetic)
  // Either way the transport sits behind the SAME registry/allowlist/policy/
  // poisoning/audit pipeline in Gateway.toolsCall — it only runs after a call
  // is approved, never instead of the checks.
  const transportMode = process.env.MCP_TRANSPORT ?? "";
  const endpointFor = (tool: registry.McpTool) => registry.getServer(db, tool.server_id)?.endpoint ?? null;
  // Any transport that can hold stdio child processes must be reaped on exit,
  // otherwise a gateway killed with SIGTERM/SIGINT leaves orphaned children.
  // closeAllSync (not closeAll) is used in the exit hook: timers cannot run
  // during process teardown, so the graceful SIGTERM-then-SIGKILL path would
  // never escalate and the children would survive.
  let stdioLike: StdioTransport | CompositeTransport | null = null;
  if (transportMode === "http") {
    options.executor = makeExecutor(new HttpTransport(), endpointFor);
  } else if (transportMode === "stdio") {
    const stdio = new StdioTransport();
    stdioLike = stdio;
    options.executor = makeExecutor(stdio, endpointFor);
  } else if (transportMode === "auto") {
    const composite = new CompositeTransport();
    stdioLike = composite;
    options.executor = makeExecutor(composite, endpointFor);
  }
  if (stdioLike) {
    const reap = stdioLike;
    process.on("exit", () => reap.closeAllSync());
    // `exit` does not fire for SIGINT/SIGTERM unless handled, so reap on those
    // too and re-raise to keep the conventional exit status.
    for (const sig of ["SIGINT", "SIGTERM"] as const) {
      process.on(sig, () => {
        reap.closeAllSync();
        process.kill(process.pid, sig);
      });
    }
  }
  const gateway = new Gateway(db, defaultPolicy, options);
  const port = Number(process.env.PORT ?? 8084);
  // Bind loopback unless an operator explicitly opts into an interface. The
  // /admin/* surface can spawn processes via stdio endpoints, so defaulting to
  // all-interfaces would expose unauthenticated process execution to the LAN.
  // Set HOST=0.0.0.0 deliberately (with ADMIN_TOKEN) to expose it.
  const host = process.env.HOST ?? "127.0.0.1";
  const adminToken = process.env.ADMIN_TOKEN ?? "";
  if (adminToken === "" && host !== "127.0.0.1" && host !== "localhost") {
    console.error(
      "refusing to start: HOST is not loopback and ADMIN_TOKEN is unset. " +
        "Set ADMIN_TOKEN before exposing this gateway beyond localhost.",
    );
    process.exit(1);
  }
  createServer(buildHandler(db, gateway, adminToken || undefined)).listen(port, host, () =>
    console.log(`mcp-security-gateway listening on ${host}:${port}${adminToken ? " (admin auth on)" : ""}`),
  );
}
