import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { openDB } from "../src/db.ts";
import { buildHandler } from "../src/server.ts";
import * as registry from "../src/registry.ts";

function listen(): Promise<{ server: Server; base: string; db: ReturnType<typeof openDB> }> {
  const db = openDB();
  registry.registerAgent(db, { id: "agent-a", name: "A", base_scopes: ["read", "search"] });
  registry.registerAgent(db, { id: "agent-b", name: "B", base_scopes: ["read"] });
  return new Promise((resolve) => {
    const server = createServer(buildHandler(db));
    server.listen(0, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}`, db });
    });
  });
}

async function call(base: string, path: string, body?: unknown) {
  const res = await fetch(`${base}${path}`, {
    method: body ? "POST" : "GET",
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: (await res.json()) as Record<string, any> };
}

test("HTTP: issue -> delegate -> verify -> revoke", async () => {
  const { server, base } = await listen();
  try {
    const issued = await call(base, "/tokens", { agent_id: "agent-a", on_behalf_of: "user@x.com" });
    assert.equal(issued.status, 201);
    const parent = issued.json.token as string;

    const delegated = await call(base, "/tokens/delegate", {
      token: parent,
      to_agent_id: "agent-b",
      scopes: ["read", "search"],
    });
    assert.equal(delegated.status, 201);

    const verified = await call(base, "/tokens/verify", { token: delegated.json.token });
    assert.equal(verified.status, 200);
    assert.deepEqual(verified.json.claims.scopes, ["read"]);
    assert.equal(verified.json.delegation_depth, 1);

    // Revoke the delegated token by its jti.
    const jti = verified.json.claims.jti as string;
    await call(base, "/tokens/revoke", { jti, reason: "test" });
    const after = await call(base, "/tokens/verify", { token: delegated.json.token });
    assert.equal(after.status, 400);
    assert.match(after.json.error, /revoked/);
  } finally {
    server.close();
  }
});

test("HTTP: elevation request -> approval -> token with new scope", async () => {
  const { server, base } = await listen();
  try {
    const req = await call(base, "/elevation-requests", {
      agent_id: "agent-b",
      scopes: ["deploy"],
      justification: "release",
    });
    assert.equal(req.status, 201);
    const approved = await call(base, `/elevation-requests/${req.json.id}/approve`, { approver: "admin" });
    assert.equal(approved.status, 200);

    const issued = await call(base, "/tokens", { agent_id: "agent-b", scopes: ["deploy"] });
    const verified = await call(base, "/tokens/verify", { token: issued.json.token });
    assert.ok((verified.json.claims.scopes as string[]).includes("deploy"));
  } finally {
    server.close();
  }
});
