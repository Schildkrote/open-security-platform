import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { openDB } from "../src/db.ts";
import { buildHandler } from "../src/server.ts";
import { registerApp } from "../src/catalog.ts";

function listen(db: ReturnType<typeof openDB>): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = createServer(buildHandler(db));
    server.listen(0, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

test("full SSO -> request -> approve -> proxy flow over HTTP", async () => {
  const db = openDB();
  const app = registerApp(db, { name: "ChatGPT", risk: "medium", data_residency: "us", approval_required: 1 });
  const { server, base } = await listen(db);
  try {
    // user + admin log in via mock IdP
    const userTok = await login(base, "user@x.com", "user");
    const adminTok = await login(base, "admin@x.com", "admin");

    // user requests access
    const reqRes = await fetch(`${base}/access-requests`, {
      method: "POST",
      headers: auth(userTok),
      body: JSON.stringify({ app_id: app.id, justification: "work" }),
    });
    assert.equal(reqRes.status, 201);
    const accessReq = (await reqRes.json()) as { id: string; status: string };
    assert.equal(accessReq.status, "pending");

    // proxy is blocked before approval
    const blocked = await fetch(`${base}/proxy/${app.id}`, {
      method: "POST",
      headers: auth(userTok),
      body: "hello",
    });
    assert.equal(blocked.status, 403);

    // admin approves
    const decRes = await fetch(`${base}/access-requests/${accessReq.id}/decide`, {
      method: "POST",
      headers: auth(adminTok),
      body: JSON.stringify({ approve: true }),
    });
    assert.equal(decRes.status, 200);

    // proxy now works and redacts PII
    const ok = await fetch(`${base}/proxy/${app.id}`, {
      method: "POST",
      headers: auth(userTok),
      body: "contact me at jane@corp.com",
    });
    assert.equal(ok.status, 200);
    const result = (await ok.json()) as { redactions: number };
    assert.ok(result.redactions >= 1);
  } finally {
    server.close();
  }
});

async function login(base: string, email: string, role: string): Promise<string> {
  const codeRes = await fetch(`${base}/idp/login`, {
    method: "POST",
    body: JSON.stringify({ email, role }),
  });
  const { code } = (await codeRes.json()) as { code: string };
  const tokRes = await fetch(`${base}/idp/token`, {
    method: "POST",
    body: JSON.stringify({ code }),
  });
  const { id_token } = (await tokRes.json()) as { id_token: string };
  return id_token;
}

function auth(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, "content-type": "application/json" };
}
