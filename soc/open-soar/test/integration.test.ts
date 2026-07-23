import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { openDB } from "../src/db.ts";
import { buildHandler } from "../src/server.ts";

function listen(): Promise<{ server: Server; base: string }> {
  const db = openDB();
  return new Promise((resolve) => {
    const server = createServer(buildHandler(db));
    server.listen(0, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}` });
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

test("HTTP: case -> triage -> playbook run -> evidence -> audit", async () => {
  const { server, base } = await listen();
  try {
    const created = await call(base, "/cases", { title: "phishing email reported", alert: { ip: "1.2.3.4" } });
    assert.equal(created.status, 201);
    const caseId = created.json.id as string;

    const triage = await call(base, `/cases/${caseId}/triage`, {});
    assert.equal(triage.status, 200);
    assert.equal(triage.json.triage.classification, "phishing");

    const run = await call(base, "/playbooks/pb-phishing/run", { input: { ip: "1.2.3.4", title: "phishing email reported" }, case_id: caseId });
    assert.equal(run.status, 200);
    assert.equal(run.json.status, "success");
    assert.equal(run.json.outputs.block_ip.status, "blocked");

    const fetched = await call(base, `/cases/${caseId}`);
    assert.ok((fetched.json.evidence as unknown[]).some((e: any) => e.type === "playbook_run"));

    const verify = await call(base, "/audit/verify");
    assert.equal(verify.json.valid, true);
  } finally {
    server.close();
  }
});

test("HTTP: unknown playbook returns 404", async () => {
  const { server, base } = await listen();
  try {
    const run = await call(base, "/playbooks/nope/run", { input: {} });
    assert.equal(run.status, 404);
  } finally {
    server.close();
  }
});
