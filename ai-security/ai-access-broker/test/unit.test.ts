import { test } from "node:test";
import assert from "node:assert/strict";
import { sign, verify } from "../src/jwt.ts";
import { redact } from "../src/redact.ts";
import { openDB } from "../src/db.ts";
import { registerApp, residencyAllowed } from "../src/catalog.ts";
import { ensureUser, requestAccess, decide, hasAccess } from "../src/access.ts";
import { brokerRequest, mockUpstream } from "../src/proxy.ts";

test("jwt round-trips and rejects tampering", () => {
  const token = sign({ sub: "u@x.com", role: "admin" });
  const claims = verify(token);
  assert.equal(claims.sub, "u@x.com");
  assert.throws(() => verify(token.slice(0, -2) + "xx"));
});

test("redact removes PII and secrets", () => {
  const { output, findings } = redact("email a@b.com key sk-abcdefghij0123456789ABCDEF");
  assert.ok(output.includes("[REDACTED:EMAIL]"));
  assert.ok(output.includes("[REDACTED:OPENAI_KEY]"));
  assert.ok(findings.length >= 2);
});

test("residency policy blocks disallowed regions", () => {
  const db = openDB();
  const app = registerApp(db, { name: "X", risk: "high", data_residency: "cn" });
  assert.equal(residencyAllowed(app, ["us", "eu"]), false);
  assert.equal(residencyAllowed(app, ["us", "cn"]), true);
});

test("access request -> approval -> access", () => {
  const db = openDB();
  const app = registerApp(db, { name: "ChatGPT", risk: "medium", approval_required: 1 });
  const user = ensureUser(db, "u@x.com");
  const admin = ensureUser(db, "a@x.com", "admin");

  const req = requestAccess(db, user, app.id, "need it");
  assert.equal(req.status, "pending");
  assert.equal(hasAccess(db, user, app.id), false);

  const decided = decide(db, req.id, admin, true);
  assert.equal(decided.status, "approved");
  assert.equal(hasAccess(db, user, app.id), true);
});

test("brokerRequest enforces access, redacts, and logs usage", async () => {
  const db = openDB();
  const app = registerApp(db, { name: "ChatGPT", risk: "medium", data_residency: "us", approval_required: 0 });
  const user = ensureUser(db, "u@x.com");
  requestAccess(db, user, app.id); // auto-approved (approval_required = 0)

  const denied = await brokerRequest(
    { db, userId: "someone-else", app, allowedRegions: ["us"], upstreamFetch: mockUpstream },
    "hello",
  );
  assert.equal(denied.status, 403);

  const ok = await brokerRequest(
    { db, userId: user, app, allowedRegions: ["us"], upstreamFetch: mockUpstream },
    "my ssn is 123-45-6789",
  );
  assert.equal(ok.status, 200);
  assert.ok(ok.redactions >= 1);
  const usage = db.prepare(`SELECT COUNT(*) c FROM usage_log`).get() as { c: number };
  assert.equal(usage.c, 1);
});
