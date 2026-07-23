import { test } from "node:test";
import assert from "node:assert/strict";
import { openDB } from "../src/db.ts";
import * as registry from "../src/registry.ts";
import * as tokens from "../src/tokens.ts";
import * as approvals from "../src/approvals.ts";
import { decode } from "../src/jwt.ts";

function setup() {
  const db = openDB();
  registry.registerAgent(db, { id: "agent-a", name: "Agent A", base_scopes: ["read", "search"] });
  registry.registerAgent(db, { id: "agent-b", name: "Agent B", base_scopes: ["read"] });
  return db;
}

test("issue token with effective scopes and verify", () => {
  const db = setup();
  const token = tokens.issueToken(db, "agent-a");
  const claims = tokens.verifyToken(db, token);
  assert.deepEqual(claims.scopes.sort(), ["read", "search"]);
  assert.equal(claims.sub, "agent-a");
});

test("requested scopes are capped to effective scopes", () => {
  const db = setup();
  const token = tokens.issueToken(db, "agent-a", { scopes: ["read", "admin"] });
  const claims = tokens.verifyToken(db, token);
  assert.deepEqual(claims.scopes, ["read"]); // "admin" not granted
});

test("disabled agent cannot get or use tokens", () => {
  const db = setup();
  const token = tokens.issueToken(db, "agent-a");
  registry.setStatus(db, "agent-a", "disabled");
  assert.throws(() => tokens.issueToken(db, "agent-a"));
  assert.throws(() => tokens.verifyToken(db, token));
});

test("delegation narrows scopes and records chain", () => {
  const db = setup();
  const parent = tokens.issueToken(db, "agent-a", { onBehalfOf: "user@x.com" });
  const child = tokens.delegateToken(db, parent, "agent-b", { scopes: ["read", "search"] });
  const claims = tokens.verifyToken(db, child);
  // agent-b only has "read", so "search" is dropped.
  assert.deepEqual(claims.scopes, ["read"]);
  assert.equal(claims.on_behalf_of, "user@x.com");
  assert.equal(claims.act?.sub, "agent-a");
  assert.equal(tokens.delegationDepth(claims), 1);
});

test("JIT grant adds temporary scopes", () => {
  const db = setup();
  tokens.grantJIT(db, "agent-b", ["deploy"], 3600, "admin");
  assert.deepEqual(tokens.effectiveScopes(db, "agent-b").sort(), ["deploy", "read"]);
});

test("revocation invalidates a token", () => {
  const db = setup();
  const token = tokens.issueToken(db, "agent-a");
  const jti = decode(token).jti!;
  tokens.revoke(db, jti, "compromised");
  assert.throws(() => tokens.verifyToken(db, token), /revoked/);
});

test("elevation approval creates a usable grant", () => {
  const db = setup();
  const req = approvals.requestElevation(db, "agent-b", ["deploy"], "release");
  assert.equal(req.status, "pending");
  const { grant } = approvals.approveElevation(db, req.id, "admin", 3600);
  assert.ok(grant.expires_at);
  assert.ok(tokens.effectiveScopes(db, "agent-b").includes("deploy"));
  const token = tokens.issueToken(db, "agent-b", { scopes: ["deploy"] });
  assert.ok(tokens.verifyToken(db, token).scopes.includes("deploy"));
});
