import assert from "node:assert";
import { test } from "node:test";
import { openDB } from "../src/db.ts";
import { SqliteAuditRepository, SqliteCaseRepository, type CaseRepository } from "../src/repository.ts";

test("case repository CRUD via the interface", () => {
  const db = openDB(":memory:");
  const repo: CaseRepository = new SqliteCaseRepository(db);

  const c = repo.create("phishing alert", { severity: "high", alert: { src: "1.2.3.4" } });
  assert.equal(repo.get(c.id)?.title, "phishing alert");
  assert.equal(c.alerts.length, 1);

  repo.setStatus(c.id, "investigating", "analyst");
  assert.equal(repo.get(c.id)?.status, "investigating");

  repo.assign(c.id, "analyst");
  assert.equal(repo.get(c.id)?.assignee, "analyst");

  repo.addEvidence(c.id, { note: "confirmed malicious" });
  assert.equal(repo.get(c.id)?.evidence.length, 1);

  assert.equal(repo.list().length, 1);
});

test("audit repository verifies the chain", () => {
  const db = openDB(":memory:");
  const repo = new SqliteCaseRepository(db);
  repo.create("case a");
  repo.create("case b");
  const auditRepo = new SqliteAuditRepository(db);
  assert.ok(auditRepo.verify().valid);
});
