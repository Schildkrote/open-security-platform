import { test } from "node:test";
import assert from "node:assert/strict";
import { validate, execute, type Playbook } from "../src/playbook.ts";
import { phishingPlaybook } from "../src/playbooks.ts";
import { heuristicTriage } from "../src/triage.ts";
import { openDB } from "../src/db.ts";
import * as cases from "../src/cases.ts";
import { verifyChain } from "../src/audit.ts";

test("validate catches cycles and unknown deps", () => {
  const cyclic: Playbook = {
    id: "c",
    name: "cyclic",
    steps: [
      { id: "a", type: "transform.set", deps: ["b"] },
      { id: "b", type: "transform.set", deps: ["a"] },
    ],
  };
  assert.ok(validate(cyclic).some((e) => e.includes("cycle")));

  const badDep: Playbook = { id: "b", name: "bad", steps: [{ id: "a", type: "transform.set", deps: ["nope"] }] };
  assert.ok(validate(badDep).some((e) => e.includes("unknown step")));
});

test("execute runs DAG in dependency order with parallel branches", async () => {
  const result = await execute(phishingPlaybook, { ip: "1.2.3.4", title: "phishing email" });
  assert.equal(result.status, "success");
  // block_ip must come after enrich_ip.
  assert.ok(result.order.indexOf("enrich_ip") < result.order.indexOf("block_ip"));
  const block = result.outputs.block_ip as { status: string };
  assert.equal(block.status, "blocked");
  const triage = result.outputs.triage as { classification: string };
  assert.equal(triage.classification, "phishing");
});

test("execute skips dependents of a failed step", async () => {
  const pb: Playbook = {
    id: "p",
    name: "fail",
    steps: [
      { id: "boom", type: "no.such.node" },
      { id: "after", type: "transform.set", params: { value: 1 }, deps: ["boom"] },
    ],
  };
  const result = await execute(pb, {});
  assert.equal(result.status, "failed");
  assert.ok(result.errors.boom);
  assert.ok(result.skipped.includes("after"));
});

test("triage classifies by signal strength", () => {
  assert.equal(heuristicTriage({ title: "ransomware detected on host" }).severity, "critical");
  assert.equal(heuristicTriage({ title: "phishing email reported" }).classification, "phishing");
  assert.equal(heuristicTriage({ title: "nothing notable" }).classification, "unclassified");
});

test("case lifecycle and audit chain", () => {
  const db = openDB();
  const c = cases.createCase(db, "Suspicious login", { severity: "medium", alert: { src: "1.2.3.4" } });
  cases.addEvidence(db, c.id, { type: "log", data: "failed logins" });
  cases.setStatus(db, c.id, "investigating", "analyst");
  cases.assign(db, c.id, "analyst");
  const updated = cases.getCase(db, c.id)!;
  assert.equal(updated.status, "investigating");
  assert.equal(updated.assignee, "analyst");
  assert.equal(updated.evidence.length, 1);
  assert.ok(updated.timeline.length >= 3);
  assert.ok(verifyChain(db).valid);
});
