import assert from "node:assert";
import { test } from "node:test";
import { openDB } from "../src/db.ts";
import { ingestAlert, normalizeAlert } from "../src/ingest.ts";

test("normalizeAlert handles Wazuh format", () => {
  const norm = normalizeAlert({
    id: "1",
    rule: { description: "ssh brute force", level: 13 },
    data: { srcip: "1.2.3.4" },
  });
  assert.equal(norm.title, "ssh brute force");
  assert.equal(norm.severity, "critical");
});

test("normalizeAlert handles generic format", () => {
  const norm = normalizeAlert({ title: "malware callback", severity: "high", src: "5.6.7.8" });
  assert.equal(norm.title, "malware callback");
  assert.equal(norm.severity, "high");
});

test("normalizeAlert defaults", () => {
  const norm = normalizeAlert({});
  assert.equal(norm.title, "SIEM alert");
  assert.equal(norm.severity, "medium");
});

test("ingestAlert opens a case with the alert attached", () => {
  const db = openDB(":memory:");
  const c = ingestAlert(db, { rule: { description: "c2 beacon", level: 12 }, data: { srcip: "9.9.9.9" } });
  assert.equal(c.title, "c2 beacon");
  assert.equal(c.severity, "critical");
  assert.equal(c.alerts.length, 1);
  assert.equal(c.status, "open");
});
