import assert from "node:assert";
import { createServer, type Server } from "node:http";
import { test } from "node:test";
import {
  Cortex,
  MockCortex,
  MockOpenCTI,
  MockWazuh,
  OpenCTI,
  Wazuh,
  registerConnectorNodes,
} from "../src/connectors.ts";

function listen(handler: Parameters<typeof createServer>[0]): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, () => resolve({ server, port: (server.address() as { port: number }).port }));
  });
}

test("mock connectors work offline", async () => {
  const alerts = await new MockWazuh().fetchAlerts();
  assert.equal(alerts.length, 2);

  const intel = await new MockOpenCTI().enrichIp("1.2.3.4");
  assert.equal(intel.reputation, "malicious");

  const cortex = new MockCortex();
  const r = await cortex.blockIp("1.2.3.4");
  assert.equal(r.status, "blocked");
  assert.equal(cortex.actions.length, 1);
});

test("Wazuh real client fetches + maps alerts", async () => {
  const captured: { url?: string; auth?: string } = {};
  const { server, port } = await listen((req, res) => {
    captured.url = req.url ?? "";
    captured.auth = req.headers.authorization;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        data: { items: [{ id: "1", rule: { description: "brute force", level: 13 }, data: { srcip: "9.9.9.9" } }] },
      }),
    );
  });
  try {
    const alerts = await new Wazuh(`http://127.0.0.1:${port}`, "user", "pass").fetchAlerts();
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].severity, "critical");
    assert.equal(alerts[0].src, "9.9.9.9");
    assert.equal(captured.url, "/alerts?limit=50&sort=-timestamp");
    assert.ok(captured.auth?.startsWith("Basic "));
  } finally {
    server.close();
  }
});

test("OpenCTI real client posts a GraphQL query", async () => {
  const captured: { url?: string; auth?: string; body?: string } = {};
  const { server, port } = await listen((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      captured.url = req.url ?? "";
      captured.auth = req.headers.authorization;
      captured.body = data;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { ipv4Addr: { value: "1.2.3.4" } } }));
    });
  });
  try {
    const intel = await new OpenCTI(`http://127.0.0.1:${port}`, "tok").enrichIp("1.2.3.4");
    assert.equal(intel.source, "opencti");
    assert.equal(captured.url, "/graphql");
    assert.equal(captured.auth, "Bearer tok");
    assert.ok(captured.body?.includes("ipv4Addr"));
  } finally {
    server.close();
  }
});

test("Cortex real client runs a responder", async () => {
  const captured: { url?: string; auth?: string } = {};
  const { server, port } = await listen((req, res) => {
    captured.url = req.url ?? "";
    captured.auth = req.headers.authorization;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({}));
  });
  try {
    const r = await new Cortex(`http://127.0.0.1:${port}`, "tok").blockIp("1.2.3.4");
    assert.equal(r.status, "executed");
    assert.equal(captured.url, "/api/connector/run/block_ip/ip");
    assert.equal(captured.auth, "Bearer tok");
  } finally {
    server.close();
  }
});

test("registerConnectorNodes registers connector-backed nodes", async () => {
  const registered: Record<string, unknown> = {};
  registerConnectorNodes(
    (type, fn) => {
      registered[type] = fn;
    },
    { alertSource: new MockWazuh(), enricher: new MockOpenCTI(), responder: new MockCortex() },
  );
  assert.ok(registered["wazuh.fetch"]);
  assert.ok(registered["opencti.enrich.ip"]);
  assert.ok(registered["cortex.block_ip"]);
});
