import assert from "node:assert";
import { createServer, type Server } from "node:http";
import { test } from "node:test";
import { HttpTransport, MockTransport, makeExecutor } from "../src/transport.ts";
import type { McpTool } from "../src/registry.ts";

function listen(handler: Parameters<typeof createServer>[0]): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, () => resolve({ server, port: (server.address() as { port: number }).port }));
  });
}

const tool: McpTool = { name: "search", server_id: "s1", description: null, risk: "low", allowed: 1 };

test("HttpTransport posts JSON-RPC tools/call and returns result", async () => {
  const captured: { body?: string } = {};
  const { server, port } = await listen((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      captured.body = data;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "ok" }] } }));
    });
  });
  try {
    const result = await new HttpTransport().callTool(`http://127.0.0.1:${port}`, "search", { q: "x" });
    const body = JSON.parse(captured.body ?? "{}");
    assert.equal(body.method, "tools/call");
    assert.equal(body.params.name, "search");
    assert.deepEqual(result, { content: [{ type: "text", text: "ok" }] });
  } finally {
    server.close();
  }
});

test("HttpTransport parses SSE responses", async () => {
  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [] } })}\n\n`);
  });
  try {
    const result = await new HttpTransport().callTool(`http://127.0.0.1:${port}`, "search", {});
    assert.deepEqual(result, { content: [] });
  } finally {
    server.close();
  }
});

test("MockTransport returns mock content", async () => {
  const result = (await new MockTransport().callTool("e", "search", { q: "x" })) as {
    content: Array<{ text: string }>;
  };
  assert.ok(result.content[0].text.includes("executed search"));
});

test("makeExecutor dispatches via transport when endpoint present, else mock", async () => {
  const calls: string[] = [];
  const transport = {
    callTool: async (endpoint: string, name: string) => {
      calls.push(`${endpoint}:${name}`);
      return { content: [{ type: "text", text: "real" }] };
    },
  };
  const exec = makeExecutor(transport, (t) => (t.server_id === "s1" ? "http://real" : null));
  const withEndpoint = (await exec(tool, {})) as { content: Array<{ text: string }> };
  assert.equal(withEndpoint.content[0].text, "real");
  assert.deepEqual(calls, ["http://real:search"]);

  const noEndpoint = (await exec({ ...tool, server_id: "other" }, {})) as {
    content: Array<{ text: string }>;
  };
  assert.ok(noEndpoint.content[0].text.includes("executed search"));
});
