// Offline fixture child that IGNORES SIGTERM, used to prove StdioSession.close()
// really escalates to SIGKILL. A well-behaved MCP child exits on stdin EOF, so
// the escalation path would otherwise never be exercised.
//
// On startup it emits a JSON-RPC notification carrying its own pid so the test
// can probe liveness with process.kill(pid, 0) from the parent.

function send(msg: unknown): void {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

// Deliberately ignore SIGTERM (and SIGINT) so only SIGKILL can stop us.
process.on("SIGTERM", () => undefined);
process.on("SIGINT", () => undefined);

send({
  jsonrpc: "2.0",
  method: "notifications/message",
  params: { level: "info", text: `pid:${process.pid}` },
});

function reply(id: number | string, result: unknown): void {
  send({ jsonrpc: "2.0", id, result });
}

process.stdin.setEncoding("utf8");
let buffer = "";
process.stdin.on("data", (chunk: string) => {
  buffer += chunk;
  let nl = buffer.indexOf("\n");
  while (nl !== -1) {
    const line = buffer.slice(0, nl);
    buffer = buffer.slice(nl + 1);
    nl = buffer.indexOf("\n");
    if (!line.trim()) continue;
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    const id = msg.id as number | string | undefined;
    const method = msg.method as string | undefined;
    if (method === "initialize") {
      reply(id ?? 0, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "stubborn-mcp-child", version: "0.1.0" },
      });
    } else if (method === "tools/list") {
      reply(id ?? 0, {
        tools: [
          { name: "ping", description: "pong", inputSchema: { type: "object", properties: {} } },
          { name: "hang", description: "never replies", inputSchema: { type: "object", properties: {} } },
        ],
      });
    } else if (method === "tools/call") {
      const name = (msg.params as Record<string, unknown>)?.name;
      if (name === "hang") {
        // Deliberately never reply, so the parent has a request genuinely in
        // flight. Used to test that close() rejects pending requests instead of
        // leaving callers hanging forever.
        continue;
      }
      reply(id ?? 0, { content: [{ type: "text", text: "pong" }] });
    }
    // notifications/initialized: no reply needed
  }
});
process.stdin.on("end", () => process.exit(0));
