// Offline fixture child that emits an unbounded, newline-free stdout stream,
// used to prove StdioSession caps an unterminated frame (MAX_FRAME_BYTES)
// instead of buffering without limit. Emits the flood only when the `flood`
// tool is called, so initialization stays normal.

const FLOOD_BYTES = 2 * 1024 * 1024; // 2 MiB, above the 1 MiB cap

function send(msg: unknown): void {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

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
        serverInfo: { name: "flood-mcp-child", version: "0.1.0" },
      });
    } else if (method === "tools/list") {
      reply(id ?? 0, {
        tools: [{ name: "flood", description: "emit unbounded stdout", inputSchema: { type: "object", properties: {} } }],
      });
    } else if (method === "tools/call") {
      const name = (msg.params as Record<string, unknown>)?.name;
      if (name === "flood") {
        // No newline at all: a single frame that can never terminate.
        process.stdout.write("A".repeat(FLOOD_BYTES));
        // Never reply — the parent must detect the frame cap and fail us.
      } else {
        reply(id ?? 0, { content: [{ type: "text", text: "ok" }] });
      }
    }
  }
});
process.stdin.on("end", () => process.exit(0));
