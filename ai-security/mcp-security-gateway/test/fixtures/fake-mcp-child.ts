// Offline fake MCP child server used by test/stdio.test.ts. Speaks the MCP
// stdio framing (newline-delimited JSON-RPC 2.0 on stdin/stdout) and exposes
// two tools: `echo` and `add`. Also exercises notification pass-through
// (`notifications/message`), JSON-RPC error responses (`boom`), delayed
// replies (`slow`, for timeout tests), and an early `exit` command so the
// parent's dead-child handling can be tested. No network, no dependencies.
// stdout is JSON-only; everything else goes to stderr (per the MCP spec).

let nextId = 1000;

function send(msg: unknown): void {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function logNote(text: string): void {
  send({ jsonrpc: "2.0", method: "notifications/message", params: { level: "info", text } });
}

function reply(id: number | string, result: unknown): void {
  send({ jsonrpc: "2.0", id, result });
}

function textContent(text: string): { content: Array<{ type: string; text: string }> } {
  return { content: [{ type: "text", text }] };
}

function handle(msg: Record<string, unknown>): void {
  const id = msg.id as number | string | undefined;
  const method = msg.method as string | undefined;
  if (method === undefined) return; // this child never receives responses

  switch (method) {
    case "initialize":
      reply(id ?? 0, {
        protocolVersion: (msg.params as Record<string, unknown>)?.protocolVersion ?? "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "fake-mcp-child", version: "0.1.0" },
      });
      break;
    case "notifications/initialized":
      logNote("initialized"); // unsolicited notification → pass-through test
      break;
    case "tools/list":
      reply(id ?? 0, {
        tools: [
          { name: "echo", description: "Echoes the input back" },
          { name: "add", description: "Adds two numbers" },
        ],
      });
      break;
    case "tools/call": {
      const params = (msg.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
      const name = params.name;
      const args = params.arguments ?? {};
      if (name === "echo") {
        if (id !== undefined) reply(id, textContent(`echo: ${JSON.stringify(args)}`));
        break;
      }
      if (name === "add") {
        const sum = Number(args.a ?? 0) + Number(args.b ?? 0);
        if (id !== undefined) reply(id, textContent(String(sum)));
        break;
      }
      if (name === "boom") {
        // JSON-RPC error response: parent must reject, not hang.
        send({ jsonrpc: "2.0", id, error: { code: -32000, message: "boom failed" } });
        break;
      }
      if (name === "slow") {
        const delay = Number(args.delayMs ?? 5_000);
        setTimeout(() => {
          if (id !== undefined) reply(id, textContent("late"));
        }, delay);
        break;
      }
      if (name === "exit") {
        // Die with a request in flight so the parent's exit handling is tested.
        process.exit(3);
      }
      if (id !== undefined) {
        send({ jsonrpc: "2.0", id, error: { code: -32601, message: `unknown tool: ${name}` } });
      }
      break;
    }
    case "logging/setLevel":
      if (id !== undefined) reply(id, {});
      break;
    default:
      if (id !== undefined) {
        send({ jsonrpc: "2.0", id, error: { code: -32601, message: `unknown method: ${method}` } });
      }
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => {
  buffer += chunk;
  let nl = buffer.indexOf("\n");
  while (nl !== -1) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    nl = buffer.indexOf("\n");
    if (line === "") continue;
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      continue; // ignore malformed frames
    }
    if (typeof msg === "object" && msg !== null) handle(msg as Record<string, unknown>);
  }
});
process.stdin.on("end", () => process.exit(0));

// A request the gateway does not support (server→client sampling) so the
// parent's method-not-found auto-reply path is exercised.
setTimeout(() => {
  send({ jsonrpc: "2.0", id: nextId++, method: "sampling/createMessage", params: {} });
}, 50);
