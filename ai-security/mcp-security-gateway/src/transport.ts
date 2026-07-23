import type { ToolExecutor } from "./gateway.ts";
import type { McpTool } from "./registry.ts";

// Real MCP transports (Phase 3). HttpTransport implements MCP Streamable-HTTP
// (JSON-RPC over HTTP, with SSE response support); MockTransport is the offline
// default. A stdio transport for local servers is a documented follow-up.

export interface Transport {
  callTool(endpoint: string, toolName: string, args: unknown): Promise<unknown>;
}

function parseSse(text: string): unknown {
  const line = text
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.startsWith("data:"));
  const data = (line ?? "data: {}").slice(5).trim();
  return JSON.parse(data || "{}");
}

// HttpTransport calls a remote MCP server over Streamable-HTTP.
export class HttpTransport implements Transport {
  async callTool(endpoint: string, toolName: string, args: unknown): Promise<unknown> {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: toolName, arguments: args },
    });
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body,
    });
    if (!resp.ok) throw new Error(`mcp: tools/call failed (${resp.status})`);
    const ctype = resp.headers.get("content-type") ?? "";
    const payload = ctype.includes("text/event-stream")
      ? parseSse(await resp.text())
      : await resp.json();
    return (payload as { result?: unknown }).result;
  }
}

// MockTransport is the offline default (mirrors the gateway's mock executor).
export class MockTransport implements Transport {
  async callTool(_endpoint: string, toolName: string, args: unknown): Promise<unknown> {
    return { content: [{ type: "text", text: `executed ${toolName} with ${JSON.stringify(args)}` }] };
  }
}

// makeExecutor adapts a Transport into the gateway's ToolExecutor, resolving each
// tool's server endpoint. Tools whose server has no endpoint fall back to a mock
// result, so partially-real deployments still work offline.
export function makeExecutor(
  transport: Transport,
  endpointFor: (tool: McpTool) => string | null,
): ToolExecutor {
  return async (tool, args) => {
    const endpoint = endpointFor(tool);
    if (!endpoint) {
      return { content: [{ type: "text", text: `executed ${tool.name} with ${JSON.stringify(args)}` }] };
    }
    return transport.callTool(endpoint, tool.name, args);
  };
}
