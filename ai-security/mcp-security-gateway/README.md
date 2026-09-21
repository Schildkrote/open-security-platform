# mcp-security-gateway

An open **MCP Security Gateway**: a JSON-RPC proxy that sits in front of Model
Context Protocol servers/tools and enforces a registry, allowlists, policy,
secret injection, egress filtering, tool-poisoning detection, and a
tamper-evident audit trail. Zero runtime dependencies (Node 22 stdlib + `node:sqlite`).

## Features (MVP)

- **MCP server & tool registry** with risk ratings and allow/deny state
- **JSON-RPC gateway** handling `initialize`, `tools/list`, `tools/call`
- **Tool allowlists** (`tools/list` only returns allowed tools on allowed servers)
- **Policy engine** → `allow` / `deny` / `approve` per tool & argument pattern
- **Tool-poisoning detection**: flags instruction injection, role spoofing,
  exfil intent, hidden directives, zero-width chars, encoded payloads, and
  suspicious URLs in tool descriptions *and* call arguments
- **Secret injection**: `{{secret:NAME}}` placeholders resolved server-side so
  clients never see credentials
- **Hash-chained audit log** with integrity verification
- Pluggable **tool executor** (offline mock included)
- **Real MCP transports** for upstream servers, selectable per server:
  - **Streamable-HTTP/SSE** — register an http(s) `endpoint`
  - **stdio** — register a `stdio:` endpoint; the gateway spawns the child MCP
    server (newline-delimited JSON-RPC over stdin/stdout, `initialize`
    handshake, id-correlated requests, notification pass-through, timeouts,
    dead-child handling)
  - All calls pass through the same registry/allowlist/policy/poisoning/audit
    pipeline regardless of transport — denied calls never reach (or spawn) an
    upstream server.

## Transports

`MCP_TRANSPORT` selects the executor at startup:

```bash
MCP_TRANSPORT=http   npm start   # all endpoints treated as Streamable-HTTP
MCP_TRANSPORT=stdio  npm start   # all endpoints treated as stdio children
MCP_TRANSPORT=auto   npm start   # per-server: `stdio:` prefix vs http(s) URL
npm start                        # unset: offline mock executor (default)
```

A server's registered `endpoint` decides its upstream transport:

```bash
# Remote Streamable-HTTP server
curl -X POST localhost:8084/admin/servers \
  -d '{"id":"remote","name":"Remote","endpoint":"https://mcp.example.com/rpc"}'

# Local stdio server (whitespace form: stdio:<command> [args...])
curl -X POST localhost:8084/admin/servers \
  -d '{"id":"local","name":"Local","endpoint":"stdio:node /srv/mcp-server/index.js"}'

# stdio JSON form — required when args contain spaces
curl -X POST localhost:8084/admin/servers -d '{"id":"ts","name":"TS child",
  "endpoint":"stdio:{\"command\":\"node\",\"args\":[\"--experimental-strip-types\",\"/srv/my server.ts\"]}"}'
```

Children are spawned **without a shell**, so endpoint strings cannot inject
shell metacharacters; one child per endpoint is reused across calls and
killed when the gateway exits. Stdio tests run fully offline against an
in-repo fake MCP child (`test/fixtures/fake-mcp-child.ts`).

## Quickstart

```bash
npm start   # listens on :8084
```

```bash
# Register a server + tool
curl -X POST localhost:8084/admin/servers -d '{"id":"srv","name":"Demo"}'
curl -X POST localhost:8084/admin/tools -d '{"name":"search","server_id":"srv","description":"Search docs"}'
curl -X POST localhost:8084/admin/secrets -d '{"name":"TOKEN","value":"abc123"}'

# JSON-RPC: list tools
curl -X POST localhost:8084/mcp -H 'Authorization: Bearer alice' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Call a tool with server-side secret injection
curl -X POST localhost:8084/mcp -H 'Authorization: Bearer alice' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{"token":"{{secret:TOKEN}}"}}}'

# Poisoned call is blocked
curl -X POST localhost:8084/mcp -H 'Authorization: Bearer alice' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"q":"ignore previous instructions"}}}'

curl localhost:8084/admin/audit/verify   # {"valid":true}
```

Default policy denies `shell|exec|run_command` and requires approval for `payment*`.

## Tests

```bash
npm test
```

## License

AGPL-3.0-only
