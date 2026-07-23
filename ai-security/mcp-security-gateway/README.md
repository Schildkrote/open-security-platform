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

Apache-2.0
