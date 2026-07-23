# Next Steps — mcp-security-gateway

## Real MCP transport
- Proxy real MCP servers over **stdio and Streamable HTTP/SSE** (today the
  executor is an offline mock). Spawn/manage child MCP servers per tenant.
- **Egress enforcement** to server endpoints via a controlled network path.

## Detection depth
- Replace heuristics with **classifiers** for prompt-injection and poisoning.
- **Static + dynamic analysis of tools/plugins** before registration
  (pair with `agent-sandbox` to detonate tool code safely).
- Detect **rug-pull** attacks (tool behavior changing after approval).

## Authorization & identity
- Require an **`agent-identity` token** per call; scope tools by token.
- **Per-principal tool ACLs** and just-in-time approval workflows.
- **OAuth on-behalf-of** so tools act with the user's permissions.

## Governance & observability
- OpenTelemetry traces of every tool call; cost/latency metrics.
- **Session recording/replay** of tool invocations for audit.
- Emit evidence to `ai-compliance-hub`.

## Platform
- Multi-tenant policy, Postgres backend, HA, admin UI.
- Signed tool manifests / reputation registry for a tool marketplace.
