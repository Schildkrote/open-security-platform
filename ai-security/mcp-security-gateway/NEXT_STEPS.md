# Next Steps — mcp-security-gateway

## Done — real MCP transports (with evidence)

- **Streamable-HTTP/SSE transport** (`src/transport.ts`, `HttpTransport`) —
  proxies `tools/call` JSON-RPC to remote MCP servers, parses both plain JSON
  and `text/event-stream` responses. Verified by `test/transport.test.ts`
  against a local throwaway HTTP server (offline).
- **Stdio transport** (`src/stdio.ts`, `StdioTransport`) — proxies JSON-RPC 2.0
  to a **real child MCP server process** (`node:child_process` spawn, no
  shell) using MCP stdio framing: newline-delimited JSON over the child's
  stdin/stdout. Implements the MCP lifecycle (`initialize` +
  `notifications/initialized`), request/response correlation by id,
  notification pass-through (`onNotification`), per-request timeouts,
  dead-child handling, and auto-`method not found` replies to server→client
  requests (e.g. sampling). Verified by `test/stdio.test.ts` against an
  in-repo fake MCP child (`test/fixtures/fake-mcp-child.ts`) — offline, no
  network, no external server.
- **Per-upstream transport selection** — a server's registered `endpoint`
  decides its transport: `stdio:<command> [args...]` (whitespace form) or
  `stdio:{"command":…,"args":[…]}` (JSON form, for args containing spaces) →
  stdio child; an http(s) URL → Streamable-HTTP. `MCP_TRANSPORT=http|stdio|auto`
  selects the executor (`auto` = per-endpoint `CompositeTransport`); unset keeps
  the offline mock. Documented in the README and `src/server.ts`.
- **No security bypass** — stdio traffic runs through the same
  `Gateway.toolsCall` pipeline as HTTP: registry → server/tool allowlist →
  policy engine → poisoning scan → secret injection → hash-chained audit. The
  transport is the executor *at the end* of that chain; `test/stdio.test.ts`
  asserts denied/poisoned/disallowed calls never spawn a child at all.

### What is still mocked / honest gaps

- The stdio tests use an **in-repo fake child** (`test/fixtures/fake-mcp-child.ts`),
  not a real third-party MCP server package (zero-runtime-deps and offline-test
  rules). Framing/lifecycle match the spec, but no interop run against a real
  published server has been done yet.
- Stdio children are spawned with the gateway's environment; there is **no
  per-tenant isolation** (no sandboxing, no cgroup/namespace, no dropped
  privileges) yet — pair with `agent-sandbox` for untrusted servers.
- **No child pool/restart policy**: one child per endpoint, lazily spawned,
  killed on transport close; crashed sessions are replaced on next call but
  there is no supervisor, backoff, or health probing.
- **No stdio-side `tools/list` discovery**: the registry remains the source of
  truth (tools are registered via `/admin/tools`); the child's `tools/list` is
  not yet crawled/merged or re-scanned for rug-pulls.
- HTTP transport has no session management (`Mcp-Session-Id`), resumability, or
  GET-stream listening — single-shot POST + optional SSE body only.

## Real MCP transport (remaining)
- **Egress enforcement** to server endpoints via a controlled network path.
- Crawl child/remote `tools/list` into the registry with poisoning re-scan on
  change (rug-pull detection hook).

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
