# open-ai-gateway

A self-hosted **AI / Agent Gateway + Firewall**: a reverse proxy that sits in
front of your LLM, agent, and tool traffic and enforces policy, redaction,
rate limits, budgets, and audit — with zero external dependencies.

This is a clean-room, open-source wedge toward a full AI security control
plane (agent identity, sandboxing, DLP, compliance, red-teaming).

## Features (MVP)

- **Reverse proxy** for OpenAI-compatible `/v1/chat/completions` traffic
- **Policy engine**: ordered rules matching model, content regex, and caller
  API key → `allow` / `deny` / `redact`
- **PII + secret redaction** on request *and* response bodies (email, phone,
  SSN, credit card, OpenAI/AWS/GitHub/Slack keys, private keys, JWTs, IPs)
- **Rate limiting** (requests/minute) and **spend budgets** (tokens + dollars)
- **Tool / MCP registry** with risk ratings and allow/deny state
- **Tamper-evident audit log** (hash-chained JSONL)
- **Offline mock upstream** so it runs end-to-end with no network access

## Quickstart

```bash
# Run with defaults (mock upstream, listens on :8080)
go run .

# Or with a config file
go run . -config examples/config.json
```

Send a request:

```bash
curl -s localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: demo' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"my email is jane.doe@example.com"}]}'
```

The response echoes the prompt with the email redacted:
`"echo: my email is [REDACTED:EMAIL]"`.

Admin:

```bash
curl -s localhost:8080/admin/tools                       # list registry
curl -s localhost:8080/admin/tools -d '{"name":"web-search","kind":"mcp","risk":"low","allowed":true}'  # register
curl -s localhost:8080/healthz
```

## Architecture

```
client ──> Gateway.ServeHTTP
             ├─ policy.Engine.Evaluate   (allow/deny/redact)
             ├─ ratelimit.Limiter        (req/min + token/$ budget)
             ├─ redact.Redact            (request body)
             ├─ forward to upstream (real or mock)
             ├─ redact.Redact            (response body)
             ├─ ratelimit.RecordUsage    (usage accounting)
             └─ audit.Logger.Log         (hash-chained JSONL)
```

| Package | Responsibility |
|---|---|
| `internal/proxy` | Request pipeline / `http.Handler` |
| `internal/policy` | Rule engine |
| `internal/redact` | PII/secret detectors |
| `internal/ratelimit` | Rate + budget limiter |
| `internal/registry` | Tool/MCP registry |
| `internal/audit` | Hash-chained JSONL audit log |
| `internal/mockupstream` | Offline LLM stand-in |
| `internal/config` | JSON config loading |

## Tests

```bash
go test ./...
```

## License

AGPL-3.0-only
