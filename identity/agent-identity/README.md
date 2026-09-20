# agent-identity

Open **Agent Identity & Permissions**: give AI agents unique identities and
issue them scoped, short-lived credentials with delegation, just-in-time (JIT)
elevation, approvals, and revocation. Zero runtime dependencies
(Node 22 stdlib + `node:sqlite` + `node:crypto`).

## Features (MVP)

- **Agent registry** with owners, types, base scopes, and active/disabled status
- **Scoped signed tokens** (JWT HS256) — requested scopes are always capped to
  the agent's effective scopes
- **Delegation chains** — an agent can delegate to another agent; scopes can
  only be *narrowed*, and the chain is recorded in the `act` claim
- **JIT permissions** — temporary scope grants with expiry
- **Approval workflow** — request elevated scopes → approve → auto-grant
- **Revocation** — revoke a token by `jti`; verification checks the list
- **Agent-to-agent auth** — verify tokens presented by other agents
- **Audit log** of all identity events

## Quickstart

```bash
npm start   # listens on :8083
```

```bash
# Register an agent
curl -X POST localhost:8083/agents -d '{"id":"agent-a","name":"A","base_scopes":["read","search"]}'

# Issue a scoped token
curl -X POST localhost:8083/tokens -d '{"agent_id":"agent-a","on_behalf_of":"user@x.com"}'

# Delegate to another agent (scopes narrow automatically)
curl -X POST localhost:8083/tokens/delegate -d '{"token":"<TOKEN>","to_agent_id":"agent-b"}'

# Verify a token
curl -X POST localhost:8083/tokens/verify -d '{"token":"<TOKEN>"}'

# JIT elevation: request -> approve -> new scope becomes usable
curl -X POST localhost:8083/elevation-requests -d '{"agent_id":"agent-b","scopes":["deploy"]}'
curl -X POST localhost:8083/elevation-requests/<ID>/approve -d '{"approver":"admin"}'

# Revoke
curl -X POST localhost:8083/tokens/revoke -d '{"jti":"<JTI>","reason":"compromised"}'
```

## Tests

```bash
npm test
```

## License

AGPL-3.0-only
