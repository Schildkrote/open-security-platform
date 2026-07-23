# Next Steps — agent-identity

## Cryptography & trust
- Use **asymmetric signing** (Ed25519/ECDSA) and publish a **JWKS** so other
  services can verify tokens without the shared secret.
- **mTLS / SPIFFE** identities for agent-to-agent authentication.
- Bound tokens to a context (audience, client IP, tool) to prevent replay.

## Policy & governance
- **Policy engine** (OPA/Cedar) for who can request/issue which scopes.
- **Delegation depth limits** and time-boxed chains.
- **Approval policies** by risk level, owner, and requested scope.
- Integration with `mcp-security-gateway` and `open-ai-gateway` so tool/API
  calls are authorized against these tokens.

## Lifecycle
- **Credential rotation**, token binding to sessions, and automatic expiry.
- **Agent reputation** scoring fed by telemetry/audit.
- **Service account fencing**: detect and reduce standing privileges.

## Platform
- Postgres persistence, HA, multi-tenant workspaces.
- Admin UI for agents, grants, requests, and audit.
- SCIM/IdP sync to tie agents to human owners and teams.
- Emit evidence to `ai-compliance-hub` (non-human identity governance).
