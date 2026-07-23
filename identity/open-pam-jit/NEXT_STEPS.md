# Next Steps — open-pam-jit

## Real target integrations
- **SSH**: mint per-session certificates or rotate local accounts; record real
  sessions (PTY) with keystroke logging.
- **Databases**: dynamic credentials (Postgres/MySQL temporary users).
- **Cloud**: short-lived IAM roles/STS tokens for AWS/GCP/Azure.
- **Kubernetes**: ephemeral RBAC bindings and exec auditing.

## Cryptography & key management
- Store the vault key in a **KMS/HSM**; use a random per-deployment salt.
- **Secret rotation** and dynamic credential generation per target.
- Asymmetric signing of credentials; mTLS for the broker API.

## Governance
- **Approval policies** by target risk, requester role, and time window.
- **Access reviews** and entitlement analytics; standing-access reduction.
- **Break-glass review** workflow with mandatory post-incident sign-off.
- Authentication via `agent-identity` / OIDC instead of free-form names.

## Session & audit
- Real **session recording** (asciinema-style) with replay and redaction.
- Stream audit + recordings to `open-soar` / SIEM.
- Emit evidence to `ai-compliance-hub` (privileged-access controls).

## Platform
- Postgres persistence, HA, multi-tenant workspaces, admin UI.
- gRPC/SDK for programmatic JIT access from CI/CD and agents.
