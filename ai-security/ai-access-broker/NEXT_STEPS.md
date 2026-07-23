# Next Steps — ai-access-broker

## Identity & SSO
- Replace the mock IdP with **real OIDC/SAML** (Entra, Okta, Google Workspace).
- **SCIM** provisioning to sync users/groups and drive auto-approval policies.
- Browser enforcement via a **browser extension** or **network proxy/PAC** so
  traffic actually flows through the broker (today the proxy is API-driven).

## Discovery & governance
- **Shadow AI discovery**: scan network/cloud/IdP logs to find unsanctioned AI apps.
- **OAuth app risk review** for connected AI integrations.
- Policy-as-code for auto-approval (risk, role, department, data class).

## DLP & data controls
- Swap regex redaction for **NER** (Presidio) and custom dictionaries.
- **Upload/file inspection** (documents sent to AI apps).
- Per-app **data-residency and retention** enforcement with real egress control.

## Spend & observability
- Real **token/cost metering** per user/team/project (FinOps for AI).
- OpenTelemetry traces + dashboards; alerting on anomalous usage.

## Platform
- Admin web UI for catalog, approvals, and usage.
- Multi-tenant policy, Postgres persistence, HA deployment.
- Integrate with `open-ai-gateway` (API-level) and `ai-compliance-hub`
  (evidence of access governance).
