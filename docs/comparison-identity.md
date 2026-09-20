# Vendor Comparison — Identity

!!! warning "Not a drop-in replacement — yet"
    Both components are **self-contained MVPs** with mock/in-memory backends,
    tagged **v0.1-scaffold**. `open-pam-jit` is part of the spine-proven
    subset (JIT credential brokering is exercised end-to-end by
    `make integration`); `agent-identity` is not. See the
    [maturity legend](comparison.md#maturity-legend).

## identity/open-pam-jit — PAM / JIT access broker

Access requests, approvals, temporary credentials, encrypted secrets vault,
break-glass, and session recording.

| Component | Maturity | Comparable vendors / OSS | What it replaces for you |
|---|---|---|---|
| `open-pam-jit` | 🟨 Spine-proven subset (v0.1-scaffold) | **Commercial:** Teleport, CyberArk, Delinea/Thycotic, One Identity Safeguard, Britive, Oasis Security, Sonrai. **OSS:** Teleport Community, AWS SSM / Vault SSH cert signing | A heavyweight PAM suite for *just-in-time* access: request → approve → temporary credential → recorded session, self-hosted and auditable — once its store moves beyond in-memory. Today: a reference implementation and starting point, not a PAM replacement. |

## identity/agent-identity — agent identity & permissions

Agent registry, scoped JWT, delegation chains, JIT permissions, approvals,
revocation, and agent-to-agent auth.

| Component | Maturity | Comparable vendors / OSS | What it replaces for you |
|---|---|---|---|
| `agent-identity` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** Astrix, Aembit, Token Security, Auth0 for AI Agents, Okta AI agents. **OSS:** SPIFFE/SPIRE, OAuth 2.1 token exchange | An emerging non-human/agent identity platform: scoped tokens with delegation chains and revocation for AI agents. For SPIFFE/SPIRE it is a lighter, JWT-first alternative aimed at agent-to-agent auth rather than workload attestation. |
