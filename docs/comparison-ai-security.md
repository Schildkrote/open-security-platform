# Vendor Comparison — AI Security

!!! warning "Not a drop-in replacement — yet"
    All components here are **self-contained MVPs** with mock/in-memory
    backends, tagged **v0.1-scaffold**. `agent-sandbox` is part of the
    spine-proven subset (confined execution is exercised end-to-end by
    `make integration`); the others are not. See the
    [maturity legend](comparison.md#maturity-legend).

| Component | Maturity | Comparable vendors / OSS | What it replaces for you |
|---|---|---|---|
| `open-ai-gateway` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** LiteLLM, Portkey, Kong AI Gateway, Cloudflare AI Gateway, Envoy AI Gateway, Martian. **OSS:** LiteLLM proxy | A hosted LLM gateway/firewall SaaS: policy enforcement, PII/secret redaction, rate limits & budgets, tool registry, and hash-chained audit on every request — self-hosted. For LiteLLM proxy it adds firewall-style policy + tamper-evident audit; today at reference-implementation depth. |
| `mcp-security-gateway` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** Lasso Security, Invariant Labs, Docker MCP Gateway/Toolkit, Cloudflare MCP portal, Oso. **Emerging OSS:** mcp-proxy, mcp-guardian | An MCP security layer: tool registry with allowlists, policy, secret injection, egress filtering, and tool-poisoning detection between your agents and MCP servers. The category is young — this is an OSS entry point, not a parity product. |
| `rag-authorization` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** Oso, Permit.io, Cerbos, AuthZed/SpiceDB, OpenFGA, Varonis (data-side), Microsoft Purview DSPM for AI | Document-level authorization for RAG: ACL retrieval filtering, sensitivity labels, automatic classification, and overexposure detection — so the retriever cannot leak documents the asking principal may not see. Unlike general policy engines (OpenFGA/Cerbos), it is retrieval-pipeline-shaped; unlike DSPM tools, it enforces at query time. |
| `agent-sandbox` | 🟨 Spine-proven subset (v0.1-scaffold) | **Commercial:** E2B, Daytona, Modal, Cloudflare Workers/Sandbox. **OSS isolation tech:** gVisor, Firecracker, Kata Containers | A hosted agent-execution cloud (E2B/Daytona/Modal): confined fs/net/shell with resource limits, session recording, and snapshot/rollback, self-hosted. Note: it is a Python confinement layer — it does not (yet) wrap kernel-level isolators like gVisor/Firecracker/Kata. |
| `ai-access-broker` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** Okta / AI access governance, Microsoft Entra AI access, Zscaler AI, Netskope AI CASB, Harmony (Check Point), Prompt Security | An employee-AI-access gateway: SSO into an approved AI app catalog, approval workflows, DLP/redaction proxy, data-residency controls, and usage/spend tracking — instead of bolt-on AI CASB features on an existing SASE stack. |
