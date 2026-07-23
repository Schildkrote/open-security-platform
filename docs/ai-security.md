# AI Security

Runtime security for LLMs, agents, RAG, and MCP.

| Component | Lang | Description |
|---|---|---|
| `ai-security/open-ai-gateway` | Go | LLM/agent gateway + firewall: reverse proxy with policy engine, PII/secret redaction, rate limits & budgets, tool/MCP registry, and hash-chained audit. |
| `ai-security/ai-access-broker` | Node/TS | Employee AI access broker: SSO, app catalog, approval workflows, DLP/redaction proxy, data-residency controls, and usage/spend tracking. |
| `ai-security/mcp-security-gateway` | Node/TS | MCP security gateway: JSON-RPC proxy with tool registry, allowlists, policy, secret injection, egress filtering, and tool-poisoning detection. |
| `ai-security/rag-authorization` | Python | RAG authorization engine: document-level ACL retrieval filtering, sensitivity labels, automatic classification, and overexposure detection. |
| `ai-security/agent-sandbox` | Python | Agent runtime sandbox: confined filesystem/network/shell, resource limits, session recording, and snapshot/rollback. |

See each component's `README.md` and `NEXT_STEPS.md` in the repository.
