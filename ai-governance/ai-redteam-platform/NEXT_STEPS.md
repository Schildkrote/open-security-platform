# Next Steps — ai-redteam-platform

## Test coverage
- Expand the library: multilingual/encoded injections, multi-turn and many-shot
  jailbreaks, RAG poisoning, MCP tool poisoning, agent memory poisoning,
  cost/DoS amplification, insecure codegen, copyright/license, brand safety.
- **Automated attack generation** (mutation/fuzzing, GCG-style suffixes).
- Pull the latest **OWASP LLM Top 10 / Agentic AI / MITRE ATLAS** mappings.

## Targets & execution
- Adapters for real model providers and for **agents** (run tool calls inside
  `agent-sandbox`).
- Test **RAG pipelines** (`rag-authorization`) and **MCP servers**
  (`mcp-security-gateway`) end-to-end as first-class target types.
- Distributed, rate-limited workers; async campaign scheduling.

## Detection & purple teaming
- Validate that guardrails/AI-gateway/SIEM **detect** each attack; feed results
  to `purple-team` for coverage gaps.

## Evidence & governance
- Object-storage evidence with KMS encryption, RBAC, and client isolation.
- Signed reports; export findings to `pentest-manager` and evidence to
  `ai-compliance-hub` (EU AI Act / ISO 42001 testing evidence).
- Retries for reproducibility scoring; confidence calibration with LLM-as-judge.

## Platform
- Web UI, Postgres backend, multi-tenant workspaces, CI integration that fails
  builds on regressions (reuse `ai-redteam-evals` baselines).
