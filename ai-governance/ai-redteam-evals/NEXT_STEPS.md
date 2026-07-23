# Next Steps — ai-redteam-evals

## Attack coverage
- Expand the library: multilingual injections, encoded/obfuscated payloads,
  multi-turn attacks, role-play jailbreaks, many-shot jailbreaking.
- **Automated attack generation** (fuzzing prompts, GCG-style suffixes, mutation).
- **Agent-specific attacks**: tool abuse, multi-step exfiltration, memory
  poisoning, A2A trust abuse.

## Detection quality
- Replace keyword detectors with **LLM-as-judge** and trained classifiers.
- **Semantic leak detection** (paraphrased PII/secrets) and bias scoring.
- Confidence calibration and false-positive review workflow.

## Targets & integration
- Adapters for OpenAI/Anthropic/local models and for **agents** (run tool calls
  in `agent-sandbox`).
- Test **RAG pipelines** end-to-end with `rag-authorization` corpora.
- Test **MCP tools** via `mcp-security-gateway`.

## Platform
- CI integration: fail builds on regressions; schedule continuous red-teaming.
- Results store, dashboards, and mapping findings to controls in
  `ai-compliance-hub` (red-team evidence repository).
- Parallel execution, rate limiting, cost tracking.
