# Next Steps — agent-redteam-range

## More targets
- **Browser agent** (unsafe navigation/form/payment abuse) using a headless browser.
- **Computer-use / desktop agent** in a virtual desktop sandbox.
- **Voice agent** (vishing/consent abuse) and **multi-agent** collusion scenarios.
- **Vector database** extraction/poisoning target and a **CI/CD** pipeline target.

## Realism
- Back the chatbot/RAG/agent with a real (local) LLM (e.g. Ollama) so behavior
  is model-driven rather than rule-driven, while keeping deterministic flags.
- Realistic tool schemas (OpenAI function-calling / MCP JSON-RPC) so
  `mcp-security-gateway` and `ai-redteam-platform` can speak native protocols.

## Range infrastructure
- Per-challenge **scoring/flag submission** endpoint (AI CTF mode).
- **Docker/Kubernetes** orchestration with disposable, auto-resetting labs.
- Difficulty tiers, hints, and a guided curriculum.

## Integration
- Wire each app as a first-class target type in `ai-redteam-platform`.
- Emit detection telemetry to `purple-team` to validate guardrails fire.

## Safety
- Add a prominent acceptable-use banner and a runtime guard that refuses to
  bind to non-loopback interfaces.
