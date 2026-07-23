# AI Governance

AI GRC, compliance evidence, and red teaming.

| Component | Lang | Description |
|---|---|---|
| `ai-governance/ai-compliance-hub` | Python | AI compliance evidence hub: control library mapped to EU AI Act / NIST AI RMF / ISO 42001 / SOC 2, risk register, model/system cards, and a hash-chained evidence trail. |
| `ai-governance/ai-redteam-evals` | Python | AI red-team eval harness: attack library (injection, jailbreak, exfiltration, tool abuse, RAG poisoning, bias, hallucination), scoring, regression, and reports. |
| `ai-governance/ai-redteam-platform` | Python | AI red-team platform: target registry + authorization gate, OWASP/ATLAS-mapped test library, safe runner, scoring, redacted evidence, compliance mapping, and reports. Embeds `ai-redteam-evals`. |

See each component's `README.md` and `NEXT_STEPS.md` in the repository.
