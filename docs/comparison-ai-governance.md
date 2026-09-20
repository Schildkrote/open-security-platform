# Vendor Comparison — AI Governance

!!! warning "Not a drop-in replacement — yet"
    All components here are **self-contained MVPs** with mock/in-memory
    backends, tagged **v0.1-scaffold**. `ai-redteam-platform` (embedding
    `ai-redteam-evals`) and `ai-compliance-hub` are part of the spine-proven
    subset — the red-team → findings → compliance-evidence flow is exercised
    end-to-end by `make integration`. See the
    [maturity legend](comparison.md#maturity-legend).

| Component | Maturity | Comparable vendors / OSS | What it replaces for you |
|---|---|---|---|
| `ai-compliance-hub` | 🟨 Spine-proven subset (v0.1-scaffold) | **Commercial:** Vanta, Drata, Comp AI, Secureframe, Sprinto, Credo AI, Holistic AI | A compliance-automation SaaS subscription for AI governance: control library mapped to **EU AI Act, ISO 42001, NIST AI RMF, SOC 2**, risk register, model/system cards, and a hash-chained evidence trail you own. Evidence here is produced offline and by other components (e.g. red-team findings) rather than collected from your cloud accounts — collection connectors are the missing piece. |
| `ai-redteam-evals` | 🟥 Scaffold (v0.1-scaffold) | **OSS:** Garak (NVIDIA), promptfoo, PyRIT (Microsoft). **Commercial:** Mindgard, HiddenLayer, Robust Intelligence, modelaudit. **Benchmarks:** HarmBench, AdvBench | An eval harness dependency: attack library (injection, jailbreak, exfiltration, tool abuse, RAG poisoning, bias, hallucination) with scoring, regression, and reports — stdlib-only Python in the same shape as Garak/promptfoo/PyRIT. It embeds into `ai-redteam-platform` as its test engine. |
| `ai-redteam-platform` | 🟨 Spine-proven subset (v0.1-scaffold) | **OSS:** Garak (NVIDIA), promptfoo, PyRIT (Microsoft). **Commercial:** Mindgard, HiddenLayer, Robust Intelligence, modelaudit. **Benchmarks:** HarmBench, AdvBench | A managed AI red-teaming platform: target registry with an authorization gate, OWASP/ATLAS-mapped test library, safe runner, scoring, redacted evidence, compliance mapping, and reports — plus native flow of findings into `pentest-manager` and evidence into `ai-compliance-hub`, which none of the point tools do out of the box. |
