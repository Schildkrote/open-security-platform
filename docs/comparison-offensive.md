# Vendor Comparison — Offensive

!!! warning "Not a drop-in replacement — yet"
    All components here are **self-contained MVPs** with mock/in-memory
    backends, tagged **v0.1-scaffold**. `pentest-manager` is part of the
    spine-proven subset (findings ingest is exercised end-to-end by
    `make integration`); the others are not. OSINT components
    (`live-recon`, `username-enum`, `credential-intel`) are mock/offline by
    default and only touch the network behind explicit `--live` gates with
    scope, consent, and audit requirements. See the
    [maturity legend](comparison.md#maturity-legend).

| Component | Maturity | Comparable vendors / OSS | What it replaces for you |
|---|---|---|---|
| `pentest-manager` | 🟨 Spine-proven subset (v0.1-scaffold) | **Commercial:** DefectDojo (commercial support), PlexTrac, Dradis, Faraday, Archery, CIRT. **OSS:** DefectDojo, Faraday, Archery | A pentest management platform: clients/engagements, scope & ROE authorization gate with kill switch, findings enriched with CVSS/EPSS/KEV prioritization, evidence vault with chain of custody, reports, retests, and a client portal — self-hosted, with native ingest of AI red-team findings from the spine. |
| `purple-team` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** AttackIQ, SafeBreach, Cymulate. **OSS:** Atomic Red Team, MITRE CALDERA, Vectr | A BAS (breach-and-attack-simulation) platform or manual coverage-tracking spreadsheet: ATT&CK technique library, safe test cases, detection coverage matrix, mock SIEM, gap analysis + recommendations, and exercise timeline — the Vectr-shaped OSS slot, with CALDERA-style tests as data rather than an execution framework. |
| `attack-path` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** BloodHound Enterprise, XM Cyber, Tenable.cs, Wiz, Orca, Horizon3 nodezero. **OSS:** BloodHound, Prowler, Cartography | A CNAPP/attack-path-management subscription for graph-based exposure analysis: graph engine, exposure → critical path finding, risk scoring, choke-point/remediation analysis, JSON/Graphviz output, plus Shodan dork ingestion, geo enrichment, and passive domain intelligence. Compared to BloodHound it is multi-source rather than AD-only; today the graph is fed by mocks/fixtures. |
| `live-recon` | 🟥 Scaffold (v0.1-scaffold, `--live`-gated) | **OSS:** Sherlock, Maigret, holehe, theHarvester, recon-ng, SpiderFoot. **Commercial:** Have I Been Pwned, Dehashed, Intelligence X, Flare, Hudson Rock, Maltego, ShadowDragon, SpiderFoot HX | A suite of separate OSINT tools: active scanning, account-recovery probing, people search, and authenticated scraping behind one policy gate (`--live <feature>`), with explicit scope/consent requirements, rate limits, redacted PII, and a tamper-evident audit log per run — the compliance wrapper the individual tools lack. Mock by default. |
| `username-enum` | 🟥 Scaffold (v0.1-scaffold, `--live`-gated) | **OSS:** Sherlock, Maigret, holehe. **Commercial:** Maltego, ShadowDragon | Sherlock/Maigret-style username enumeration across a service catalog, with differential probing and audit logging under the `--live recovery-probing` policy gate instead of ad-hoc scripts. Mock by default. |
| `credential-intel` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** Have I Been Pwned, Dehashed, Intelligence X, Flare, Hudson Rock | Paid breach-intel API subscriptions for basic lookups: HIBP k-anonymity pwned-password/email checks plus offline breach-dump corpora support, with no PII leaving the machine on the k-anon path. |
| `agent-redteam-range` | 🟥 Scaffold (v0.1-scaffold) | **OSS/demos:** OWASP LLM Top 10 demos, Damn Vulnerable LLM Agent, Gandalf (Lakera), LLM-attacks ranges. **Training-range analog:** DVWA / OWASP Juice Shop for web | Hosting your own deliberately-vulnerable AI targets: chatbot, RAG, MCP, agent, and codegen apps that are vulnerable by design for testing and training — the DVWA/Juice Shop of the LLM/agent world. Localhost-only, fake secrets, never deploy publicly. |
