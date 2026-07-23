# Offensive

Red teaming, penetration testing, purple teaming, and attack path analysis —
built for **authorized testing** with safety and auditability by design.

| Component | Lang | Description |
|---|---|---|
| `offensive/pentest-manager` | Node/TS | Pentest management: clients/engagements, scope & ROE authorization gate + kill switch, findings (CVSS/EPSS/KEV + prioritization), evidence vault with chain of custody, reports, retests, and a client portal. |
| `offensive/purple-team` | Python | Purple team platform: ATT&CK technique library, safe test cases, detection coverage matrix, mock SIEM, gap analysis + recommendations, and exercise timeline. |
| `offensive/attack-path` | Go | Attack path management: graph engine, exposure→critical path finding, risk scoring, choke-point/remediation analysis, and JSON/Graphviz output. |
| `offensive/agent-redteam-range` | Python | Agent red team range: intentionally vulnerable-by-design AI apps (chatbot, RAG, MCP, agent, codegen) for testing and training. Localhost-only, fake secrets. |

See each component's `README.md` and `NEXT_STEPS.md` in the repository.
