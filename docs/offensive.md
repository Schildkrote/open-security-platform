# Offensive

Red teaming, penetration testing, purple teaming, attack path analysis, and
OSINT — built for **authorized testing** with safety and auditability by
design.

| Component | Lang | Description |
|---|---|---|
| `offensive/pentest-manager` | Node/TS | Pentest management: clients/engagements, scope & ROE authorization gate + kill switch, findings (CVSS/EPSS/KEV + prioritization), evidence vault with chain of custody, reports, retests, and a client portal. |
| `offensive/purple-team` | Python | Purple team platform: ATT&CK technique library, safe test cases, detection coverage matrix, mock SIEM, gap analysis + recommendations, and exercise timeline. |
| `offensive/attack-path` | Go | Attack path management: graph engine, exposure→critical path finding, risk scoring, choke-point/remediation analysis, JSON/Graphviz output. Now with **Shodan dork** ingestion, **geo enrichment** (IP/phone), and **passive domain intelligence** (offline tables by default). |
| `offensive/agent-redteam-range` | Python | Agent red team range: intentionally vulnerable-by-design AI apps (chatbot, RAG, MCP, agent, codegen) for testing and training. Localhost-only, fake secrets. |
| `offensive/username-enum` | Go | Username enumeration across a service catalog (mock + live HTTP differential probing). |
| `offensive/credential-intel` | Go | Breach / credential-dump lookups (HIBP k-anonymity + offline mock). |
| `offensive/live-recon` | Go | The four `--live`-gated recon features: active scanning, recovery probing, people search, authenticated scraping. Mock by default; live behind `-live <feature> -real`. |

See each component's `README.md` and `NEXT_STEPS.md` in the repository.

The full **OSINT source taxonomy** (people, breach, account, network, geo
categories and which component owns each) is in [OSINT Taxonomy](osint.md).