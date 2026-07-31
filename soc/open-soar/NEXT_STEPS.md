# Next Steps — open-soar

## Integrations (the heart of SOAR)
- Real **enrichment** connectors: VirusTotal, AbuseIPDB, Shodan, Whois,
  internal CMDB, threat intel (`opencti`/MISP).
- Real **response actions**: EDR isolation, firewall block, IdP user disable,
  email quarantine, ticketing (Jira/ServiceNow), paging.
- **Inbound ingestion**: SIEM/webhook/email parsers to auto-create cases.

## Playbooks
- **Visual playbook editor** and a playbook library/marketplace.
- **Conditional branching, loops, sub-playbooks**, and approvals/human-in-the-loop.
- **AI-assisted playbook generation** and an AI SOC analyst copilot.
- Versioning, testing, and dry-run/simulation mode.

## Cases & IR
- **DFIR timeline** with chain-of-custody and evidence signing.
- SLA tracking, metrics (MTTD/MTTR), and reporting.
- Map cases to frameworks via `ai-compliance-hub` (incident-response evidence).

## Platform
- Postgres persistence: gateway-backed **async repositories + migrations exist**
  (`src/pg_gateway.ts`, `src/repository.ts`, `migrations/`); next **wire them
  into `server.ts`** (migrate the sync call sites to the async interface) and
  exercise against a real PostgREST + Postgres. Then HA, RBAC, multi-tenant
  workspaces.
- OpenTelemetry tracing of playbook runs; queue-based workers.
- Integrate `agent-identity` so automated actions are authorized and audited,
  and `agent-sandbox` to safely run response scripts.
