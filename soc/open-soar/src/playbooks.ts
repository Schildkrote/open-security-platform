import type { Playbook } from "./playbook.ts";

// A sample phishing-response playbook demonstrating the DAG engine:
// triage runs first; enrichment runs in parallel; response actions depend on
// the enrichment/triage results.
export const phishingPlaybook: Playbook = {
  id: "pb-phishing",
  name: "phishing-response",
  steps: [
    { id: "triage", type: "ai.triage" },
    { id: "enrich_ip", type: "enrich.ip" },
    { id: "enrich_user", type: "enrich.user" },
    { id: "block_ip", type: "action.block_ip", deps: ["enrich_ip"] },
    { id: "disable_user", type: "action.disable_user", params: { user: "suspect" }, deps: ["enrich_user"] },
    { id: "ticket", type: "action.create_ticket", params: { summary: "Phishing response" }, deps: ["triage"] },
  ],
};

export const PLAYBOOKS: Record<string, Playbook> = {
  [phishingPlaybook.id]: phishingPlaybook,
};
