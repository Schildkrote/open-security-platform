// SIEM alert ingestion for open-soar (Phase 4): push-based inbound. Accepts a
// generic alert or a Wazuh-style alert over POST /ingest and opens a case.
// (Pull-based ingestion from Wazuh lives in connectors.ts; this is the webhook
// side, e.g. for Wazuh active-response forwarding or any SIEM webhook.)

import type { DB } from "./db.ts";
import * as cases from "./cases.ts";

export interface NormalizedAlert {
  title: string;
  severity: string;
  alert: Record<string, unknown>;
}

function severityFromLevel(level: number): string {
  if (level >= 12) return "critical";
  if (level >= 7) return "high";
  return "medium";
}

// normalizeAlert accepts a generic alert ({title|name, severity, ...}) or a
// Wazuh alert ({rule: {description, level}, data: {srcip}, ...}).
export function normalizeAlert(body: Record<string, unknown>): NormalizedAlert {
  const rule = body.rule as { description?: string; level?: number } | undefined;
  if (rule) {
    return {
      title: rule.description ?? "Wazuh alert",
      severity: severityFromLevel(rule.level ?? 0),
      alert: body,
    };
  }
  return {
    title: (body.title as string) ?? (body.name as string) ?? "SIEM alert",
    severity: (body.severity as string) ?? "medium",
    alert: body,
  };
}

// ingestAlert opens a case from an inbound SIEM alert and returns it.
export function ingestAlert(db: DB, body: Record<string, unknown>): cases.Case {
  const norm = normalizeAlert(body);
  return cases.createCase(db, norm.title, {
    severity: norm.severity,
    alert: norm.alert,
    assignee: "siem",
  });
}
