export interface TriageInput {
  title?: string;
  description?: string;
  [k: string]: unknown;
}

export interface TriageResult {
  severity: "low" | "medium" | "high" | "critical";
  classification: string;
  confidence: number;
  rationale: string;
}

export type TriageFn = (input: TriageInput) => TriageResult;

const RULES: Array<{ re: RegExp; classification: string; severity: TriageResult["severity"]; weight: number }> = [
  { re: /\b(ransomware|data exfil|breach|apt)\b/i, classification: "intrusion", severity: "critical", weight: 0.95 },
  { re: /\b(malware|trojan|c2|beacon)\b/i, classification: "malware", severity: "high", weight: 0.85 },
  { re: /\b(phishing|bec|impersonation)\b/i, classification: "phishing", severity: "medium", weight: 0.7 },
  { re: /\b(brute ?force|credential stuffing|failed logins)\b/i, classification: "credential_attack", severity: "high", weight: 0.8 },
  { re: /\b(policy|misconfig|compliance)\b/i, classification: "policy", severity: "low", weight: 0.5 },
];

// heuristicTriage is an offline stand-in for an AI SOC analyst. Swap in a real
// model by providing a custom TriageFn to the playbook engine.
export const heuristicTriage: TriageFn = (input) => {
  const text = `${input.title ?? ""} ${input.description ?? ""}`;
  let best: (typeof RULES)[number] | null = null;
  for (const rule of RULES) {
    if (rule.re.test(text) && (!best || rule.weight > best.weight)) best = rule;
  }
  if (!best) {
    return { severity: "low", classification: "unclassified", confidence: 0.3, rationale: "no strong signals" };
  }
  return {
    severity: best.severity,
    classification: best.classification,
    confidence: best.weight,
    rationale: `matched signal: ${best.re.source}`,
  };
};
