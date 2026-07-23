export type Decision = "allow" | "deny" | "approve";

export interface Rule {
  name: string;
  toolPattern?: string; // regex against tool name
  argPattern?: string; // regex against JSON-serialized arguments
  decision: Decision;
  reason?: string;
}

export interface PolicyResult {
  decision: Decision;
  rule?: string;
  reason?: string;
}

export class PolicyEngine {
  rules: Rule[];
  defaultDecision: Decision;

  constructor(rules: Rule[], defaultDecision: Decision = "allow") {
    this.rules = rules;
    this.defaultDecision = defaultDecision;
  }

  evaluate(tool: string, args: unknown): PolicyResult {
    const argStr = JSON.stringify(args ?? {});
    for (const r of this.rules) {
      if (r.toolPattern && !new RegExp(r.toolPattern).test(tool)) continue;
      if (r.argPattern && !new RegExp(r.argPattern).test(argStr)) continue;
      return { decision: r.decision, rule: r.name, reason: r.reason };
    }
    return { decision: this.defaultDecision };
  }
}
