export interface Finding {
  kind: string;
  count: number;
}

const DETECTORS: Array<{ kind: string; re: RegExp }> = [
  { kind: "EMAIL", re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  { kind: "SSN", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { kind: "CREDIT_CARD", re: /\b(?:\d[ -]?){13,16}\b/g },
  { kind: "PHONE", re: /\b(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b/g },
  { kind: "OPENAI_KEY", re: /sk-[A-Za-z0-9]{20,}/g },
  { kind: "AWS_ACCESS_KEY", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "GITHUB_TOKEN", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { kind: "PRIVATE_KEY", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: "JWT", re: /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g },
];

export function redact(input: string): { output: string; findings: Finding[] } {
  let output = input;
  const findings: Finding[] = [];
  for (const { kind, re } of DETECTORS) {
    const matches = output.match(re);
    if (!matches) continue;
    findings.push({ kind, count: matches.length });
    output = output.replace(re, `[REDACTED:${kind}]`);
  }
  return { output, findings };
}
