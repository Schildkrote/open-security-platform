export interface PoisonSignal {
  kind: string;
  detail: string;
}

// Heuristic indicators of MCP tool poisoning / indirect prompt injection.
const TEXT_PATTERNS: Array<{ kind: string; re: RegExp }> = [
  { kind: "instruction_injection", re: /ignore (all )?(previous|prior|above) (instructions|prompts)/i },
  { kind: "role_spoofing", re: /\b(system|assistant)\s*:/i },
  { kind: "exfil_intent", re: /\b(exfiltrate|send .* to|post .* to|upload .* to)\b/i },
  { kind: "hidden_directive", re: /(do not tell the user|hide this|secretly|without revealing)/i },
  { kind: "credential_grab", re: /\b(api[_-]?key|secret|token|password|credentials?)\b.*\b(send|post|exfil|leak)/i },
];

const ZERO_WIDTH = /[\u200B-\u200D\uFEFF]/;
const BASE64_BLOB = /[A-Za-z0-9+/]{80,}={0,2}/;
const URL_RE = /https?:\/\/[^\s"'<>]+/g;

export function scanText(text: string, allowedDomains: string[] = []): PoisonSignal[] {
  const signals: PoisonSignal[] = [];
  for (const { kind, re } of TEXT_PATTERNS) {
    const m = text.match(re);
    if (m) signals.push({ kind, detail: m[0].slice(0, 80) });
  }
  if (ZERO_WIDTH.test(text)) signals.push({ kind: "zero_width_chars", detail: "hidden unicode" });
  const b64 = text.match(BASE64_BLOB);
  if (b64) signals.push({ kind: "encoded_payload", detail: b64[0].slice(0, 24) + "…" });
  for (const url of text.match(URL_RE) ?? []) {
    const host = new URL(url).hostname;
    const ok = allowedDomains.some((d) => host === d || host.endsWith("." + d));
    if (!ok) signals.push({ kind: "suspicious_url", detail: url.slice(0, 80) });
  }
  return signals;
}

// Scan a tool description (registration-time poisoning) or call arguments
// (runtime injection). Returns signals; caller decides threshold.
export function scanToolDescription(description: string, allowedDomains: string[] = []): PoisonSignal[] {
  return scanText(description, allowedDomains);
}

export function scanArguments(args: unknown, allowedDomains: string[] = []): PoisonSignal[] {
  return scanText(JSON.stringify(args ?? {}), allowedDomains);
}
