import type { DB } from "./db.ts";

const PLACEHOLDER = /\{\{\s*secret:([A-Za-z0-9_\-]+)\s*\}\}/g;

export function setSecret(db: DB, name: string, value: string): void {
  db.prepare(`INSERT OR REPLACE INTO secrets (name,value) VALUES (?,?)`).run(name, value);
}

export function getSecret(db: DB, name: string): string | undefined {
  const row = db.prepare(`SELECT value FROM secrets WHERE name=?`).get(name) as
    | { value: string }
    | undefined;
  return row?.value;
}

export interface InjectionResult {
  args: unknown;
  injected: string[];
  missing: string[];
}

// injectSecrets replaces {{secret:NAME}} placeholders in string values of the
// arguments with server-side secret values. Secrets never come from the client.
export function injectSecrets(db: DB, args: unknown): InjectionResult {
  const injected: string[] = [];
  const missing: string[] = [];

  const walk = (node: unknown): unknown => {
    if (typeof node === "string") {
      return node.replace(PLACEHOLDER, (_m, name: string) => {
        const val = getSecret(db, name);
        if (val === undefined) {
          missing.push(name);
          return "";
        }
        injected.push(name);
        return val;
      });
    }
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node)) out[k] = walk(v);
      return out;
    }
    return node;
  };

  return { args: walk(args), injected: [...new Set(injected)], missing: [...new Set(missing)] };
}
