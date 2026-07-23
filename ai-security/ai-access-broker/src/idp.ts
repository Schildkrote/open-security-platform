import { randomUUID } from "node:crypto";
import { sign, type Claims } from "./jwt.ts";

// Minimal in-memory authorization-code store for the mock IdP.
const codes = new Map<string, { email: string; role: string; exp: number }>();

export function issueCode(email: string, role: string): string {
  const code = randomUUID();
  codes.set(code, { email, role, exp: Date.now() + 60_000 });
  return code;
}

export function exchangeCode(code: string): { id_token: string; claims: Claims } {
  const entry = codes.get(code);
  if (!entry) throw new Error("invalid code");
  codes.delete(code);
  if (entry.exp < Date.now()) throw new Error("code expired");
  const claims: Claims = {
    sub: entry.email,
    email: entry.email,
    role: entry.role,
    aud: "ai-access-broker",
  };
  return { id_token: sign(claims), claims };
}
