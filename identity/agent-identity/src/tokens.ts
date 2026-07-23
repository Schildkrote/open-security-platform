import type { DB } from "./db.ts";
import { sign, decode, type TokenClaims, type Actor } from "./jwt.ts";
import { getAgent } from "./registry.ts";
import { audit } from "./audit.ts";

const DEFAULT_TTL = 900; // 15 minutes (JIT-friendly)

function activeGrantScopes(db: DB, agentId: string): string[] {
  const rows = db
    .prepare(`SELECT scopes FROM grants WHERE agent_id=? AND expires_at > datetime('now')`)
    .all(agentId) as Array<{ scopes: string }>;
  const scopes = new Set<string>();
  for (const r of rows) for (const s of JSON.parse(r.scopes) as string[]) scopes.add(s);
  return [...scopes];
}

// effectiveScopes = agent base scopes + active JIT grants.
export function effectiveScopes(db: DB, agentId: string): string[] {
  const agent = getAgent(db, agentId);
  const base = agent?.base_scopes ?? [];
  return [...new Set([...base, ...activeGrantScopes(db, agentId)])];
}

export interface IssueOptions {
  scopes?: string[]; // requested subset; defaults to all effective scopes
  ttl?: number;
  onBehalfOf?: string;
}

export function issueToken(db: DB, agentId: string, opts: IssueOptions = {}): string {
  const agent = getAgent(db, agentId);
  if (!agent) throw new Error("unknown agent");
  if (agent.status !== "active") throw new Error("agent not active");

  const effective = effectiveScopes(db, agentId);
  const requested = opts.scopes ?? effective;
  const scopes = requested.filter((s) => effective.includes(s)); // never exceed effective

  const token = sign(
    { sub: agentId, scopes, on_behalf_of: opts.onBehalfOf },
    opts.ttl ?? DEFAULT_TTL,
  );
  audit(db, "token_issued", agentId, { scopes, on_behalf_of: opts.onBehalfOf });
  return token;
}

// delegateToken issues a token for toAgent that acts under the parent token's
// authority. Scopes can only be narrowed, never widened, and the delegation
// chain is recorded in the `act` claim.
export function delegateToken(
  db: DB,
  parentToken: string,
  toAgentId: string,
  opts: IssueOptions = {},
): string {
  const parent = verifyToken(db, parentToken);
  const target = getAgent(db, toAgentId);
  if (!target) throw new Error("unknown delegate agent");
  if (target.status !== "active") throw new Error("delegate agent not active");

  const targetEffective = effectiveScopes(db, toAgentId);
  const requested = opts.scopes ?? parent.scopes;
  // Intersection of parent scopes, requested, and delegate's own effective scopes.
  const scopes = requested.filter(
    (s) => parent.scopes.includes(s) && targetEffective.includes(s),
  );

  const act: Actor = { sub: parent.sub, act: parent.act };
  const token = sign(
    { sub: toAgentId, scopes, on_behalf_of: parent.on_behalf_of, act },
    opts.ttl ?? DEFAULT_TTL,
  );
  audit(db, "token_delegated", toAgentId, { from: parent.sub, scopes });
  return token;
}

export function grantJIT(
  db: DB,
  agentId: string,
  scopes: string[],
  ttlSeconds: number,
  approvedBy?: string,
): { id: string; expires_at: string } {
  const id = crypto.randomUUID();
  const expires = new Date(Date.now() + ttlSeconds * 1000).toISOString().replace("T", " ").slice(0, 19);
  db.prepare(
    `INSERT INTO grants (id,agent_id,scopes,expires_at,approved_by) VALUES (?,?,?,?,?)`,
  ).run(id, agentId, JSON.stringify(scopes), expires, approvedBy ?? null);
  audit(db, "jit_grant", agentId, { scopes, expires_at: expires });
  return { id, expires_at: expires };
}

export function revoke(db: DB, jti: string, reason?: string): void {
  db.prepare(`INSERT OR IGNORE INTO revocations (jti,reason) VALUES (?,?)`).run(
    jti,
    reason ?? null,
  );
  audit(db, "token_revoked", undefined, { jti, reason });
}

export function isRevoked(db: DB, jti: string): boolean {
  return !!db.prepare(`SELECT 1 FROM revocations WHERE jti=?`).get(jti);
}

// verifyToken validates signature, expiry, revocation, and agent status.
export function verifyToken(db: DB, token: string): TokenClaims {
  const claims = decode(token); // throws on bad sig / expiry
  if (claims.jti && isRevoked(db, claims.jti)) throw new Error("token revoked");
  const agent = getAgent(db, claims.sub);
  if (!agent) throw new Error("unknown agent");
  if (agent.status !== "active") throw new Error("agent not active");
  return claims;
}

export function hasScope(claims: TokenClaims, scope: string): boolean {
  return claims.scopes.includes(scope);
}

// delegationDepth counts how many agents are in the act chain.
export function delegationDepth(claims: TokenClaims): number {
  let depth = 0;
  let act = claims.act;
  while (act) {
    depth += 1;
    act = act.act;
  }
  return depth;
}
