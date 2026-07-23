import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";

const SECRET = process.env.AGENT_ID_SECRET ?? "dev-secret-change-me";

const b64url = (b: Buffer | string): string => Buffer.from(b).toString("base64url");

export interface Actor {
  sub: string;
  act?: Actor;
}

export interface TokenClaims {
  sub: string; // agent id
  scopes: string[];
  on_behalf_of?: string; // user the agent acts for
  act?: Actor; // delegation chain
  iss?: string;
  iat?: number;
  exp?: number;
  jti?: string;
}

export function sign(claims: TokenClaims, ttlSeconds: number): string {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload: TokenClaims = {
    iss: "agent-identity",
    iat: now,
    exp: now + ttlSeconds,
    jti: randomUUID(),
    ...claims,
  };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createHmac("sha256", SECRET).update(enc).digest("base64url");
  return `${enc}.${sig}`;
}

export function decode(token: string): TokenClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [h, p, s] = parts;
  const expected = createHmac("sha256", SECRET).update(`${h}.${p}`).digest();
  const got = Buffer.from(s, "base64url");
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
    throw new Error("bad signature");
  }
  const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as TokenClaims;
  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("token expired");
  }
  return claims;
}
