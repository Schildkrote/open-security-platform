import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";

const SECRET = process.env.BROKER_SECRET ?? "dev-secret-change-me";

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}

export interface Claims {
  sub: string;
  email?: string;
  role?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  jti?: string;
  [k: string]: unknown;
}

export function sign(claims: Claims, ttlSeconds = 3600): string {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload: Claims = {
    iss: "ai-access-broker",
    iat: now,
    exp: now + ttlSeconds,
    jti: randomUUID(),
    ...claims,
  };
  const enc = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createHmac("sha256", SECRET).update(enc).digest("base64url");
  return `${enc}.${sig}`;
}

export function verify(token: string): Claims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [h, p, s] = parts;
  const expected = createHmac("sha256", SECRET).update(`${h}.${p}`).digest();
  const got = Buffer.from(s, "base64url");
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
    throw new Error("bad signature");
  }
  const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as Claims;
  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("token expired");
  }
  return claims;
}
