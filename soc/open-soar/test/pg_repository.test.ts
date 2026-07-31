import assert from "node:assert";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { test } from "node:test";
import { verifyChain } from "../src/audit.ts";
import { openDB, type DB } from "../src/db.ts";
import {
  type AsyncCaseRepository,
  PostgresAuditRepository,
  PostgresCaseRepository,
  persistenceFromEnv,
} from "../src/repository.ts";

function listen(handler: Parameters<typeof createServer>[0]): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, () => resolve({ server, port: (server.address() as { port: number }).port }));
  });
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data ? (JSON.parse(data) as Record<string, unknown>) : {}));
  });
}

// postgrest is a test-only emulator of the PostgREST conventions the real
// gateway exposes (row filtering via `?col=eq.val`, ordering via `?order=`,
// `Prefer: return=representation`), backed by the same in-memory SQLite store so
// the test exercises the real fetch client end-to-end offline.
function postgrest(db: DB) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const u = new URL(req.url ?? "/", "http://localhost");
    const method = req.method ?? "GET";
    const body = await readBody(req);
    const send = (status: number, obj: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };

    if (u.pathname === "/cases") {
      if (method === "GET") {
        const filter = u.searchParams.get("id");
        if (filter) {
          const row = db.prepare("SELECT * FROM cases WHERE id=?").get(filter.replace(/^eq\./, ""));
          return send(200, row ? [row] : []);
        }
        return send(200, db.prepare("SELECT * FROM cases ORDER BY created_at").all());
      }
      if (method === "POST") {
        db.prepare(
          `INSERT INTO cases (id,title,severity,status,assignee,classification,alerts,evidence,timeline) VALUES (?,?,?,?,?,?,?,?,?)`,
        ).run(
          body.id as string,
          body.title as string,
          (body.severity as string) ?? "medium",
          (body.status as string) ?? "open",
          (body.assignee as string | null) ?? null,
          (body.classification as string | null) ?? null,
          (body.alerts as string) ?? "[]",
          (body.evidence as string) ?? "[]",
          (body.timeline as string) ?? "[]",
        );
        const row = db.prepare("SELECT * FROM cases WHERE id=?").get(body.id as string);
        return send(201, [row]);
      }
      if (method === "PATCH") {
        const id = (u.searchParams.get("id") ?? "").replace(/^eq\./, "");
        const allowed = ["status", "assignee", "classification", "severity", "alerts", "evidence", "timeline"];
        const cols = Object.keys(body).filter((c) => allowed.includes(c));
        const set = cols.map((c) => `${c}=?`).join(",");
        const args: (string | null)[] = [...cols.map((c) => body[c] as string | null), id];
        db.prepare(`UPDATE cases SET ${set} WHERE id=?`).run(...args);
        const row = db.prepare("SELECT * FROM cases WHERE id=?").get(id);
        return send(200, row ? [row] : []);
      }
    }

    if (u.pathname === "/audit_log") {
      if (method === "GET") {
        const dir = u.searchParams.get("order") === "seq.desc" ? "DESC" : "ASC";
        const limit = u.searchParams.get("limit");
        let sql = `SELECT * FROM audit_log ORDER BY seq ${dir}`;
        if (limit) sql += ` LIMIT ${Number(limit)}`;
        return send(200, db.prepare(sql).all());
      }
      if (method === "POST") {
        db.prepare(`INSERT INTO audit_log (actor,event,detail,prev_hash,hash) VALUES (?,?,?,?,?)`).run(
          (body.actor as string | null) ?? null,
          body.event as string,
          (body.detail as string | null) ?? null,
          body.prev_hash as string,
          body.hash as string,
        );
        return send(201, []);
      }
    }

    return send(404, { error: "not found" });
  };
}

test("persistenceFromEnv defaults to sqlite and selects postgres via env", () => {
  assert.equal(persistenceFromEnv({}).kind, "sqlite");
  assert.equal(persistenceFromEnv({ OSP_SOAR_GATEWAY: "http://127.0.0.1:9999" }).kind, "postgres");
});

test("case repository CRUD over the Postgres gateway seam", async () => {
  const db = openDB(":memory:");
  const { server, port } = await listen(postgrest(db));
  try {
    const backend = persistenceFromEnv({ OSP_SOAR_GATEWAY: `http://127.0.0.1:${port}` });
    assert.equal(backend.kind, "postgres");
    if (backend.kind !== "postgres") return;
    const repo: AsyncCaseRepository = new PostgresCaseRepository(backend.gateway);

    const c = await repo.create("phishing alert", { severity: "high", alert: { src: "1.2.3.4" } });
    assert.equal((await repo.get(c.id))?.title, "phishing alert");
    assert.equal(c.alerts.length, 1);

    await repo.setStatus(c.id, "investigating", "analyst");
    assert.equal((await repo.get(c.id))?.status, "investigating");

    await repo.assign(c.id, "analyst");
    assert.equal((await repo.get(c.id))?.assignee, "analyst");

    await repo.addEvidence(c.id, { note: "confirmed malicious" });
    assert.equal((await repo.get(c.id))?.evidence.length, 1);

    assert.equal((await repo.list()).length, 1);

    // The gateway-produced chain verifies via the async audit repository...
    const auditRepo = new PostgresAuditRepository(backend.gateway);
    assert.ok((await auditRepo.verify()).valid);
    // ...and via the SQLite verifier on the same store, proving the hash-chain
    // algorithm agrees across backends.
    assert.ok(verifyChain(db).valid);
  } finally {
    server.close();
  }
});
