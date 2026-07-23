import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { openDB, type DB } from "./db.ts";
import * as cases from "./cases.ts";
import { heuristicTriage } from "./triage.ts";
import { execute } from "./playbook.ts";
import { PLAYBOOKS } from "./playbooks.ts";
import { audit, verifyChain } from "./audit.ts";
import { ingestAlert } from "./ingest.ts";

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data ? JSON.parse(data) : {}));
  });
}

export function buildHandler(db: DB) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const method = req.method ?? "GET";
    try {
      const body = method === "POST" ? await readBody(req) : {};

      if (path === "/healthz") return json(res, 200, { ok: true });
      if (path === "/playbooks" && method === "GET") return json(res, 200, Object.keys(PLAYBOOKS));

      if (path === "/cases" && method === "POST")
        return json(res, 201, cases.createCase(db, body.title as string, body as never));
      if (path === "/cases" && method === "GET") return json(res, 200, cases.listCases(db));

      let m = path.match(/^\/cases\/([^/]+)$/);
      if (m && method === "GET") {
        const c = cases.getCase(db, m[1]);
        return c ? json(res, 200, c) : json(res, 404, { error: "unknown case" });
      }
      m = path.match(/^\/cases\/([^/]+)\/(alerts|evidence)$/);
      if (m && method === "POST") {
        const updated =
          m[2] === "alerts"
            ? cases.addAlert(db, m[1], body.alert ?? body)
            : cases.addEvidence(db, m[1], body.evidence ?? body);
        return json(res, 201, updated);
      }
      m = path.match(/^\/cases\/([^/]+)\/status$/);
      if (m && method === "POST")
        return json(res, 200, cases.setStatus(db, m[1], body.status as string, (body.actor as string) ?? "system"));
      m = path.match(/^\/cases\/([^/]+)\/assign$/);
      if (m && method === "POST") return json(res, 200, cases.assign(db, m[1], body.assignee as string));

      m = path.match(/^\/cases\/([^/]+)\/triage$/);
      if (m && method === "POST") {
        const c = cases.getCase(db, m[1]);
        if (!c) return json(res, 404, { error: "unknown case" });
        const result = heuristicTriage({ title: c.title, description: JSON.stringify(c.alerts) });
        const updated = cases.setClassification(db, m[1], result.classification, result.severity);
        audit(db, "ai-triage", "case_triaged", { case: m[1], ...result });
        return json(res, 200, { case: updated, triage: result });
      }

      m = path.match(/^\/playbooks\/([^/]+)\/run$/);
      if (m && method === "POST") {
        const playbook = PLAYBOOKS[m[1]];
        if (!playbook) return json(res, 404, { error: "unknown playbook" });
        const input = (body.input as Record<string, unknown>) ?? {};
        const caseId = body.case_id as string | undefined;
        const result = await execute(playbook, input, { caseId });
        const execId = randomUUID();
        db.prepare(`INSERT INTO executions (id,playbook,case_id,status,result) VALUES (?,?,?,?,?)`).run(
          execId,
          playbook.name,
          caseId ?? null,
          result.status,
          JSON.stringify(result),
        );
        audit(db, "playbook", "playbook_run", { playbook: playbook.name, status: result.status, case: caseId });
        if (caseId && cases.getCase(db, caseId)) {
          cases.addEvidence(db, caseId, { type: "playbook_run", playbook: playbook.name, result });
        }
        return json(res, result.status === "success" ? 200 : 422, { execution_id: execId, ...result });
      }

      if (path === "/audit/verify" && method === "GET") return json(res, 200, verifyChain(db));

      // SIEM webhook ingestion (Phase 4): open a case from an inbound alert.
      if (path === "/ingest" && method === "POST") return json(res, 201, ingestAlert(db, body));

      return json(res, 404, { error: "not found" });
    } catch (e) {
      return json(res, 400, { error: (e as Error).message });
    }
  };
}

const isMain = process.argv[1]?.endsWith("server.ts");
if (isMain) {
  const db = openDB(process.env.DB_PATH ?? ":memory:");
  const port = Number(process.env.PORT ?? 8086);
  createServer(buildHandler(db)).listen(port, () => console.log(`open-soar listening on :${port}`));
}
