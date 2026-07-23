"""HTTP API for the AI red team platform (stdlib http.server)."""
from __future__ import annotations

import json
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import evidence as evidence_mod
from . import registry, reports
from .audit import AuditLog
from .engine import HttpTarget, MockTarget
from .runner import CampaignResult, SafeRunner


class Platform:
    """Wires the registry, safe runner, evidence and reporting together."""

    def __init__(self, conn: sqlite3.Connection, audit: AuditLog | None = None) -> None:
        self.conn = conn
        self.audit = audit or AuditLog()
        self.runner = SafeRunner(conn, self.audit)
        self.results: dict[str, CampaignResult] = {}

    def run(self, target_id: str, guarded: bool = True) -> CampaignResult:
        target = registry.get_target(self.conn, target_id)
        if target and target.get("endpoint"):
            engine_target = HttpTarget(target["endpoint"], name=target["name"])
        else:
            engine_target = MockTarget(guarded=guarded, name=(target or {}).get("name", "mock"))
        result = self.runner.run_campaign(target_id, engine_target)
        self.results[result.campaign_id] = result
        return result


def make_handler(platform: Platform) -> type[BaseHTTPRequestHandler]:
    conn = platform.conn

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _send(self, status: int, body: Any, ctype: str = "application/json") -> None:
            data = body.encode() if isinstance(body, str) else json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                return {}
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?")[0]
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)

            if path == "/healthz":
                return self._send(200, {"ok": True})
            if path == "/targets":
                return self._send(200, registry.list_targets(conn))
            if path == "/evidence":
                return self._send(200, evidence_mod.list_evidence(conn, params.get("campaign_id")))
            if path == "/evidence/verify":
                return self._send(200, evidence_mod.verify_chain(conn))

            m = re.match(r"^/campaigns/([^/]+)/report$", path)
            if m:
                result = platform.results.get(m.group(1))
                if not result:
                    return self._send(404, {"error": "campaign not in memory"})
                fmt = params.get("format", "technical")
                if fmt == "executive":
                    return self._send(200, reports.executive_report(result.score), "text/markdown")
                if fmt == "compliance":
                    return self._send(200, reports.compliance_report(result.score, result.compliance), "text/markdown")
                if fmt == "json":
                    return self._send(200, reports.json_report(result.score, result.compliance))
                return self._send(200, reports.technical_report(result.score, result.compliance), "text/markdown")

            m = re.match(r"^/compliance/([^/]+)$", path)
            if m:
                result = platform.results.get(m.group(1))
                if not result:
                    return self._send(404, {"error": "campaign not in memory"})
                return self._send(200, result.compliance)

            return self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?")[0]
            body = self._body()
            try:
                if path == "/targets":
                    return self._send(201, registry.register_target(conn, **body))
                m = re.match(r"^/targets/([^/]+)/authorize$", path)
                if m:
                    return self._send(200, registry.set_authorization(conn, m.group(1), body.get("status", "authorized")))
                if path == "/campaigns":
                    guarded = body.get("guarded", True)
                    result = platform.run(body["target_id"], guarded=guarded)
                    return self._send(200, {
                        "campaign_id": result.campaign_id,
                        "aborted": result.aborted,
                        "score": result.score.to_dict(),
                    })
            except Exception as e:  # noqa: BLE001
                return self._send(400, {"error": str(e)})
            return self._send(404, {"error": "not found"})

    return Handler


def serve(platform: Platform, port: int = 8090) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(platform))
