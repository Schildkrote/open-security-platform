"""HTTP API for the compliance hub (stdlib http.server)."""
from __future__ import annotations

import json
import os
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import auth, cards, controls, evidence, frameworks, models, webhook


def make_handler(conn: sqlite3.Connection) -> type[BaseHTTPRequestHandler]:
    # Opt-in shared OIDC/JWT auth (Phase 1): set OSP_AUTH_SECRET to protect the
    # write API. Empty = open (offline default). /webhook stays open for the
    # native component-to-component spine.
    auth_secret = os.environ.get("OSP_AUTH_SECRET", "")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence default logging
            pass

        def _send(self, status: int, body: Any) -> None:
            data = json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
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
            if path == "/systems":
                return self._send(200, models.list_systems(conn))
            if path == "/controls":
                fw = params.get("framework")
                if fw:
                    return self._send(200, controls.controls_for_framework(conn, fw))
                return self._send(200, controls.list_controls(conn))
            if path == "/frameworks":
                return self._send(200, {
                    "frameworks": frameworks.FRAMEWORKS,
                    "labels": frameworks.FRAMEWORK_LABELS,
                    "registered_references": frameworks.registry_summary(),
                    "catalog": frameworks.framework_catalog(),
                })
            if path == "/controls/coverage":
                return self._send(200, {
                    "controls": len(controls.list_controls(conn)),
                    "by_framework": controls.framework_coverage(conn),
                    "by_family": {
                        fam: len(items)
                        for fam, items in controls.controls_by_family(conn).items()
                    },
                })
            if path == "/controls/gaps":
                fw = params.get("framework")
                wanted = [fw] if fw else None
                gaps = controls.coverage_gaps(conn, wanted)
                return self._send(200, {
                    name: {"count": len(titles), "controls": titles}
                    for name, titles in gaps.items()
                })
            if path == "/controls/validate":
                errors = frameworks.validate_library(controls.DEFAULT_CONTROLS)
                return self._send(200, {"valid": not errors, "errors": errors})
            if path == "/risks":
                return self._send(200, models.list_risks(conn))
            if path == "/evidence":
                return self._send(200, evidence.list_evidence(conn))
            if path == "/evidence/verify":
                return self._send(200, evidence.verify_chain(conn))

            m = re.match(r"^/systems/([^/]+)/card$", path)
            if m:
                try:
                    return self._send(200, {"card": cards.system_card(conn, m.group(1))})
                except ValueError as e:
                    return self._send(404, {"error": str(e)})

            return self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?")[0]
            if path != "/webhook" and not auth.authorized(self.headers, auth_secret):
                return self._send(401, {"error": "unauthorized"})
            body = self._body()
            try:
                if path == "/systems":
                    return self._send(201, models.register_system(conn, **body))
                if path == "/controls":
                    # Reject invalid framework citations at the API boundary so a
                    # bad reference never reaches the stored library. Import via
                    # OSCAL stays permissive (import_catalog) - this guard is for
                    # directly-authored controls only.
                    errors = frameworks.validate_mappings(body.get("mappings") or {})
                    if errors:
                        return self._send(400, {"error": "invalid citation", "details": errors})
                    return self._send(201, controls.add_control(conn, **body))
                if path == "/risks":
                    return self._send(201, models.add_risk(conn, **body))
                if path == "/evidence":
                    return self._send(201, evidence.collect_evidence(conn, **body))
                if path == "/cards/model":
                    return self._send(200, {"card": cards.model_card(body)})
                if path == "/webhook":
                    created = webhook.consume_event(conn, body)
                    return self._send(200, {"consumed": len(created),
                                            "evidence": [e["id"] for e in created]})
            except (TypeError, ValueError) as e:
                return self._send(400, {"error": str(e)})
            return self._send(404, {"error": "not found"})

    return Handler


def serve(conn: sqlite3.Connection, port: int = 8082) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(conn))
    return server
