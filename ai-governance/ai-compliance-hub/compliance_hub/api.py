"""HTTP API for the compliance hub (stdlib http.server)."""
from __future__ import annotations

import json
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from . import cards, controls, evidence, models


def make_handler(conn: sqlite3.Connection) -> type[BaseHTTPRequestHandler]:
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
            body = self._body()
            try:
                if path == "/systems":
                    return self._send(201, models.register_system(conn, **body))
                if path == "/controls":
                    return self._send(201, controls.add_control(conn, **body))
                if path == "/risks":
                    return self._send(201, models.add_risk(conn, **body))
                if path == "/evidence":
                    return self._send(201, evidence.collect_evidence(conn, **body))
                if path == "/cards/model":
                    return self._send(200, {"card": cards.model_card(body)})
            except (TypeError, ValueError) as e:
                return self._send(400, {"error": str(e)})
            return self._send(404, {"error": "not found"})

    return Handler


def serve(conn: sqlite3.Connection, port: int = 8082) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(conn))
    return server
