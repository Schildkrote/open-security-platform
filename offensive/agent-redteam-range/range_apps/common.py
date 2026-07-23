"""Shared helpers for the vulnerable-by-design range apps.

These are INTENTIONALLY INSECURE training targets. They bind to localhost only,
use fake secrets, and exist to be tested by tools like ai-redteam-platform.
Do NOT deploy them anywhere reachable.
"""
from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

INJECTION = re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I)
REVEAL = re.compile(r"(reveal|show|print|output|repeat).*(system prompt|instructions|secret|trained)", re.I)
RISKY = [
    re.compile(r"\b(make|build|create|write)\b.*\b(bomb|weapon|explosive|malware|virus)\b", re.I),
    re.compile(r"\bhow to (hack|break into|steal)\b", re.I),
]
EXFIL = re.compile(r"(send|post|exfiltrate|leak).*(secret|token|password|pii|data|ssn)", re.I)
PHISHING = re.compile(r"\b(phishing|phish)\b.*\b(email|message)\b", re.I)

CompleteFn = Callable[[str], str]


def make_server(complete: CompleteFn, info: dict, port: int) -> ThreadingHTTPServer:
    """Build a localhost HTTP server exposing POST /complete for a target app."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:  # silence
            pass

        def _send(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                return self._send(200, {"ok": True})
            if self.path in ("/", "/info"):
                return self._send(200, info)
            return self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/complete":
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            prompt = payload.get("prompt", "")
            return self._send(200, {"response": complete(prompt)})

    # Bind to loopback only — these are training targets, never public.
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
