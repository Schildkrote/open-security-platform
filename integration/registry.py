"""A lightweight event registry/broker for the native webhook spine.

Components subscribe (event_type -> webhook URL) and emitters publish events to
the broker, which fans each event out to every matching subscriber. This
decouples producers from consumers: a component emits to a single URL (the
broker) and the broker routes by event type, replacing static per-component URL
wiring. This is the shared subscription/registry the platform roadmap calls for.

Stdlib only; in-memory (a control-plane service). Subscribe with
``POST /subscribe {event_type, url, component}``, publish with
``POST /events <IntegrationEvent>``. ``event_type`` "*" matches everything.
"""
from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional


class Registry:
    """In-memory subscription table + fan-out delivery."""

    def __init__(self) -> None:
        self.subscriptions: list[dict[str, str]] = []
        self.delivered: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def subscribe(self, event_type: str, url: str, component: str = "") -> None:
        with self.lock:
            self.subscriptions.append(
                {"event_type": event_type, "url": url, "component": component}
            )

    def publish(self, event: dict[str, Any]) -> int:
        """Fan out an event to matching subscribers; return the delivery count."""
        etype = event.get("type", "")
        with self.lock:
            targets = [s["url"] for s in self.subscriptions if s["event_type"] in (etype, "*")]
        payload = json.dumps(event).encode()
        delivered = 0
        for url in targets:
            try:
                req = urllib.request.Request(
                    url, data=payload, method="POST", headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read()
                delivered += 1
            except Exception:  # noqa: BLE001 - a down subscriber must not break the broker
                pass
        with self.lock:
            self.delivered.append({"type": etype, "delivered": delivered})
        return delivered


class RegistryServer:
    """HTTP wrapper around Registry (context manager)."""

    def __init__(self) -> None:
        self.registry = Registry()
        self.port: Optional[int] = None
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def events_url(self) -> str:
        return f"{self.base}/events"

    def __enter__(self) -> "RegistryServer":
        registry = self.registry

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence default logging
                pass

            def _send(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                path = self.path.split("?")[0]
                if path == "/subscribe":
                    registry.subscribe(
                        body.get("event_type", "*"), body.get("url", ""), body.get("component", "")
                    )
                    return self._send(201, {"ok": True})
                if path == "/events":
                    return self._send(200, {"delivered": registry.publish(body)})
                return self._send(404, {"error": "not found"})

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?")[0]
                if path == "/healthz":
                    return self._send(200, {"ok": True})
                if path == "/subscriptions":
                    with registry.lock:
                        return self._send(200, list(registry.subscriptions))
                return self._send(404, {"error": "not found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
