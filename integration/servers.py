"""Start/stop the polyglot component servers for the end-to-end flow.

Python components run in-thread (their own ``serve(..., port=0)`` factories);
the Node (pentest-manager) and Go (open-pam-jit) components run as subprocesses
on a free localhost port. Every server is health-checked before use and torn
down on exit. Everything binds 127.0.0.1 only (offline safety model).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, Sequence


def free_port() -> int:
    """Return a likely-free localhost TCP port (small reuse race is acceptable)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_health(base: str, timeout: float = 90.0, interval: float = 0.2) -> bool:
    """Poll ``GET {base}/healthz`` until it returns 200 or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    last: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception as e:  # noqa: BLE001 - keep polling until deadline
            last = e
        time.sleep(interval)
    raise RuntimeError(f"server at {base} not healthy after {timeout}s: {last}")


class PythonServer:
    """Run an http.server.ThreadingHTTPServer in a daemon thread."""

    def __init__(self, server: Any) -> None:
        self.server = server
        self.port = server.server_address[1]
        self._thread: Optional[threading.Thread] = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "PythonServer":
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        wait_health(self.base, timeout=15.0)
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


class SubprocessServer:
    """Run a component as a subprocess (Node or Go binary) on a fixed port."""

    def __init__(
        self,
        cmd: Sequence[str],
        port: int,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        health_timeout: float = 90.0,
    ) -> None:
        self.cmd = list(cmd)
        self.port = port
        self.cwd = cwd
        self.health_timeout = health_timeout
        self.env = {**os.environ, **(env or {})}
        self.proc: Optional[subprocess.Popen] = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "SubprocessServer":
        self.proc = subprocess.Popen(
            self.cmd,
            cwd=self.cwd,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            wait_health(self.base, timeout=self.health_timeout)
        except Exception:
            self._stop()
            raise
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop()

    def _stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def node_server(
    script_dir: str, port: int, extra_env: Optional[dict[str, str]] = None
) -> SubprocessServer:
    """pentest-manager: ``node --experimental-strip-types src/server.ts``."""
    node = shutil.which("node") or "node"
    env = {"PORT": str(port), "DB_PATH": ":memory:"}
    if extra_env:
        env.update(extra_env)
    return SubprocessServer(
        [node, "--experimental-strip-types", "--no-warnings", "src/server.ts"],
        port,
        cwd=script_dir,
        env=env,
    )


def go_server(
    binary: str, port: int, audit_file: str, extra_args: Optional[Sequence[str]] = None
) -> SubprocessServer:
    """open-pam-jit: a prebuilt binary listening on ``port``."""
    cmd = [binary, "-listen", f":{port}", "-audit", audit_file]
    if extra_args:
        cmd.extend(extra_args)
    return SubprocessServer(cmd, port)


class CollectorServer:
    """A tiny webhook collector that stores received integration events.

    ``POST /webhook`` records the event; ``GET /events`` returns them. Used by
    the native-spine test to observe events emitted by components (e.g.
    open-pam-jit ``access.granted``, agent-sandbox ``action.executed``).
    """

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.port: Optional[int] = None
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a copy of the collected events (thread-safe)."""
        with self._lock:
            return list(self.events)

    def __enter__(self) -> "CollectorServer":
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence default logging
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                with collector._lock:
                    collector.events.append(body)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def do_GET(self) -> None:  # noqa: N802
                with collector._lock:
                    snapshot = list(collector.events)
                data = json.dumps(snapshot).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


def build_go(repo_root: str, out_path: str, package: str = "./identity/open-pam-jit") -> str:
    """``go build`` a component binary (uses the root go.work workspace)."""
    subprocess.run(
        ["go", "build", "-o", out_path, package],
        cwd=repo_root,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return out_path
