"""Run one or all vulnerable range apps (localhost only).

Usage:
    python server.py chatbot [--port 8091]
    python server.py all
"""
from __future__ import annotations

import argparse
import threading

from range_apps import APPS, make_server, names


def run_one(name: str, port: int | None = None, block: bool = True) -> None:
    app = APPS[name]
    port = port or app["port"]
    server = make_server(app["module"].complete, app["module"].INFO, port)
    print(f"[range] {name} ({app['module'].INFO['category']}) on http://127.0.0.1:{port}")
    if block:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="AI red team range")
    parser.add_argument("app", choices=[*names(), "all"], help="app to run")
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    if args.app == "all":
        for name in names():
            run_one(name, block=False)
        print("[range] all apps running; Ctrl-C to stop")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    else:
        run_one(args.app, args.port)


if __name__ == "__main__":
    main()
