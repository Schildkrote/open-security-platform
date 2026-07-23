"""Run the AI red team platform API server."""
from __future__ import annotations

import argparse

from .api import Platform, serve
from .db import file_db


def main() -> None:
    parser = argparse.ArgumentParser(description="AI red team platform API")
    parser.add_argument("--dir", default=".", help="data directory")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()

    platform = Platform(file_db(args.dir))
    server = serve(platform, args.port)
    print(f"ai-redteam-platform listening on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
