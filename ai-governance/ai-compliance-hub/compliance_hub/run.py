"""Run the compliance hub API server."""
from __future__ import annotations

import argparse

from .api import serve
from .db import file_db


def main() -> None:
    parser = argparse.ArgumentParser(description="AI compliance hub API")
    parser.add_argument("--dir", default=".", help="data directory")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()

    conn = file_db(args.dir)
    server = serve(conn, args.port)
    print(f"ai-compliance-hub listening on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
