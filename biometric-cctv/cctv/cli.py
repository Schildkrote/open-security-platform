"""CLI for authorized CCTV pull."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cctv import Allowlist, AllowlistError, build_manifest, pull_frames, write_manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cctv")
    sub = p.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser("check", help="validate allowlist (no network)")
    check.add_argument("--allowlist", required=True)

    pull = sub.add_parser("pull", help="sample frames from an allowlisted camera")
    pull.add_argument("--allowlist", required=True)
    pull.add_argument("--camera", required=True)
    pull.add_argument("--out", required=True)
    pull.add_argument("--duration", type=float, default=10.0)
    pull.add_argument("--every", type=float, default=2.0, help="seconds between samples")
    pull.add_argument("--dry-run", action="store_true")
    pull.add_argument(
        "--mock",
        action="store_true",
        help="write synthetic frames (CI / no camera)",
    )

    man = sub.add_parser("manifest", help="hash frames → JSONL for corpus")
    man.add_argument("--frames", required=True)
    man.add_argument("--client", required=True)
    man.add_argument("--camera", required=True)
    man.add_argument("--out", required=True)

    args = p.parse_args(argv)

    if args.cmd == "check":
        try:
            al = Allowlist.load(args.allowlist)
            warnings = al.validate()
        except AllowlistError as e:
            print(f"INVALID: {e}", file=sys.stderr)
            return 2
        print(f"OK cameras={list(al.cameras)} version={al.version}")
        for w in warnings:
            print(f"WARN: {w}")
        return 0

    if args.cmd == "pull":
        try:
            al = Allowlist.load(args.allowlist)
            al.validate()
            result = pull_frames(
                al,
                args.camera,
                args.out,
                duration_s=args.duration,
                every_s=args.every,
                dry_run=args.dry_run,
                mock=args.mock,
            )
        except (AllowlistError, RuntimeError) as e:
            print(f"REFUSED: {e}", file=sys.stderr)
            return 2
        print(json.dumps(result.to_dict(), indent=2))
        return 1 if result.error and result.error != "dry_run" else 0

    if args.cmd == "manifest":
        rows = build_manifest(args.frames, client_id=args.client, camera_id=args.camera)
        write_manifest(rows, args.out)
        print(f"wrote {len(rows)} rows → {args.out}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
