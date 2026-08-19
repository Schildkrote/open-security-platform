"""CLI for biometric-categorise."""
from __future__ import annotations

import argparse
import json
import sys

from categorise import Features, categorise


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="categorise")
    p.add_argument("--age", type=int, default=None)
    p.add_argument("--source", default="")
    p.add_argument("--tags", default="", help="comma-separated tags")
    p.add_argument("--employee", action="store_true")
    p.add_argument("--public-figure", action="store_true")
    p.add_argument("--format", choices=("text", "json"), default="text")
    args = p.parse_args(argv)

    tags = tuple(t.strip() for t in args.tags.split(",") if t.strip())
    res = categorise(
        Features(
            age_estimate=args.age,
            source_type=args.source,
            tags=tags,
            is_employee=args.employee,
            is_public_figure=args.public_figure,
        )
    )
    if args.format == "json":
        json.dump(res.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"category={res.category} special={res.special} conf={res.confidence:.2f}")
        for r in res.reasons:
            print(f"  - {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
