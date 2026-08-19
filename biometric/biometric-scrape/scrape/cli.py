"""CLI for biometric-scrape."""
from __future__ import annotations

import argparse
import json
import sys

from scrape import Consent, MockSource, WebSource, run_scrape
import audit_log  # noqa: E402  (added to path by scrape package)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="scrape")
    sub = p.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run a targeted scrape")
    run_p.add_argument("--client", required=True)
    run_p.add_argument("--source", choices=("mock", "web"), default="mock")
    run_p.add_argument("--purpose", default="targeted_search")
    run_p.add_argument("--category", default="general")
    run_p.add_argument("--no-consent", action="store_true")
    run_p.add_argument("--limit", type=int, default=5)
    run_p.add_argument("--retain-raw", action="store_true")
    run_p.add_argument("--format", choices=("text", "json"), default="text")
    run_p.add_argument("--audit", default="", help="audit JSONL path (hash-chained log)")

    args = p.parse_args(argv)
    if args.cmd == "run":
        consent = None
        if not args.no_consent:
            consent = Consent(
                client_id=args.client,
                purposes=("targeted_search", "client_protection", "enrolment", "training"),
            )
        src = MockSource() if args.source == "mock" else WebSource()
        audit = audit_log.AuditLog(args.audit) if args.audit else None
        result = run_scrape(
            args.client,
            consent,
            src,
            purpose=args.purpose,
            category=args.category,
            limit=args.limit,
            retain_raw=args.retain_raw,
            audit=audit,
        )
        if args.audit and audit is not None:
            audit.verify()  # tamper-evidence check on every run
        if args.format == "json":
            json.dump(result.to_dict(), sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            if result.refused:
                print(f"REFUSED: {result.refuse_reason}")
                print(f"  basis={result.basis.outcome}")
                return 2
            print(f"scrape: client={result.client_id} source={result.source}")
            print(f"  basis={result.basis.outcome} retention_max={result.basis.retention_max_days}d")
            print(f"  crops={len(result.crops)}")
            for c in result.crops:
                print(f"  - {c.crop_id} hash={c.image_hash[:12]}… bbox={c.bbox}")
        return 0 if not result.refused else 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
