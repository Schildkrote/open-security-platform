# Copyright 2026 open-biometric-platform Authors.
# SPDX-License-Identifier: Apache-2.0
"""Export OBP match hits to open-decision-platform (ODP).

Runs ``Gallery.identify`` on a set of probe hashes and emits one ODP
IntegrationEvent per hit, then POSTs them to the ODP webhook
(``/hooks/osp``) — or prints them to stdout (offline / CI).

The event envelope mirrors ODP ``platform/events.IntegrationEvent``:
    id, time, type, source, action, subject, refs, data, prev_hash, hash
where ``hash = sha256(canonical JSON with hash zeroed)`` — canonical =
sorted keys, compact separators (matches Go's json.Marshal on maps).

Only pseudonyms + scores cross the wire; raw face bytes never leave OBP.

Usage:
    python3 scripts/export_odp.py \
        --store gallery.json --embedder table --table embeddings.json \
        --probes probes.json [--url http://127.0.0.1:8091/hooks/osp] \
        [--token ***] [--threshold 0.82]

probes.json: {"probes": [{"id": "web-77", "image_hash": "h1"}, ...]}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "biometric-train"))

from train.embedder import make_embedder  # noqa: E402
from train import Gallery  # noqa: E402


def event_digest(ev: dict) -> str:
    """sha256 over canonical JSON with the hash field zeroed (ODP Digest)."""
    tmp = dict(ev)
    tmp["hash"] = ""
    canon = json.dumps(tmp, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def build_match_event(
    *,
    hit_id: str,
    client_pseudo: str,
    probe_id: str,
    score: float,
    source: str = "targeted_search",
    prev_hash: str = "genesis",
    ts: str | None = None,
) -> dict:
    ev = {
        "id": hit_id,
        "time": ts or time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "type": "biometric.match",
        "source": "obp",
        "action": "match_hit",
        "subject": client_pseudo,
        "refs": {},
        "data": {
            "client_pseudo": client_pseudo,
            "probe_id": probe_id,
            "score": score,
            "source": source,
            "retention_days": 30,
        },
        "prev_hash": prev_hash,
        "hash": "",
    }
    ev["hash"] = event_digest(ev)
    return ev


def load_probes(path: Path) -> list[dict]:
    data = json.loads(Path(path).read_text())
    return data.get("probes", []) if isinstance(data, dict) else data


def export(gallery: Gallery, probes: list[dict], threshold: float) -> list[dict]:
    events: list[dict] = []
    prev = "genesis"
    for i, p in enumerate(probes):
        probe_id = p.get("id") or f"probe-{i}"
        image_hash = p.get("image_hash", "")
        if not image_hash:
            continue
        for client_id, score in gallery.identify(image_hash, threshold=threshold):
            pseudo = hashlib.sha256(client_id.encode()).hexdigest()[:24]
            hit_id = f"obp-{probe_id}-{i}-{len(events)}"
            ev = build_match_event(
                hit_id=hit_id,
                client_pseudo=pseudo,
                probe_id=probe_id,
                score=round(float(score), 6),
                prev_hash=prev,
            )
            events.append(ev)
            prev = ev["hash"]
    return events


def post(url: str, events: list[dict], token: str = "") -> int:
    ok = 0
    for ev in events:
        body = json.dumps(ev).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            if resp.status == 200:
                ok += 1
            else:
                print(f"  ! {ev['id']}: HTTP {resp.status}", file=sys.stderr)
    return ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="export_odp")
    p.add_argument("--store", required=True)
    p.add_argument("--embedder", default="table", choices=("mock", "table", "onnx"))
    p.add_argument("--table", default="")
    p.add_argument("--weights", default="")
    p.add_argument("--probes", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--token", default="")
    p.add_argument("--threshold", type=float, default=0.82)
    p.add_argument("--out", default="", help="write events to JSON file instead of POST")
    args = p.parse_args(argv)

    kwargs = {}
    if args.embedder == "table" and args.table:
        kwargs["table"] = args.table
    if args.embedder == "onnx" and args.weights:
        kwargs["weights"] = args.weights
    g = Gallery.load(args.store, embedder=make_embedder(args.embedder, **kwargs))

    events = export(g, load_probes(Path(args.probes)), args.threshold)
    if args.out:
        Path(args.out).write_text(json.dumps(events, indent=2))
        print(f"wrote {len(events)} events → {args.out}")
        return 0
    if args.url:
        ok = post(args.url, events, args.token)
        print(f"posted {ok}/{len(events)} events → {args.url}")
        return 0 if ok == len(events) else 1
    print(json.dumps(events, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())