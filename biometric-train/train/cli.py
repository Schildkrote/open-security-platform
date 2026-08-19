"""CLI for biometric-train (+ corpus ingest)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from train import Consent, Gallery, make_embedder
from train.corpus import (
    Authorization,
    Corpus,
    MockAuthorizedCCTVSource,
    MockClientUploadSource,
    MockResearchDatasetSource,
    MockSyntheticSource,
    open_cctv_policy,
)


DEFAULT_STORE = Path("gallery.json")
DEFAULT_CORPUS = Path("corpus.json")


def load_gallery(path: Path, embedder_mode: str, weights: str, table: str, audit: str = "") -> Gallery:
    kwargs = {}
    if embedder_mode == "onnx" and weights:
        kwargs["weights"] = weights
    if embedder_mode == "table" and table:
        kwargs["table"] = table
    emb = make_embedder(embedder_mode, **kwargs)
    if path.exists():
        g = Gallery.load(path, embedder=emb)
    else:
        g = Gallery(embedder=emb)
    if audit:
        g.set_audit_path(audit)
    return g


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="train")
    p.add_argument("--store", default=str(DEFAULT_STORE))
    p.add_argument("--corpus-store", default=str(DEFAULT_CORPUS))
    p.add_argument("--embedder", default="mock", choices=("mock", "table", "onnx"))
    p.add_argument("--weights", default="", help="ONNX weights path (onnx mode)")
    p.add_argument("--table", default="", help="embedding table JSON (table mode)")
    p.add_argument("--audit", default="", help="audit JSONL path (hash-chained log; created if missing)")
    sub = p.add_subparsers(dest="cmd", required=True)

    enrol = sub.add_parser("enrol", help="enrol image hashes for a client")
    enrol.add_argument("--client", required=True)
    enrol.add_argument("--hashes", required=True, help="comma-separated image hashes")
    enrol.add_argument("--no-consent", action="store_true")
    enrol.add_argument("--category", default="general")

    train_p = sub.add_parser("train", help="train/fine-tune client model")
    train_p.add_argument("--client", required=True)
    train_p.add_argument("--category", default="general")

    status = sub.add_parser("status", help="show gallery/model status")
    status.add_argument("--client", default="")

    revoke = sub.add_parser("revoke", help="revoke consent and purge client data")
    revoke.add_argument("--client", required=True)

    identify = sub.add_parser("identify", help="match a probe hash against trained models")
    identify.add_argument("--hash", required=True)
    identify.add_argument("--threshold", type=float, default=0.82)
    identify.add_argument("--path", default="", help="image path for real embedders")

    # Corpus commands
    c_auth = sub.add_parser("corpus-auth", help="add an authorization record to the corpus")
    c_auth.add_argument("--kind", required=True, choices=(
        "client_consent", "owner_consent", "dataset_license", "synthetic", "le_warrant"
    ))
    c_auth.add_argument("--holder", required=True)
    c_auth.add_argument("--purposes", default="enrolment,training,targeted_search")
    c_auth.add_argument("--notes", default="")

    c_ingest = sub.add_parser("corpus-ingest", help="ingest from a mock/authorized source")
    c_ingest.add_argument("--client", required=True)
    c_ingest.add_argument(
        "--source",
        required=True,
        choices=("client_upload", "cctv_authorized", "research_dataset", "synthetic"),
    )
    c_ingest.add_argument("--holder", default="", help="defaults to --client")
    c_ingest.add_argument("--limit", type=int, default=20)
    c_ingest.add_argument("--dataset-id", default="synthetic-faces-v1")
    c_ingest.add_argument("--camera-id", default="cam-lobby-1")
    c_ingest.add_argument("--min-quality", type=float, default=0.5)

    c_report = sub.add_parser("corpus-report", help="quality report for corpus")
    c_report.add_argument("--client", default="")

    c_promote = sub.add_parser(
        "corpus-promote",
        help="enrol corpus items for a client into the training gallery",
    )
    c_promote.add_argument("--client", required=True)
    c_promote.add_argument("--category", default="general")

    sub.add_parser("open-cctv-policy", help="print open-CCTV discovery policy (no ingest)")

    args = p.parse_args(argv)
    store = Path(args.store)
    corpus_path = Path(args.corpus_store)

    def gallery() -> Gallery:
        return load_gallery(store, args.embedder, args.weights, args.table, args.audit)

    def corpus() -> Corpus:
        if corpus_path.exists():
            return Corpus.load(corpus_path)
        return Corpus()

    if args.cmd == "enrol":
        g = gallery()
        if not args.no_consent:
            g.set_consent(
                Consent(
                    client_id=args.client,
                    purposes=("enrolment", "training", "targeted_search", "client_protection"),
                )
            )
        hashes = [h.strip() for h in args.hashes.split(",") if h.strip()]
        n, d = g.enrol(args.client, hashes, category=args.category)
        g.save(store)
        if not d.allowed():
            print(f"REFUSED: {d.reason} (basis={d.outcome})", file=sys.stderr)
            return 2
        print(f"enrolled {n} images for {args.client} (basis={d.outcome} embedder={g.embedder.name})")
        return 0

    if args.cmd == "train":
        g = gallery()
        model, d = g.train(args.client, category=args.category)
        g.save(store)
        if model is None:
            print(f"REFUSED/EMPTY: {d.reason} (basis={d.outcome})", file=sys.stderr)
            return 2
        print(
            f"trained {args.client} v{model.version} "
            f"n_images={model.n_images} embedder={model.embedder} "
            f"pseudo={model.subject_pseudo[:12]}… (basis={d.outcome})"
        )
        return 0

    if args.cmd == "status":
        g = gallery()
        if args.client:
            imgs = g.clients.get(args.client, [])
            model = g.models.get(args.client)
            c = g.consents.get(args.client)
            print(f"client={args.client} embedder={g.embedder.name}")
            print(f"  consent={'revoked' if (c and c.revoked) else ('yes' if c else 'no')}")
            print(f"  enrolled_images={len(imgs)}")
            by_src: dict[str, int] = {}
            for im in imgs:
                by_src[im.source] = by_src.get(im.source, 0) + 1
            print(f"  by_source={by_src}")
            print(f"  model={'v'+str(model.version) if model else 'none'}")
        else:
            print(json.dumps({
                "embedder": g.embedder.name,
                "clients": list(g.clients),
                "models": list(g.models),
                "consents": {
                    k: {"revoked": v.revoked, "purposes": list(v.purposes)}
                    for k, v in g.consents.items()
                },
            }, indent=2))
        return 0

    if args.cmd == "revoke":
        g = gallery()
        info = g.revoke(args.client)
        g.save(store)
        print(f"revoked {args.client}: {info}")
        return 0

    if args.cmd == "identify":
        g = gallery()
        hits = g.identify(args.hash, threshold=args.threshold, image_path=args.path)
        if not hits:
            print("no matches")
            return 0
        for cid, score in hits:
            print(f"  {cid} score={score:.4f}")
        return 0

    if args.cmd == "corpus-auth":
        c = corpus()
        purposes = tuple(x.strip() for x in args.purposes.split(",") if x.strip())
        c.add_authorization(
            Authorization(kind=args.kind, holder=args.holder, purposes=purposes, notes=args.notes)
        )
        c.save(corpus_path)
        print(f"added auth kind={args.kind} holder={args.holder} purposes={purposes}")
        return 0

    if args.cmd == "corpus-ingest":
        c = corpus()
        c.min_quality = args.min_quality
        holder = args.holder or args.client
        if args.source == "client_upload":
            src = MockClientUploadSource(client_id=args.client)
        elif args.source == "cctv_authorized":
            src = MockAuthorizedCCTVSource(client_id=args.client, camera_id=args.camera_id)
        elif args.source == "research_dataset":
            src = MockResearchDatasetSource(dataset_id=args.dataset_id)
            holder = args.holder or args.dataset_id
        else:
            src = MockSyntheticSource()
            holder = args.holder or "synthetic"
        result = c.ingest(src, client_id=args.client, holder=holder, limit=args.limit)
        c.save(corpus_path)
        print(json.dumps(result.to_dict(), indent=2)[:2000])
        print(f"… accepted={len(result.accepted)} rejected={len(result.rejected)} basis_ok={result.basis_ok}")
        return 0 if result.basis_ok else 2

    if args.cmd == "corpus-report":
        c = corpus()
        print(json.dumps(c.quality_report(args.client or None), indent=2))
        return 0

    if args.cmd == "corpus-promote":
        c = corpus()
        g = gallery()
        if args.client not in g.consents:
            g.set_consent(
                Consent(
                    client_id=args.client,
                    purposes=("enrolment", "training", "targeted_search", "client_protection"),
                )
            )
        items = c.export_hashes(args.client)
        n, d = g.enrol_from_corpus(args.client, items, category=args.category)
        g.save(store)
        if not d.allowed():
            print(f"REFUSED: {d.reason}", file=sys.stderr)
            return 2
        print(f"promoted {n} corpus items → gallery for {args.client}")
        return 0

    if args.cmd == "open-cctv-policy":
        print(json.dumps(open_cctv_policy(), indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
