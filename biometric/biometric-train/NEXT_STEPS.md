# NEXT_STEPS — biometric-train

## Done
- Consent-gated enrol + train + identify + revoke
- Centroid mock trainer (offline)
- Persistence (gallery.json)
- Minor/special-category blocked without DPiA
- **Lawful-basis consolidated**: `decide_basis` delegates to
  `platform/basis-matrix` (single source of truth, matrix.json-pinned)
- **Audit on the hot path**: enrol/train/identify/revoke append to the
  hash-chained log (`platform/audit-log`); CLI `--audit` flag
- **Real-embeddings path completed**: `scripts/align_faces.py` (offline
  InsightFace → JSON table + `.f32` blobs), golden fixture
  `tests/fixtures/emb_golden.json` pinned from both Python and Go
  (round-trip proven: Go rbr consumes the same table, match hit at 1.0)

## Next
- Python `Gallery.save` writes an object `{consents, clients, models}` but
  Go `rbr.LoadJSON` expects `[]FaceRecord` — need a Go-format export
  (`train.cli export-go`) or a Go loader for the Python layout
- Real fine-tune loop (ArcFace / AdaFace) with user weights — adapters landed
  (`embedder.py` mock|table|onnx; Go `-embeddings` external table)
- Corpus manager + authorized CCTV sources — landed (`corpus.py`, CLI)
- Hard-negative mining from confirmed non-matches
- Federated update across consenting clients (no raw exchange)
- Automatic retrain-on-revoke for multi-client joint models
- GPU training recipes (InsightFace config pack) as docs-only under `docs/recipes/`