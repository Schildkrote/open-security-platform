# Scaffold honesty (v0.1)

This file records intentional limitations so READMEs cannot overclaim.
`AGENTS.md` edits may require human approval in some environments — keep this
file in sync with reality.

## Present

- Consent + lawful-basis fail-closed paths (Go + Python mirrors).
- Mock embedders (hash→vector); optional `table` / `onnx` adapters (user weights).
- Integration pipeline identifies **only probe/crop hashes** (no enrolled-ref cheat).
- Mock scrape fixtures may reuse enrolled content hashes to model “same content seen in public.”

## Absent / incomplete

- No production FR training (no ArcFace loss, no TAR@FAR eval harness in-tree).
- No live HTTP scrape of client images (MockSource / fixtures only).
- `platform/biometric-audit` is not called from train/scrape/integration yet.
- No `deploy/` tree (do not document docker-compose until it exists).
- Python `decide_basis` duplicates Go `basis.Decide` — drift risk.

## Tag

Treat releases as **v0.1-scaffold** until real embeddings + wired audit + one
honest end-to-end on real client photos (consent-gated) land.
