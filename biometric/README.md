# open-biometric-platform

> Consent-gated facial recognition for **client harm reduction**: train on a
> client's own images (with their permission) so they can be recognized on
> the open internet and protected against defamation, false reporting, deepfakes,
> and non-consensual use of their likeness.

> [!WARNING]
> **Experimental / v0.1 scaffold.** Pre-release software. Default path uses
> **mock hash-embeddings**, not a production face model. Biometric processing is
> a special category under GDPR Art. 9 and a high-risk / restricted use under the
> EU AI Act. Do not deploy without independent legal review and a documented DPiA.

> [!NOTE]
> Independent open-source project. Not affiliated with any commercial
> biometric vendor. Every component runs offline with mocks by default.
> `make verify` green proves structure + consent gates + unit tests — **not**
> operational face recognition quality.

## Status (honest)

| Capability | Today |
|---|---|
| Lawful-basis + consent fail-closed | Real (Go engine; Python mirrors — keep in sync) |
| Enrol / train / revoke / identify CLI | Real on **mock** or user-supplied table/ONNX embeddings |
| “Best FR model” / ArcFace training loop | **Not implemented** (centroid of embeddings only) |
| Live web scrape of client photos | **MockSource only** |
| Biometric-audit on every face op | Package exists; **not fully wired** into train/scrape/integration |
| Docker deploy | **Not shipped** yet (`deploy/` planned) |

## Purpose (what this is for)

Clients (executives, public figures, private individuals under threat) grant
**explicit, revocable permission** for us to:

1. Enrol their reference images into a private gallery
2. Train / fine-tune a face recognizer on *their* images
3. Search public sources for *their* face (targeted, not untargeted mass ID)
4. Alert them when their likeness appears in contexts that may cause harm

This is **identity protection**, not surveillance of the general public.

## Architecture

```
 client consent ──► enrolment gallery ──► train / fine-tune
                                              │
                                              v
 scrape (targeted) ──► categorise ──► match (RBR) ──► person graph ──► alert
        │                  │              │                │
        └──────── lawful-basis gate (+ audit when wired) ──┘
```

## Components

| Component | Lang | Role |
|---|---|---|
| `platform/lawful-basis` | Go | Decision engine: purpose × regime × category → permit/consent/dpia/prohibit |
| `platform/biometric-audit` | Go | Hash-chained audit log with basis, retention, redaction |
| `biometric-categorise` | Python | Sensitivity class (public-figure, minor, health, …) |
| `biometric-scrape` | Python | Consent-gated, *targeted* image acquisition (web, archive, CCTV) |
| `biometric-rbr` | Go | Faceprint + gallery match + stream mode |
| `biometric-graph` | Go | Cross-case / cross-agency person graphs (pseudonymous) |
| `biometric-train` | Python | Client-permissioned FR training / fine-tune loop |
| `biometric-cctv` | Python | Allowlist-only RTSP/NVR frame pull (owner/client consent) |
| `integration/` | Python | End-to-end pipeline (enrol → train → scrape → match → graph) |

## Quickstart

```bash
make verify          # lint + test everything (offline)
make list

# Lawful-basis check (module is not package-main at root — use cmd/)
cd platform/lawful-basis && go run ./cmd/lawful-basis \
  -purpose enrolment -regime gdpr -category general -consent

# Enrol + train (mock) — CLI takes content hashes, not image directories
cd biometric-train
python3 -m train.cli enrol --client alice \
  --hashes 'alice-ref-0,alice-ref-1,alice-ref-2,alice-ref-3,alice-ref-4'
python3 -m train.cli train --client alice
python3 -m train.cli identify --hash alice-ref-0

# Targeted scrape (mock)
cd ../biometric-scrape && python3 -m scrape.cli run --client alice --source mock

# Gallery match (mock embeddings unless -embeddings is set)
cd ../biometric-rbr && go run ./cmd/rbr \
  -gallery examples/gallery.json -probe examples/probe.json -consent
```

For real vectors: export InsightFace (or similar) offline → `embeddings.json` →
`--embedder table --table embeddings.json` (see `docs/recipes/`).

## Safety model (summary)

See [AGENTS.md](AGENTS.md) for the full rules. Short version:

1. **Lawful-basis first.** No face is touched without a permit.
2. **Client consent is the primary basis** for training and targeted search.
3. **Mock = default.** CI is fully offline. Real models/weights are user-supplied.
4. **No raw storage by default.** Hash + bbox + metadata; raw crop only with auto-expiry.
5. **Category-differentiated retention.** Minors / health / religion → stricter.
6. **Pseudonymous graphs.** Person nodes are hashes; names stay agency-local.
7. **Tamper-evident audit** is required by policy; wire calls are still landing.

## License

Apache-2.0
