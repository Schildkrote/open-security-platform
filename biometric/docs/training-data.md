# Training data strategy: building a high-quality FR model

This document explains how `open-biometric-platform` is meant to accumulate
**lots of high-quality training data** — including CCTV-like conditions —
without sliding into untargeted mass surveillance.

## Goal

Best-in-class **client-protection** recognition:

1. **Foundation model** — general face representation (pose, lighting, age,
   compression, surveillance optics).
2. **Client fine-tune / enrolment** — a tight gallery + optional adapter for
   *one consenting person* so they can be found in the wild.

The lawful basis for (2) is almost always **client consent**. The basis for
(1) is **dataset license / synthetic / research terms** — never "we found
open cameras on the internet."

## Data tiers

| Tier | What | Basis | Role in training |
|---|---|---|---|
| **A. Client enrolment** | Studio + selfie + ID-style stills the client uploads | `client_consent` | Primary gallery; always required |
| **B. Client-authorized CCTV** | Exports from the client's own NVR / office / home cams, or a venue with **written owner consent** | `client_consent` and/or `owner_consent` | Domain gap: angle, compression, motion blur |
| **C. Licensed research corpora** | VGGFace2-class, WebFace, surveillance benchmarks **with terms that allow training** | `dataset_license` | Foundation pretrain only |
| **D. Synthetic** | Rendered / diffusion identities, CCTV-style synth | `synthetic` (no real subject) | Hard poses, rare lighting, privacy-safe volume |
| **E. Open internet CCTV** | Insecam-style indexes, Shodan RTSP, random IP cams | **prohibited for ingest** | Discovery/research notes only |

Implemented in `biometric-train/train/corpus.py` and the CLI:

```bash
python3 -m train.cli corpus-auth --kind client_consent --holder alice \
  --purposes enrolment,training,targeted_search
python3 -m train.cli corpus-ingest --client alice --source cctv_authorized
python3 -m train.cli corpus-promote --client alice
python3 -m train.cli train --client alice
python3 -m train.cli open-cctv-policy   # read the ban + allowed paths
```

## Can we find open CCTV streams on the internet?

**Yes, they exist. No, we must not train on them by default.**

### What exists (discovery only)

- Public webcam indexes (historically "insecam"-class sites)
- Search-engine dorks and device search engines (Shodan/Censys) for RTSP,
  MJPEG, vendor default paths
- Municipal traffic / tourism cams published as open data
- Leaked or misconfigured NVR web UIs

### Why auto-ingest is banned here

1. **No lawful basis for the faces in frame** — passers-by never consented;
   GDPR Art. 9 / AI Act risk is extreme.
2. **No camera-owner authorization** — accessing many of these feeds is
   unauthorized access under criminal law in EU/US, regardless of "it was
   open."
3. **Product policy** — this repo's purpose is *client protection*, not
   building a planetary face graph. `untargeted_mass_id` and `open_cctv`
   source types are hard-refused in code.
4. **Quality is often terrible and biased** — helps less than licensed
   surveillance datasets + synthetic CCTV-style data, with far more risk.

### When CCTV *is* allowed

| Scenario | Required auth record | Notes |
|---|---|---|
| Client's own premises NVR export | `client_consent` (client is controller) | Best path for "recognize me on my cameras / similar cams" |
| Hotel / office / event venue | `owner_consent` + client consent if matching client | Written agreement; notice to staff/visitors where required |
| Licensed surveillance face benchmark | `dataset_license` for that dataset id | Foundation only; check redistribution |
| Synthetic CCTV-style video | `synthetic` | Preferred for volume |

Municipal open-data cams: only if the **license text explicitly allows
biometric identification / derivative ML** — almost none do. Treat as
discovery, not corpus.

## How to train with *lots* of high-quality data

### Phase 0 — instrumentation (done in this repo)

- Lawful-basis gate on every enrol / train / ingest
- Corpus manager with auth records + quality floor
- Mock sources for client upload, authorized CCTV, research, synthetic
- Embedders: `mock` | `table` (precomputed) | `onnx` (user weights)
- Go RBR consumes the same tables via `-embeddings`

### Phase 1 — foundation representation (offline GPU box)

1. Assemble **tier C + D** only (licensed + synthetic). Target: millions of
   stills / frames across identities **you are allowed to train on**.
2. Detect + align faces (RetinaFace / SCRFD) → 112×112 crops.
3. Train or fine-tune ArcFace / AdaFace / PartIOU-style loss (InsightFace
   stack is the usual starting point).
4. Export ONNX → point `train.cli --embedder onnx --weights model.onnx`
   or dump a JSON/`.f32` embedding table for Go.

Quality knobs that matter more than raw count:

- **Condition coverage:** frontal / profile / pitch, day/night, bitrate
  ladders, rain/flare, mask/sunglasses, age bands
- **Surveillance optics:** high FOV, compression, low lux — use authorized
  CCTV + synth, not open cams
- **Label cleanliness:** one identity per folder; purge near-dupes
- **Balanced demographics** within license constraints

### Phase 2 — client pack (the product loop)

For each consenting client:

1. **Enrol 20–200 stills** (tier A): controlled lighting + a few in-the-wild
   selfies the client selects.
2. **Optional authorized CCTV** (tier B): days of lobby/home footage where
   the client appears; auto-sample high-quality frames (sharpness, face
   size, pose entropy).
3. **Quality filter** (`min_quality`, Laplacian/face-det score) before enrol.
4. **Gallery embed** with the foundation ONNX model (or table).
5. **Optional fine-tune:** LoRA / partial FC on top of frozen backbone using
   *only* that client's tiers A+B (never mix other real clients into the
   same head without isolation).
6. **Hard negatives:** public web hits confirmed *not* the client (from
   targeted search false positives) — still no untargeted scrape for
   training identities.
7. **Eval:** TAR@FAR on held-out client stills + authorized CCTV holdout;
   threshold calibration per client.
8. **Revocation:** purge embeddings + adapters immediately (`train.cli revoke`).

### Phase 3 — continuous improvement

- Scheduled re-embed when foundation model upgrades
- Active learning: analyst-confirmed true hits → enrol (with consent still
  valid)
- Synthetic augmentation around the client's faceprint (identity-preserving
  renders) to cover missing poses without new real footage
- Cross-device calibration (phone vs CCTV vs news compression)

## Pipeline diagram

```
 licensed datasets + synthetic          client consent
           │                                  │
           v                                  v
   foundation pretrain ──────────────► ONNX / embedding table
                                              │
                    authorized CCTV + uploads │
                              │               │
                              v               v
                         corpus (auth-gated) → enrol → gallery
                                              │
                                              v
                                    identify / RBR match
                                              │
                                              v
                                    alert client (redacted)
```

## Engineering map in this repo

| Need | Where |
|---|---|
| Basis decisions | `platform/lawful-basis` |
| Audit trail | `platform/biometric-audit` |
| Corpus + CCTV policy | `biometric-train/train/corpus.py` |
| Embedders mock/table/onnx | `biometric-train/train/embedder.py` |
| Enrol/train/identify | `biometric-train/train/__init__.py` + CLI |
| Match at inference | `biometric-rbr` (`-embeddings` for real vectors) |
| Person graph | `biometric-graph` |

## Practical open-source starting stack (outside OSS core)

Not vendored here (licenses / size); run in your training env:

- **InsightFace** (detection + ArcFace embeddings)
- **AdaFace** or **PartIOU** checkpoints for wild/surveillance conditions
- **ONNX Runtime** for portable inference
- **faiss** / HNSW for large galleries later

Feed outputs into this repo as:

- `--embedder onnx --weights /models/arcface.onnx`, or
- `--embedder table --table embeddings.json`, or
- Go: `-embeddings embeddings.json`

## Non-negotiables

1. No open-stream bulk ingest for faces.
2. No training identity that lacks a live auth record.
3. Client revoke ⇒ purge.
4. Foundation data stays isolated from client adapters unless license +
   consent both allow.
5. Prefer synthetic + licensed surveillance data over any "found on the
   internet" CCTV shortcut.
