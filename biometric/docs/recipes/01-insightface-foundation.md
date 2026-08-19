# Recipe: InsightFace foundation → ONNX → open-biometric-platform

Docs-only. Weights stay on your GPU box; never commit them.

## Goal

Produce a portable face embedder that this monorepo can consume:

1. `python3 -m train.cli --embedder onnx --weights arcface.onnx …`
2. or a precomputed table: `--embedder table --table embeddings.json`
3. Go RBR: `-embeddings embeddings.json` or a directory of `.f32` blobs

## Environment (suggested)

```bash
# CUDA box, Python 3.10–3.12
python -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install insightface onnxruntime-gpu opencv-python-headless numpy pillow
# CPU-only alternative:
# pip install onnxruntime opencv-python-headless numpy pillow insightface
```

Download a detection + recognition pack from the InsightFace model zoo
(buffalo_l is a solid default). Place under `$MODELS/`:

```
$MODELS/
  buffalo_l/
    det_10g.onnx
    w600k_r50.onnx   # ArcFace recognition
```

Respect each checkpoint’s license. Do **not** redistribute weights inside
this git repo.

## Step 1 — detect + align stills

`scripts/align_faces.py` does this end-to-end (run on the training box, not
in CI). It detects the largest qualifying face per image with InsightFace,
extracts unit embeddings, and writes a JSON table plus optional `.f32`
blobs:

```bash
python3 scripts/align_faces.py \
  --input raw_stills --out embeddings.json --out-f32 f32/ \
  --models /path/to/models --pack buffalo_l --ctx -1
```

Under the hood it uses `FaceAnalysis(name="buffalo_l", root=$MODELS)`,
`app.get(img)`, picks the largest face above `--min-face-px`, and reads
`face.normed_embedding` (falling back to `face.embedding`).

For surveillance / CCTV frames prefer a detector tuned for small faces
(SCRFD variants) and a minimum face size filter (e.g. ≥ 40 px).

## Step 2 — export recognition ONNX (if not already)

Many InsightFace packs already ship ONNX. If you fine-tune:

```bash
# example only — exact API depends on your training framework
python -m torch.onnx.export \
  --model checkpoints/arcface_epoch90.pt \
  --out $MODELS/arcface_client.onnx \
  --input-shape 1,3,112,112
```

Validate:

```bash
python - <<'PY'
import onnxruntime as ort, numpy as np
s = ort.InferenceSession("arcface.onnx", providers=["CPUExecutionProvider"])
x = np.random.randn(1, 3, 112, 112).astype("float32")
y = s.run(None, {s.get_inputs()[0].name: x})[0]
print(y.shape, float(np.linalg.norm(y)))
PY
```

## Step 3 — wire into biometric-train

```bash
cd biometric-train

# Enrol + train using ONNX embeddings (paths to real crops)
python3 -m train.cli --embedder onnx --weights $MODELS/arcface.onnx \
  --store gallery.json \
  enrol --client alice --hashes h1,h2,h3

# Prefer table mode for batch: precompute once
python3 - <<'PY'
from pathlib import Path
from train.embedder import ONNXEmbedder, write_embedding_table
# Build {image_hash: vector} offline, then:
# write_embedding_table(table, Path("embeddings.json"))
print("see train.embedder.ONNXEmbedder.embed_path")
PY

python3 -m train.cli --embedder table --table embeddings.json \
  --store gallery.json train --client alice
```

## Step 4 — Go RBR inference

```bash
# Same embeddings.json the Python side wrote
go run ./biometric-rbr/cmd/rbr \
  -embeddings embeddings.json \
  -gallery gallery.json \
  -probe probe.json \
  -consent
```

## Step 5 — authorized CCTV frames into the same loop

```bash
# 1) Pull frames from allowlisted RTSP (see recipe 02)
python3 -m train.cli corpus-auth --kind owner_consent --holder alice \
  --purposes enrolment,training
python3 -m cctv.cli pull --allowlist allowlist.json --camera lobby-1 --out frames/

# 2) Align + embed on GPU box, then ingest hashes into corpus
python3 -m train.cli corpus-ingest --client alice --source cctv_authorized
python3 -m train.cli corpus-promote --client alice
python3 -m train.cli --embedder table --table embeddings.json train --client alice
```

## Quality checklist

| Check | Target |
|---|---|
| Face size | ≥ 80 px eye-to-eye for enrolment; ≥ 40 px for CCTV candidates |
| Blur | Laplacian variance floor before enrol |
| Pose coverage | frontal + ¾ + profile if available |
| Per-identity count | 20–200 stills before fine-tune |
| Eval | held-out TAR@FAR; separate CCTV holdout |
| Revocation | `train.cli revoke --client …` purges gallery + model |

## Hard negatives

After targeted search false positives (client-consent path only), add those
hashes as negative anchors — never untargeted scrape identities.

## Out of scope for this recipe

- Untargeted open CCTV indexes
- Shipping weights in git
- Joint multi-client heads without isolation + consent
