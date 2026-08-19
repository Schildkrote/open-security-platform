# Recipe: Authorized RTSP / NVR pull

Pull frames only from cameras on a signed **allowlist** with a live
authorization record (`owner_consent` or `client_consent`).

## Policy

| Allowed | Banned |
|---|---|
| Client-owned NVR export / RTSP | Open internet cam indexes |
| Venue cameras with written owner consent | Shodan-discovered RTSP without auth |
| LE feeds under warrant / statutory basis | Any stream not in allowlist.json |

The connector refuses URLs that are not in the allowlist file. Discovery of
open cams is **not** implemented.

## Allowlist format

```json
{
  "version": 1,
  "cameras": [
    {
      "id": "lobby-1",
      "rtsp_url": "rtsp://user:pass@192.168.1.20:554/stream1",
      "holder": "alice",
      "auth_kind": "owner_consent",
      "purposes": ["enrolment", "training", "targeted_search"],
      "notes": "Client office lobby NVR channel 1",
      "max_fps_sample": 1,
      "min_face_px": 40
    }
  ]
}
```

Store allowlists outside git when they contain credentials. Prefer
environment variable substitution:

```json
"rtsp_url": "rtsp://${NVR_USER}:${NVR_PASS}@nvr.internal/cam1"
```

## CLI

```bash
# Validate allowlist + basis (no network)
python3 -m cctv.cli check --allowlist allowlist.json

# Sample frames via ffmpeg (must be installed)
python3 -m cctv.cli pull \
  --allowlist allowlist.json \
  --camera lobby-1 \
  --out ./frames/lobby-1 \
  --duration 30 \
  --every 2

# Emit corpus-ready JSONL (hashes + paths) for train.cli promote path
python3 -m cctv.cli manifest \
  --frames ./frames/lobby-1 \
  --client alice \
  --camera lobby-1 \
  --out lobby-1.jsonl
```

## ffmpeg dependency

```bash
# macOS
brew install ffmpeg
# Debian/Ubuntu
sudo apt-get install -y ffmpeg
```

OpenCV/PyAV are optional; the default path shells out to `ffmpeg` /
`ffprobe` so CI stays mock-friendly without cv2.

## Wiring into training

```bash
python3 -m train.cli corpus-auth --kind owner_consent --holder alice \
  --purposes enrolment,training
# After pull + face filter on GPU box:
python3 -m train.cli corpus-ingest --client alice --source cctv_authorized
python3 -m train.cli corpus-promote --client alice
python3 -m train.cli train --client alice
```

## LE / warrant path

For law-enforcement deployments set `auth_kind` to `le_warrant` and attach
the warrant/case id in `notes`. The corpus manager still requires that
authorization record before ingest. Pair with `platform/lawful-basis`
purpose `law_enforcement` + jurisdiction pack.
