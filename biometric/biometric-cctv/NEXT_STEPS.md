# NEXT_STEPS — biometric-cctv

## Done
- Allowlist-only camera model (owner/client consent, le_warrant)
- Open-cam host ban (insecam-style)
- Mock pull for CI + ffmpeg real path
- Manifest → corpus JSONL

## Next
- Digest auth / ONVIF discovery *within* allowlisted subnets only
- Face-size prefilter before writing frames
- Direct corpus.ingest adapter (skip manual JSONL)
- mTLS to on-prem NVR bridge
