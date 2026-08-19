# Roadmap

## Done (this scaffold)

- Monorepo + tooling (Makefile, go.work, governance docs)
- `platform/lawful-basis` decision engine
- `platform/biometric-audit` hash-chained audit
- `biometric-categorise` sensitivity classifier (rule + mock ML)
- `biometric-scrape` targeted, consent-gated sources
- `biometric-rbr` faceprint + gallery match + stream
- `biometric-graph` person graphs + cross-agency federation
- `biometric-train` client-permissioned FR training loop
- `integration/` end-to-end pipeline test

## Now

- Real detector/embedder adapters (MediaPipe / ArcFace weights user-supplied)
- Postgres backends for gallery + audit
- DPiA template pack + regime matrix (GDPR / AI Act / BSR)

## Next

- Continuous targeted monitoring schedules
- Alert channels (email/webhook) with redacted evidence packs
- Federated learning across consenting clients (no raw exchange)

## Later

- Hosted control plane (separate repo)
- Helm packaging, multi-tenancy enforcement