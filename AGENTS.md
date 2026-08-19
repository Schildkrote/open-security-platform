# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## What this repo is

`open-biometric-platform` is a polyglot Apache-2.0 monorepo for
**consent-gated facial recognition used for client harm reduction**.
Clients enrol their own images and grant permission for us to train a
recognizer and search public sources for *their* face — not the general
public.

Components: `platform/lawful-basis`, `platform/biometric-audit`,
`biometric-categorise`, `biometric-scrape`, `biometric-rbr`,
`biometric-graph`, `biometric-train`, `integration/`.

## Build / test / lint

```bash
make list
make test
make lint
make verify   # lint + test — always run before finishing work
```

Per-language:

```bash
# Go
go test ./... && go build ./... && go vet ./...

# Python (stdlib only)
python3 -m unittest discover -s tests
```

## Toolchain

- **Go:** 1.25/1.26. Modules under `github.com/Schildkrote/<component>`.
  `gofmt` enforced. License header required (see `.licenserc.yaml`).
- **Python:** >= 3.11, **stdlib only** for runtime. Tests use `unittest`.
  No third-party runtime deps in the OSS core. Real model weights are
  user-supplied and never committed.

## Safety model (do not violate)

### Lawful-basis first

- Every component that touches a face **must** call
  `platform/lawful-basis` (or its Python mirror) before the operation.
- Decision outcomes: `permitted | requires_consent | requires_dpia | prohibited`.
- `prohibited` → refuse. `requires_dpia` → refuse until DPiA acknowledged.
- `requires_consent` → refuse until a valid, unrevoked client consent record
  is present.

### Primary lawful basis: client consent for self-protection

The intended production path is:

| Purpose | Basis | Notes |
|---|---|---|
| Enrol client reference images | `consent` | Explicit, revocable, purpose-bound |
| Train / fine-tune on client images | `consent` | Same consent covers training |
| Targeted search for *enrolled* clients | `consent` + `legitimate_interest` (client protection) | Scope limited to enrolled gallery |
| Untargeted mass ID of the public | **prohibited** by default | Not this product's purpose |
| RBRIS in public spaces without LE warrant | **prohibited** (AI Act) | Only via `requires_dpia` + LE basis |

### Mock = default, offline

- CI and tests run mock-only. Never break the offline path.
- Real detectors/embedders/models are user-supplied weights behind a flag.
- Connector interfaces ship mock + real; real needs credentials + basis pass.

### Data minimisation

- Default storage: face hash + bbox + source + timestamp + category.
- Raw crop only with `--retain-raw` and auto-expiry (default 24h).
- Person-graph nodes are pseudonyms (hash). Name mapping is agency-local.
- PII redacted/hashed in audit logs and default stdout.

### Category-differentiated rules

`biometric-categorise` labels: `public_figure | employee | minor |
health_context | religion_context | general`. Minors and special-category
contexts force `requires_dpia` and shorter retention.

### Audit

Every operation writes to `platform/biometric-audit` with: action, subject
pseudonym, basis decision, retention expiry, redaction status, hash-chain
link.

### Training-specific rules (`biometric-train`)

1. Training set = **only** images the client enrolled under a valid consent.
2. No scraping of third-party faces into the training set.
3. Model checkpoints store gallery IDs, never raw pixels, by default.
4. Revocation of consent → purge that client's embeddings + retrain or
   mask them from the gallery before the next inference run.

## Repo layout

- Each component: `README.md`, honest `NEXT_STEPS.md`, tests, LICENSE.
- Docs: `docs/`, mkdocs.
- Deploy: `deploy/docker-compose.yml` (localhost-only).