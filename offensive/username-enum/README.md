# username-enum

An open **username enumeration** tool: probe a list of online services for an
account under a given username and report where it exists. Pure Go standard
library; read-only HTTP GETs only (no credentials, no state changes).

## Safety model

- **mock mode (default):** fully offline, deterministic fake hit set. Used by
  CI and for offline development.
- **http mode:** live path — outbound read-only GETs to the service catalog,
  throttled (`-interval-ms`, default 200ms), capped (`-max-probes`, default
  25). Only GET/HEAD are used; no auth, no exploit, no DoS payloads. This is
  the component's live-gate surface (see the `--live` gate in AGENTS.md).
- Differential detection: a service reports **found** when the account URL
  returns 200 while a derived not-found URL returns 4xx. No differential
  → **uncertain** (reported, never guessed).

## Quickstart

```bash
go run . -username alice -mode mock
go run . -username alice -mode http -services github,gitlab
go run . -username alice -mode http -max-probes 10 -format json
```

Flags: `-username`, `-mode mock|http`, `-services` (comma list),
`-max-probes`, `-interval-ms`, `-format text|json`.

## Extending the catalog

`internal/service/catalog.go` holds the built-in list (URL template +
differential weight). Add a service with a stable public URL pattern; keep
probes read-only and keep the per-host rate limit.

## Tests

```bash
go test ./...
```

## License

Apache-2.0