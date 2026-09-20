# credential-intel

An open **breach / credential-dump lookup** tool: check whether an identifier
(email or SHA-1 password hash) appears in known public breaches, and report
which breaches affected it. Pure Go standard library.

## Safety model

- **mock mode (default):** fully offline, backed by a bundled synthetic
  sample breach set. CI and offline development run mock only.
- **hibp mode:** live path — uses the **HIBP k-anonymity API**. Only the
  first 5 hex chars of the SHA-1 of the identifier leave the machine; the
  full hash is never sent. Read-only GETs; optional API key for higher rate
  limits. This is the component's live-gate surface (see AGENTS.md).
- No credentials are ever submitted; no state changes; no exfiltration beyond
  the k-anonymity range request.

## Quickstart

```bash
go run . -id alice@example.com -mode mock
go run . -id alice@example.com -mode hibp
go run . -id alice@example.com -mode hibp -api-key "$HIBP_API_KEY"
go run . -id alice@example.com -mode mock -mock-file ./my-breaches.json
go run . -id alice@example.com -mode mock -format json
```

Flags: `-id`, `-mode mock|hibp`, `-api-key`, `-mock-file`, `-format text|json`.

## What is mocked / real

- Mock source: synthetic sample data (see `internal/source/mock.go`).
- HIBP source: real k-anonymity range lookup; verified with httptest in CI.
- Breach-detail listing (`-breaches` flag, HIBP `/range/{prefix}/{email}?
  unmask=email`) is stubbed in the CLI — wire `parseBreachList` when needed.

## Tests

```bash
go test ./...
```

## License

AGPL-3.0-only