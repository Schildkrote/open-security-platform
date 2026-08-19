# live-recon

An open **live reconnaissance** runner: the four `--live`-gated offensive
features from the safety model, each with a mock (offline) and a real
(network) implementation.

| Feature | Flag | What it does |
|---------|------|--------------|
| `active-scanning` | `-feature active-scanning` | TCP connect + read-only HTTP GET against `host:port` targets |
| `recovery-probing` | `-feature recovery-probing` | Password-reset / account-existence differential against a URL template |
| `people-search` | `-feature people-search` | Read-only GET against a source whitelist (requires `-consent`); whitelist loaded from the osint taxonomy |
| `authenticated-scrape` | `-feature authenticated-scrape` | Authenticated read-only GET (Bearer token from env/`-credential`) |
| `recovery-reveal` | `-feature recovery-reveal` | Masked email/phone reveal from account-recovery pages (requires `-consent`) |

## Safety model

- **Default is mock.** Every feature runs offline against a deterministic
  mock unless `-real` **and** `-live <feature>` are both given. CI runs mock
  only.
- **Live-gate printed every run.** The gate state (`feature=on/off`) is
  printed to stderr at the start of every invocation, so the audit trail
  shows exactly which exceptions were active.
- **Per-feature conditions** (from AGENTS.md safety model) are enforced:
  people-search requires `-consent`; authenticated-scrape requires a
  credential (env `LIVE_RECON_CREDENTIAL` or `-credential`, never argv-only
  in the audit log); active scanning is read-only (TCP connect + GET).
- **Redaction:** the subject's name/identifier appears in `target` but not in
  `evidence`; credentials are sent in headers only.

## Quickstart

```bash
# Offline (default):
go run . -feature active-scanning -target 10.0.0.1:80
go run . -feature recovery-probing -target "https://x/reset?email={identifier}" -credential alice@example.com
go run . -feature people-search -target spokeo -credential "Alice" -consent
go run . -feature authenticated-scrape -target "https://x/contacts" -credential "$LIVE_RECON_CREDENTIAL"

# Live (real network):
go run . -feature active-scanning -target 93.184.216.34:80 -live active-scanning -real
go run . -feature people-search -target spokeo -credential "Alice" -consent -live people-search -real
```

Flags: `-feature`, `-target`, `-live` (comma list), `-real`, `-credential`,
`-consent`, `-format text|json`.

## Tests

```bash
go test ./...
```

Real-path tests use `httptest` servers and a loopback listener, so they stay
offline in CI.

## License

Apache-2.0