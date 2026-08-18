# NEXT_STEPS — credential-intel

Honest status, mock vs real.

## What works (real, offline)

- Mock source with embedded synthetic sample + user-supplied JSON file.
- HIBP k-anonymity source: SHA-1 range lookup with httptest-verified parsing;
  429 → Uncertain with a helpful message; optional API key.
- CLI with text/JSON output, live-gate notice on the hibp path.
- Redaction: the answer always carries the SHA-1 of the input, never the
  input itself.

## What is mocked / aspirational

- **Breach-detail listing** (`parseBreachList` exists but the CLI has no
  `-breaches` flag yet) — add it and verify against a real HIBP response
  shape.
- **Password-hash lookups** (HIBP PwnedPasswords `/range/{prefix}` with a
  SHA-1 password hash) — the source interface supports it; the CLI currently
  treats `-id` as an email. Add a `-type email|password` flag.
- **Local dump corpora** (HaveIBeenPwned CSV exports, Dehash) as an offline
  real-data source alongside the mock — a `file` source that reads a JSON or
  CSV dump.
- **Recovery-question answers** (DigIn / recovery-DB lookups) — the
  "password-recovery lookups" half of the feature; needs a real data source
  or an API.
- **Live-gate integration:** `-mode hibp` prints a gate notice but does not
  yet call `platform/livegate.Parse` / `Summary` — wire the shared gate once
  the other live features land.

## Safety

- Keep the k-anonymity invariant: never send the full SHA-1.
- Redact the input in all logs and reports (carry the hash, not the value).
- HIBP is read-only GETs; keep it that way.
- CI must stay offline (mock only).