# NEXT_STEPS — live-recon

Honest status, mock vs real.

## What works (real, offline-verified)

- All four features with mock + real runners; mock is deterministic.
- Live-gate parsing + per-run gate summary printed to stderr.
- People-search consent enforcement; auth-scraper Bearer header; recovery
  prober differential; active scanner TCP + optional HTTP GET.
- Real-path tests use httptest + loopback (offline in CI).

## What is mocked / aspirational

- **Active scanning** (TCP connect + GET) now has an **aggressive sub-gate**
  (`-aggressive`): external `nmap -sV` service-version probe (+ optional
  `-nuclei <templates>`). Both binaries are optional — missing binary reports
  `unavailable`, the scan never fails. Exploit/DoS templates stay out
  (read-only `-sV -Pn` only).
- **Recovery prober** issues a single GET per identifier; the "at most one
  state-changing request" condition is enforced by the caller's cap, not by
  the prober itself. Add a per-identifier dedup cache (file-backed) so
  repeated runs don't re-trigger reset emails.
- **People-search** now aggregates multiple sources (`-sources a,b,c`) with a
  redacted summary and a PII-redaction pass (email/phone masked, names
  hashed). Contact parsing (extracting emails/phones from response HTML/JSON)
  is still next.
- **Auth-scraper** issues one GET; contact parsing (email/phone extraction
  from HTML/JSON) and per-platform rate limiting are next.
- **Audit log:** results are printed, not yet written to a tamper-evident
  hash-chained log (the `platform/audit` backbone integration is the next
  step, consistent with the repo's "enforce the backbone in-component" item).
- **Shared `platform/livegate`:** wired via `livegate.Parse` / `Summary`. Remaining:
  canonical across all live features.

## Safety

- Keep mock as the default; `-real` without `-live <feature>` must fail.
- Credentials in env/`-credential` only; never in argv defaults or logs.
- People-search always requires `-consent`.
- CI stays offline (mock + httptest only).

## Honesty update

- CLI now calls shared `platform/livegate.Parse` / `Summary` for live paths.
- Mock/default remains offline with gate off.
