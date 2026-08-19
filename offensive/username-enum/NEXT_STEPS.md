# NEXT_STEPS — username-enum

Honest status, mock vs real.

## What works (real, offline)

- Catalog with 6 conservative services (github, gitlab, mastodon-social,
  reddit, discord, stackexchange) + URL-template substitution.
- Mock source: deterministic, offline, ratio-tunable.
- HTTP source: read-only GET differential probing with httptest-verified
  found/not-found/uncertain classification.
- Engine: rate limiting, probe caps, context cancellation, per-probe audit
  hook, aggregate report (text + JSON).

## What is mocked / aspirational

- **Service catalog is small.** Real sherlock/maigred wordlists cover 500+
  services; import their JSON wordlist format as a `LoadWordlist` importer
  (pattern: `offensive/attack-path/internal/ingest`).
- **Discord/StackExchange entries are weight-1 placeholders** (no stable
  public GET URL without auth); keep them until a real endpoint is found.
- **No custom-words / common-suffix expansion** (e.g. `alice`, `alice_`,
  `alice123`) — the engine probes one exact username per run.
- **No concurrency** beyond the throttle ticker; a bounded worker pool
  (e.g. 4 hosts in parallel) is the natural next step, keeping the per-host
  rate limit.
- **Live-gate integration:** `-mode http` prints a gate notice but does not
  yet call `platform/livegate.Parse` / `Summary` — wire the shared gate once
  the other live features land.

## Safety

- Keep probes read-only (GET/HEAD/OPTIONS only).
- Keep `-max-probes` enforced; CI must stay offline (mock only).
- Redact usernames in any audit log that leaves the machine.

## Honesty update

- CLI now calls shared `platform/livegate.Parse` / `Summary` for live paths.
- Mock/default remains offline with gate off.
