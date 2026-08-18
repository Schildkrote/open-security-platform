# Offensive OSINT Taxonomy

Canonical source categories for offensive OSINT, with the default
mock/real seam for each. This mirrors the taxonomy used by
[Legendary_OSINT](https://github.com/K2SOsint/Legendary_OSINT) and is the
reference for which connector belongs to which component.

## People / background check

| Source class | Examples | Live-gate | Component |
|---|---|---|---|
| People finders | Spokeo, Pipl, TruePeopleSearch, FastPeopleSearch, That'sThem | `people-search` | `live-recon` |
| Voter / public records | State voter rolls, court records | `people-search` | `live-recon` |
| Contact aggregators | Truecaller, Whitepages | `people-search` | `live-recon` |

> Subject consent (`-consent`) is required; read-only GETs to a source
> whitelist; results redacted (names hashed in the audit log).

## Breach / credential

| Source class | Examples | Live-gate | Component |
|---|---|---|---|
| Pwned-password / email k-anonymity | HIBP (Have I Been Pwned) | (k-anon, no gate) | `credential-intel` |
| Breach dump corpora | Dehash, HaveIBeenPwned exports | (offline file) | `credential-intel` |
| Password-recovery / security questions | Recovery-DB aggregators | (aspirational) | `credential-intel` |

## Account / identity

| Source class | Examples | Live-gate | Component |
|---|---|---|---|
| Username enumeration | Sherlock, Maigret, Blackbird service lists | (mock default; live HTTP) | `username-enum` |
| Account-existence / reset flows | Per-site `/reset?email=`, masked-detail reveal | `recovery-probing` | `live-recon` |
| Authenticated contact harvesting | Osintgram-style platform scrapes | `authenticated-scrape` | `live-recon` |

## Network / device

| Source class | Examples | Live-gate | Component |
|---|---|---|---|
| Shodan / Censys dorks | `product:`, `org:`, `vuln:` queries | (mock default; live API) | `attack-path` |
| Active port/service scan | nmap, nuclei, web-check | `active-scanning` | `live-recon` |
| Passive domain intel | DNS history, cert transparency, WHOIS, Wayback | (offline table default) | `attack-path` |

## Geo / movement

| Source class | Examples | Live-gate | Component |
|---|---|---|---|
| IP geolocation / ASN | MaxMind GeoLite2, RIPE | (offline table default) | `attack-path` |
| Phone carrier / region | Carrier lookup tables | (offline table default) | `attack-path` |
| Movement / home/workplace inference | Derived from cached observations | (analysis only) | `attack-path` |

## Rules for new sources

1. Pick the right component from the tables; register the source in that
   component's catalog.
2. Ship a **mock** (offline, deterministic) and a **real** implementation
   behind the connector interface.
3. If the source makes outbound calls or touches PII, it is live-gated —
   use the matching `--live` feature and honor its conditions (AGENTS.md).
4. Redact PII in audit logs and default output.