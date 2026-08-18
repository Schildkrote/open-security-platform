<!--
Proposed addition to AGENTS.md — insert directly after the existing
"## Safety model (do not violate)" bullet list (after the license-header
bullet), before "## `identity/oiaf` is a git subtree".

The same table (abridged) is already in SECURITY.md under "Security Posture".
-->

### `--live` gate: policy exceptions for state-changing or PII-touching work

Four classes of offensive work would violate the safety model if run by
default. Each is a **policy exception** implemented by the shared
`platform/livegate` package: default **OFF**, opt-in per invocation via
`--live <feature>` (comma-separated), and CI/test suites run mock-only with no
features enabled. The gate is printed in every run's output so the audit trail
shows exactly which exceptions were active.

| # | Feature | Flag | Exception conditions (enforced) |
|---|---------|------|---------------------------------|
| 6 | **Active attack-surface scanning** (port/service probes, HTTP requests, vulnerability templates) | `--live active-scanning` | explicit scope list per invocation; only read-only probes (GET/HEAD/OPTIONS, no exploit/auth-bypass/DoS templates); per-host rate limit (default 5 req/s); redacted evidence + tamper-evident audit log; 5-minute run cap. |
| 7 | **Account-recovery & account-existence probing** (reset flows, masked email/phone reveal, account-existence differentials) | `--live recovery-probing` | explicit target + identifier list; ≤ 1 state-changing request per identifier (one reset request / one reveal); global cap 10 identifiers per run; no credential submission; differential results audit-logged; at-least-daily cadence per identifier. |
| 8 | **People-search / background-check aggregation** (people finders, voter records, contact aggregators) | `--live people-search` | explicit `--consent` subject-consent flag required at run time; read-only GETs to a source whitelist; results cached and redacted (names hashed in the audit log); PII hidden from stdout unless `-verbose`; data minimization: one query per source per run. |
| 9 | **Authenticated platform scraping / contact harvesting** (emails/phones via user-supplied session) | `--live authenticated-scrape` | user-supplied credential in memory or env var only (never argv, never the audit log); read-only access, no posts or profile edits; per-platform rate limit (default 1 req/5s); harvested PII written redacted by default; session discarded at run end. |

Rules for adding new live features:

1. Register the feature in `platform/livegate` (constant + `Exceptions` entry)
   before any code may enable it; unknown features are rejected by `Parse`.
2. The feature's mock path must remain fully offline; the real path is only
   reachable when the gate is enabled **and** a scope/credential is supplied.
3. Every live action writes to the component's tamper-evident audit log with
   the active gate state; PII is redacted or hashed in logs and default
   output.
4. `SECURITY.md` documents the gate for reporters; the exception table above
   is the canonical list.