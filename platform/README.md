# platform

Shared, stdlib-only Go libraries for `open-security-platform` components — the
"OSS core" referenced in `AGENTS.md`. Component-specific logic stays in each
component; only genuinely cross-cutting building blocks live here.

Module path: `github.com/Schildkrote/platform`. It is a member of the root
`go.work` workspace, so components depend on it with a normal `require` (no
network fetch, no `replace` needed in workspace mode).

## Packages

- [`audit`](./audit) — a tamper-evident, hash-chained audit trail engine
  (`Chain`). Components keep their own domain record types and wrap `Chain`
  with a thin adapter; the chaining/hashing/serialization/verification logic
  lives here once instead of being copy-pasted per component.

## Schemas

- [`schemas/audit_event.schema.json`](./schemas/audit_event.schema.json) — the
  common audit-record envelope (constant `time`/`prev_hash`/`hash` chaining
  fields plus optional `actor`/`action`/`target`/`detail`; components add their
  own domain fields).

## Conventions

- **stdlib only** — no third-party runtime dependencies.
- Apache-2.0, like the rest of the repo.
- Adding a new shared package: keep it cross-cutting and dependency-free, add
  tests, and ensure `make verify` stays green.
