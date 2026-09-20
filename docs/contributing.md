# Contributing

See the repository [CONTRIBUTING.md](https://github.com/open-security-platform/open-security-platform/blob/main/CONTRIBUTING.md)
for full details.

## Quick summary

- Polyglot monorepo: Go, Node/TypeScript, Python.
- Each component is self-contained under a portfolio directory.
- Run `make test` to exercise all components; `make verify` to lint + test.
- Keep components runnable offline with minimal dependencies.
- Offensive/AI components must preserve the safety model (authorized scope only,
  no destructive payloads, no real exfiltration, full audit).
- All contributions are licensed under AGPL-3.0-only.

Please read the
[Code of Conduct](https://github.com/open-security-platform/open-security-platform/blob/main/CODE_OF_CONDUCT.md).
