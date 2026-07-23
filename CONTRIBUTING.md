# Contributing

Thanks for your interest in open-security-platform! This is a polyglot monorepo
(Go, Node/TypeScript, Python). Each component lives under a portfolio directory
and is self-contained.

## Repository layout

```
identity/  ai-security/  ai-governance/  offensive/  soc/
```

Each component has its own `README.md`, `NEXT_STEPS.md`, tests, and manifest
(`go.mod`, `package.json`, or `pyproject.toml`).

## Getting started

```bash
make help     # list targets
make list     # show components by language
make test     # run all component test suites
```

To work on one component, `cd` into it and use its native tooling:

- **Go:** `go test ./...`, `go build ./...`
- **Node/TS:** `npm test`, `npm start` (runs via `node --experimental-strip-types`, Node ≥ 22.6)
- **Python:** `python3 -m unittest discover -s tests`

## Guidelines

- Keep components **self-contained** and runnable offline with minimal deps.
- Follow the existing style of the component you are editing.
- Add tests for new behavior; keep `make test` green.
- Offensive components must preserve the **safety model**: authorized scope only,
  no external calls, no destructive payloads, no real exfiltration, full audit.
- Update the component's `README.md` and `NEXT_STEPS.md` as appropriate.
- All contributions are licensed under Apache-2.0 (see [LICENSE](LICENSE)).

## Pull requests

1. Fork and create a branch.
2. Make your change with tests.
3. Run `make verify` (lint + test) locally.
4. Open a PR describing the change and the component(s) affected.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md).
