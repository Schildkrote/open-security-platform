# Roadmap

A high-level, non-committal roadmap for open-security-platform. Each component
has its own detailed `NEXT_STEPS.md`.

## Now

- Consolidate the 16 components into this monorepo with shared tooling and CI.
- Stabilize each component's MVP API and test suite.
- Publish per-component documentation in the aggregated docs site.

## Next

- **Cross-component integration:** wire `ai-redteam-platform` ↔ `ai-redteam-evals`
  ↔ `agent-redteam-range`; export findings to `pentest-manager`; align technique
  mapping with `purple-team`; feed evidence to `ai-compliance-hub`.
- **Real integrations:** model providers, SIEM/EDR, cloud IAM, vector DBs, MCP
  transports, SSH/DB/cloud targets for `open-pam-jit`.
- **Hardening:** replace regex detectors with ML classifiers; real sandboxing
  (gVisor/Firecracker); authenticated APIs and RBAC.

## Later

- **Attack path expansion:** cloud IAM and Active Directory ingestion for
  `attack-path`; probabilistic path scoring; what-if simulation.
- **Continuous validation:** schedule safe tests in CI/CD; detection-coverage
  trends; AI purple teaming.
- **Platform concerns:** web UIs, Postgres backends, multi-tenancy, packaging
  (Helm, images), and a unified release process.

## Contributing to the roadmap

Open an issue to propose direction. Significant changes follow the
[governance](GOVERNANCE.md) process.
