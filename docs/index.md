# open-security-platform

An open-source security platform monorepo of self-hostable, developer-friendly
security products across five portfolios.

## Portfolios

- **Identity** — human, machine, and agent identity: `oiaf`, `open-pam-jit`, `agent-identity`.
- **AI Security** — AI/agent runtime security: `open-ai-gateway`, `ai-access-broker`,
  `mcp-security-gateway`, `rag-authorization`, `agent-sandbox`.
- **AI Governance** — AI GRC and red teaming: `ai-compliance-hub`, `ai-redteam-evals`,
  `ai-redteam-platform`.
- **Offensive** — red team / pentest / purple team: `pentest-manager`, `purple-team`,
  `attack-path`, `agent-redteam-range`.
- **SOC** — security operations: `open-soar`.

Each component is self-contained with its own `README.md`, `NEXT_STEPS.md`, and
tests. See the portfolio pages for details, or the
[repository README](https://github.com/open-security-platform/open-security-platform).

## Quickstart

```bash
make help     # list targets
make test     # run every component's test suite
make docs     # serve this site locally
```

## Safety

Offensive and AI-security components are built for **authorized testing only**,
with scope gates, auditability, and non-destructive behavior by design. The
`agent-redteam-range` targets are intentionally vulnerable training apps that
bind to localhost and use fake secrets.

## License

Apache-2.0.
