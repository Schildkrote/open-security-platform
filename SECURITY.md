# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in any component of
open-security-platform, please report it responsibly. **Do not open a public
issue.**

- Email the maintainers with a description, affected component(s), and
  reproduction steps.
- We aim to acknowledge reports within 5 business days and provide a remediation
  timeline after triage.
- We coordinate disclosure and credit reporters who follow this policy.

## Scope

This repository contains security tooling, including **intentionally vulnerable**
training targets (`offensive/agent-redteam-range`). Those targets are insecure
**by design** for authorized testing/training and are not eligible for security
reports unless they expose something beyond their intended localhost-only,
fake-secret scope.

## Security Posture

- Components are pre-release; interfaces and behavior may change.
- Treat identity- and AI-enforcement components as high-trust and review before
  deployment.
- Offensive components enforce authorization gates and avoid destructive or
  evasive behavior by design.
- **`--live` gate:** by default all offensive components run offline against
  mocks and make no external calls. Four policy exceptions — active
  attack-surface scanning, account-recovery/account-existence probing,
  people-search aggregation, and authenticated platform scraping — are
  default-off, opt-in per invocation via `--live <feature>`, and subject to
  the per-feature conditions in the AGENTS.md safety model (explicit scope,
  read-only or single state-changing request per identifier, rate limits,
  redacted/hashed PII, tamper-evident audit logs, run caps). The gate state is
  printed at the start of every run that enables one. Reporters: a live-gated
  feature run without its documented conditions is in scope for reporting.

## Supported Versions

Only the latest `main` branch is supported.
