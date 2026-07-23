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

## Supported Versions

Only the latest `main` branch is supported.
