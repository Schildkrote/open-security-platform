# Security Policy

## Reporting a Vulnerability

Do **not** open a public issue. Email the maintainers with a description,
affected component(s), and reproduction steps. We aim to acknowledge within
5 business days.

## Scope

This repository processes biometric data under a consent-gated model.
Intentionally insecure training targets are out of scope. Reports that a
component ran without a lawful-basis pass, retained raw crops past expiry,
or trained on non-consented images **are in scope**.

## Security Posture

- Pre-release; interfaces may change.
- Lawful-basis gate is mandatory for every face-touching operation.
- Mock path is the default; real models are user-supplied.
- Biometric audit log is hash-chained and tamper-evident.
- Only the latest `main` branch is supported.