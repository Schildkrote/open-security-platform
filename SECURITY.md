# Security Policy

## Supported versions
Pre-release (`main` only). No stability guarantees.

## Reporting
Email security concerns to the repository owner. Do not open public issues
for vulnerabilities that enable unauthorized access to sensor or case data.

## Design constraints
- Purpose-bound access (policy engine)
- Hash-chained audit of actions and sensitive reads
- Default deny on ALPR historical queries without case/warrant context
- Connectors never embed secrets
- Biometric material is referenced by pseudonym/hash only
