# open-pam-jit

An open **PAM / JIT Access Broker**: request-based privileged access with
approvals, short-lived credentials, an encrypted secrets vault, break-glass,
session recording, and a tamper-evident audit trail. Zero external
dependencies (Go standard library only — AES-256-GCM + PBKDF2).

## Features (MVP)

- **Access requests** with justification and requested duration
- **Approval workflow** — approving mints a **temporary credential** (auto-expiring)
- **Encrypted secrets vault** — secrets stored as AES-256-GCM ciphertext, key
  derived from a passphrase via PBKDF2-HMAC-SHA256
- **Credential lifecycle** — validate (expiry/revocation), fetch secret, revoke
- **Break-glass** — immediate short-lived access, flagged and logged loudly
- **Session recording** — hash-chained transcripts with integrity verification
- **Tamper-evident audit log** (hash-chained)

## Quickstart

```bash
go run . -listen :8085 -passphrase change-me
```

```bash
# Request access
curl -X POST localhost:8085/requests \
  -d '{"requester":"alice","target_id":"prod-db","justification":"incident","duration_sec":3600}'

# Approve -> returns a temporary credential
curl -X POST localhost:8085/requests/<REQ_ID>/approve -d '{"approver":"bob"}'

# Validate + fetch the secret (only while valid)
curl -X POST localhost:8085/credentials/<CRED_ID>/validate
curl -X POST localhost:8085/credentials/<CRED_ID>/secret

# Revoke
curl -X POST localhost:8085/credentials/<CRED_ID>/revoke -d '{"actor":"bob"}'

# Break-glass + simulated session recording
curl -X POST localhost:8085/break-glass -d '{"requester":"oncall","target_id":"prod-db","reason":"outage"}'
curl -X POST localhost:8085/sessions -d '{"user":"alice","target":"prod-db","commands":["SELECT 1"]}'
curl localhost:8085/audit/verify   # {"valid":true}
```

## Tests

```bash
go test ./...
```

## License

Apache-2.0
