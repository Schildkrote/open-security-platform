# live/ — local Mock→Real connector proof harness

Proves the ROADMAP "Now" item: exercise the components' **Real** connector code
paths against local containerized instances of Keycloak, Wazuh, DefectDojo and
OpenBao (plus Ollama for the AI-gateway provider proof), confirming the
Mock→Real seam end to end.

**Requires Docker** (Docker Engine + the `docker compose` v2 plugin), plus
`go`, `node` (>= 22.6), `python3`, `curl` and `openssl` on the host for the
proof scripts. Nothing here runs in offline CI: the root `make test` /
`make verify` fan-out deliberately excludes this directory.

All published ports are bound to **127.0.0.1 only** — the stack is unreachable
from the network. Credentials are random, local-only values generated into
`live/.env` (git-ignored). **Real credentials must never be committed.**

## Layout

```
live/
├── docker-compose.yml      # pinned, loopback-only stack (see header comments)
├── .env.example            # credential template (make env generates .env from it)
├── Makefile                # env / config / certs / up / proofs / down
├── keycloak/osp-realm.json # realm imported at Keycloak first boot
├── config/wazuh/           # fetched (sha256-pinned) upstream Wazuh config + certs
├── scripts/
│   ├── common.sh             # shared helpers (wait_url, die/pass, env loading)
│   ├── gen-env.sh            # generate .env with random local-only credentials
│   ├── fetch-wazuh-config.sh # fetch + verify pinned wazuh-docker v4.14.7 configs
│   ├── validate_compose.py   # OFFLINE compose validation (YAML, loopback-only…)
│   └── run-proofs.sh         # run every proof, tally PASS/FAIL
└── proofs/
    ├── keycloak.sh           # OIDC smoke: well-known + jwks + token endpoint
    ├── wazuh.sh              # manager API smoke (see "Honest scope" below)
    ├── defectdojo.sh         # pentest-manager → DefectDojo via FindingsSink
    ├── openbao.sh            # open-pam-jit → OpenBao via internal/bao
    └── ollama.sh             # open-ai-gateway → Ollama via provider.Ollama
```

## Exact commands

From the repository root (equivalently: `cd live && make …`):

```bash
# 0. One-time prerequisites: Docker Engine + compose v2 plugin running,
#    go/node/python3/curl/openssl on PATH, network access for image pulls
#    and the sha256-pinned Wazuh config fetch.

# 1. Bring the whole stack up and block until every service is healthy.
#    Generates live/.env (random local-only creds), fetches+verifies the
#    pinned Wazuh configs, generates Wazuh TLS certs via a one-shot service,
#    then `docker compose up -d`. First run: image pulls + DefectDojo
#    migrations take several minutes (up to ~10 on a cold box; Wazuh needs
#    ~4GB RAM headroom).
make live-up

# 2. Run all proofs (each waits for its own service health first).
make live-proofs

#    …or individually:
make -C live proof-openbao        # open-pam-jit → OpenBao (internal/bao)
make -C live proof-defectdojo     # pentest-manager → DefectDojo (--live gate)
make -C live proof-ollama         # open-ai-gateway → Ollama (provider path)
make -C live proof-keycloak       # Keycloak OIDC smoke check
make -C live proof-wazuh          # Wazuh manager API smoke check

# 3. Tear down and REMOVE ALL STATE (named volumes included):
make live-down
#    To keep volumes for a faster restart: make -C live down-keep-volumes

# Offline (no Docker): validate the compose file — YAML, loopback-only ports,
# pinned tags, healthchecks, named volumes:
make -C live verify-compose
```

Each proof prints `PASS: …` and exits 0 on success, or `FAIL: …` with a
diagnostic on stderr and exits non-zero.

## What each proof exercises (real code, not reimplemented clients)

| Proof | Component path exercised | Assertion |
|---|---|---|
| openbao.sh | `identity/open-pam-jit` binary with `BAO_ADDR`+`BAO_TOKEN` set → `internal/bao.NewClient` (Real KV v2 client, per main.go) | JIT credential minted by the component is stored in OpenBao and reads back byte-identical via the component; the key is independently visible in OpenBao KV v2. |
| defectdojo.sh | `offensive/pentest-manager` server with `--live=external-findings-push` + `DEFECTDOJO_URL`/`DEFECTDOJO_API_KEY` → the Real `DefectDojo` FindingsSink in `src/defectdojo.ts` | Finding created through the component's HTTP API appears in DefectDojo with `vuln_id_from_tool` == the component's finding id, severity mapped, attached to the seeded test. |
| ollama.sh | `ai-security/open-ai-gateway` binary with `OSP_LLM_PROVIDER=ollama` → `provider.FromEnv("ollama")` Real connector endpoint | Chat completion round-trips through the gateway's full pipeline and returns content; the audit log records the allowed, proxied request. |
| keycloak.sh | none (infrastructure proof) — realm well-known discovery + jwks + admin-cli password grant | Discovery document is structurally valid for the imported `osp` realm; token endpoint mints a JWT with expected claims. |
| wazuh.sh | none — see honest scope below | Manager REST API answers, JWT auth works, version matches the pinned image, core daemons running. |

### The `--live` gate

pentest-manager only builds the Real DefectDojo sink when the
`external-findings-push` livegate feature is enabled **and** the env vars are
set (`src/server.ts`); otherwise the offline `MockDefectDojo` is used. The
proof therefore passes `--live=external-findings-push` explicitly — the whole
point is to exercise the gated real path — and asserts the gate banner
(`live-gate: ON [external-findings-push]`) appears in the component log before
continuing. The offline default is untouched.

### Honest scope: the Wazuh proof

`soc/open-soar`'s Wazuh connector targets `GET /alerts` with HTTP Basic auth.
Its own source header flags this as "confirm-at-integration" placeholder, and
indeed the real Wazuh 4.14 REST API has no `GET /alerts` route (alerts live in
the indexer; the manager API uses JWT auth). Rather than rewrite the connector
(components stay untouched by this harness) or fake a round-trip, `wazuh.sh`
proves the live stack itself: JWT authentication against the pinned manager,
`GET /manager/info` version match, and daemon status. Making open-soar's
connector real against the 4.14 API shape is tracked as follow-up work.

## Stack ports (all 127.0.0.1)

| Service | Host port | Notes |
|---|---|---|
| Keycloak | 18080 | `start-dev --import-realm`, realm `osp` |
| Wazuh manager API | 15500 | HTTPS, self-signed; agent ports not published |
| DefectDojo (nginx) | 18082 | initializer creates admin from `.env` |
| OpenBao | 18200 | dev mode, in-memory + named volume, KV v2 at `secret/` |
| Ollama | 11434 | model pulled on first proof run (`OLLAMA_MODEL`) |

## Credentials

`make env` (run automatically by `make up`) generates `live/.env` with random
local-only credentials; `live/.gitignore` excludes `.env`, the fetched Wazuh
config and generated certs. Two values are intentionally fixed in the stack
because they must match bcrypt hashes inside the pinned upstream config:
`WAZUH_INDEXER_USER/PASSWORD` (`admin`/`SecretPassword` from the v4.14.7 demo
`internal_users.yml`). The stack is loopback-only and throwaway — but the rule
stands: never put real credentials in anything that gets committed.

## Troubleshooting

- **Regenerated `.env` against an existing stack?** Keycloak/DefectDojo bake
  their admin credentials into their data volumes on first boot. After
  `FORCE=1 bash scripts/gen-env.sh`, run `make live-down` (removes volumes)
  before `make live-up`, or the old credentials still apply and proofs that
  log in will fail.
- `make -C live logs` — tail all containers.
- DefectDojo slow to come up: the initializer runs Django migrations; wait for
  `make -C live wait` instead of polling by hand.
- Wazuh indexer needs `vm.max_map_count >= 262144` on Linux hosts
  (`sudo sysctl -w vm.max_map_count=262144`); Docker Desktop sets it already.
- Reset everything: `make live-down` (removes volumes), then `make live-up`.
- Ollama pull is slow: the proof uses `smollm2:135m` (~270 MB); change
  `OLLAMA_MODEL` in `.env` to pick another small model.
