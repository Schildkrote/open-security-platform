#!/usr/bin/env bash
# Proof: open-pam-jit -> OpenBao (REAL connector path).
#
# open-pam-jit selects its secrets backend at startup: when BAO_ADDR and
# BAO_TOKEN are set it uses internal/bao.NewClient (the Real OpenBao/Vault KV v2
# client) instead of the offline encrypted vault (see main.go). This proof runs
# the ACTUAL component binary against the local OpenBao container, mints a JIT
# credential, reads the secret back through the component, and then independently
# confirms that exact secret is stored inside OpenBao's KV v2 engine — proving
# the Mock->Real seam end to end. No client is reimplemented: the component's
# own internal/bao code does every OpenBao write/read.
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/common.sh"
require_cmds go curl python3
load_env
ensure_tmp

BAO_HOST="http://127.0.0.1:18200"
PAM_LISTEN="127.0.0.1:18085"
PAM_HOST="http://$PAM_LISTEN"
PAM_BIN="$LIVE_TMP/open-pam-jit"
PAM_LOG="$LIVE_TMP/openbao-pam.log"

step "Waiting for OpenBao health"
wait_url "openbao" "$BAO_HOST/v1/sys/health" 120 200

step "Building open-pam-jit (real internal/bao client compiled in)"
( cd "$REPO_ROOT/identity/open-pam-jit" && go build -o "$PAM_BIN" . ) || die "go build open-pam-jit failed"

step "Starting open-pam-jit with BAO_ADDR/BAO_TOKEN set (forces the Real OpenBao backend)"
BAO_ADDR="$BAO_HOST" BAO_TOKEN="$BAO_ROOT_TOKEN" \
  "$PAM_BIN" -listen "$PAM_LISTEN" -audit "$LIVE_TMP/openbao-pam-audit.jsonl" \
  >"$PAM_LOG" 2>&1 &
PAM_PID=$!
# shellcheck disable=SC2329  # invoked via trap EXIT
cleanup() { kill "$PAM_PID" 2>/dev/null || true; wait "$PAM_PID" 2>/dev/null || true; }
trap cleanup EXIT

# The component logs which backend it picked — assert it is OpenBao, not the vault.
sleep 1
if ! grep -q "secrets backend: OpenBao" "$PAM_LOG"; then
  die "open-pam-jit did not select the OpenBao backend (log: $(cat "$PAM_LOG"))"
fi
log "confirmed: open-pam-jit selected the Real OpenBao backend"

wait_url "open-pam-jit" "$PAM_HOST/healthz" 30 200

step "Requesting + approving JIT access to a seeded target (prod-db)"
REQ_ID="$(curl -s -X POST "$PAM_HOST/requests" \
  -H 'content-type: application/json' \
  -d '{"requester":"osp-proof","target_id":"prod-db","justification":"live proof harness","duration_sec":120}' \
  | json_field id)"
[[ -n "$REQ_ID" ]] || die "no request id returned (target prod-db missing?)"

CRED_ID="$(curl -s -X POST "$PAM_HOST/requests/$REQ_ID/approve" \
  -H 'content-type: application/json' -d '{"approver":"osp-approver"}' | json_field id)"
[[ -n "$CRED_ID" ]] || die "approval returned no credential id"

step "Reading the credential secret back through open-pam-jit (served from OpenBao)"
SECRET="$(curl -s -X POST "$PAM_HOST/credentials/$CRED_ID/secret" | json_field secret)"
[[ -n "$SECRET" ]] || die "open-pam-jit returned an empty secret for credential $CRED_ID"
log "component returned a non-empty secret (${#SECRET} chars)"

step "Independently verifying the secret is stored in OpenBao KV v2"
# KV v2 list lives under the metadata path; the bao client's mount is "secret".
KEYS="$(curl -s -H "X-Vault-Token: $BAO_ROOT_TOKEN" "$BAO_HOST/v1/secret/metadata/?list=true" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(d.get("data",{}).get("keys",[])))')"
[[ -n "$KEYS" ]] || die "OpenBao has no keys under secret/ — the real connector never wrote"

FOUND=""
for k in $KEYS; do
  val="$(curl -s -H "X-Vault-Token: $BAO_ROOT_TOKEN" "$BAO_HOST/v1/secret/data/$k" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("data",{}).get("data",{}).get("value",""))')"
  if [[ "$val" == "$SECRET" ]]; then
    FOUND="$k"
    break
  fi
done

[[ -n "$FOUND" ]] || die "secret returned by open-pam-jit was not found in OpenBao (keys: $KEYS)"
log "secret round-tripped through OpenBao at key '$FOUND'"

pass "open-pam-jit stored and retrieved a JIT secret via the Real OpenBao connector (internal/bao)"