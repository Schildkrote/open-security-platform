#!/usr/bin/env bash
# Proof: open-ai-gateway -> Ollama (REAL provider path).
#
# The gateway selects its upstream at startup from OSP_LLM_PROVIDER (main.go):
# with "ollama" it builds provider.Ollama via provider.FromEnv — the Real
# connector, whose Endpoint() is OLLAMA_BASE_URL + /v1/chat/completions — and
# proxies every /v1/ request through the full policy -> rate-limit -> redact ->
# forward -> audit pipeline. This proof runs the ACTUAL gateway binary against
# the local Ollama container and asserts a completion round-trip plus a real
# audit record. No client is reimplemented.
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/common.sh"
require_cmds go curl python3
load_env
ensure_tmp

GW_LISTEN="127.0.0.1:18081"
GW_HOST="http://$GW_LISTEN"
GW_BIN="$LIVE_TMP/open-ai-gateway"
GW_CFG="$LIVE_TMP/gateway-config.json"
GW_AUDIT="$LIVE_TMP/gateway-audit.jsonl"
GW_LOG="$LIVE_TMP/gateway.log"
MODEL="${OLLAMA_MODEL:-smollm2:135m}"

step "Waiting for Ollama health"
wait_url "ollama" "http://127.0.0.1:11434/api/tags" 120 200

step "Ensuring model '$MODEL' is present (pulls over HTTP; small model, first run downloads)"
PULL_BODY="{\"model\":\"$MODEL\",\"stream\":false}"
PULL_OUT="$(curl -s --max-time 900 -X POST http://127.0.0.1:11434/api/pull \
  -H 'content-type: application/json' -d "$PULL_BODY")"
echo "$PULL_OUT" | grep -q '"status":"success"' \
  || die "ollama pull failed for $MODEL: $PULL_OUT"
log "model ready"

step "Building open-ai-gateway (real provider connectors compiled in)"
( cd "$REPO_ROOT/ai-security/open-ai-gateway" && go build -o "$GW_BIN" . ) \
  || die "go build open-ai-gateway failed"

step "Starting gateway with OSP_LLM_PROVIDER=ollama (forces the Real provider path)"
cat > "$GW_CFG" <<EOF
{
  "listen": "$GW_LISTEN",
  "use_mock_upstream": false,
  "audit_file": "$GW_AUDIT"
}
EOF
OSP_LLM_PROVIDER=ollama OLLAMA_BASE_URL="http://127.0.0.1:11434" \
  "$GW_BIN" -config "$GW_CFG" >"$GW_LOG" 2>&1 &
GW_PID=$!
# shellcheck disable=SC2329  # invoked via trap EXIT
cleanup() { kill "$GW_PID" 2>/dev/null || true; wait "$GW_PID" 2>/dev/null || true; }
trap cleanup EXIT

sleep 1
# The gateway logs the selected provider + resolved upstream endpoint.
grep -q "LLM provider ollama -> http://127.0.0.1:11434/v1/chat/completions" "$GW_LOG" \
  || die "gateway did not select the ollama real provider (log: $(cat "$GW_LOG"))"
log "confirmed: gateway routed to the Real Ollama connector endpoint"

wait_url "open-ai-gateway" "$GW_HOST/healthz" 30 200

step "Round-tripping a chat completion through the gateway -> Ollama"
RESP_FILE="$LIVE_TMP/gateway-resp.json"
CODE="$(curl -s -o "$RESP_FILE" -w '%{http_code}' --max-time 120 \
  -X POST "$GW_HOST/v1/chat/completions" \
  -H 'content-type: application/json' \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with one word: OSP\"}]}")"
[[ "$CODE" == "200" ]] || die "gateway returned HTTP $CODE (body: $(cat "$RESP_FILE"))"

CONTENT="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
choices = d.get("choices") or []
print((choices[0].get("message") or {}).get("content", "").strip())
' "$RESP_FILE")"
[[ -n "$CONTENT" ]] || die "completion contained no message content (body: $(cat "$RESP_FILE"))"
log "completion received (${#CONTENT} chars)"

step "Asserting the gateway audited the proxied decision"
grep -q "\"model\":\"$MODEL\"" "$GW_AUDIT" || die "no audit record for model $MODEL in $GW_AUDIT"
grep -q '"action":"allow"' "$GW_AUDIT" || die "audit record does not show an allowed action"
log "audit trail records the allowed proxied request"

pass "open-ai-gateway proxied a completion through the Real Ollama provider connector and audited it"