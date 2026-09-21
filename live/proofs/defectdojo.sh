#!/usr/bin/env bash
# Proof: pentest-manager -> DefectDojo (REAL connector path, --live gated).
#
# pentest-manager only constructs the Real DefectDojo sink when the
# `external-findings-push` live feature is enabled AND DEFECTDOJO_URL +
# DEFECTDOJO_API_KEY are set (src/server.ts + src/livegate.ts); otherwise it
# uses the offline MockDefectDojo. This proof runs the ACTUAL component with the
# gate explicitly opened, creates a finding through its HTTP API, and asserts the
# finding lands in a live DefectDojo instance via the existing FindingsSink /
# DefectDojo Real client — tied back by vuln_id_from_tool == the component's
# finding id. No DD client is reimplemented.
#
# WHY THE GATE IS PASSED: the gate exists so the real (state-changing, external)
# push is opt-in per invocation. A live proof MUST exercise the real path, so we
# pass --live=external-findings-push explicitly and target only the loopback
# DefectDojo container. The offline default (mock) is untouched.
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/common.sh"
require_cmds node curl python3
load_env
ensure_tmp

DD_HOST="http://127.0.0.1:18082"
PM_PORT="18087"
PM_HOST="http://127.0.0.1:$PM_PORT"
PM_LOG="$LIVE_TMP/defectdojo-pm.log"

step "Waiting for DefectDojo health"
wait_url "defectdojo" "$DD_HOST/login/" 600 200

step "Obtaining a DefectDojo API token for ${DD_ADMIN_USER}"
DD_TOKEN="$(curl -s -X POST "$DD_HOST/api/v2/api-token-auth/" \
  -d "username=${DD_ADMIN_USER}" -d "password=$DD_ADMIN_PASSWORD" | json_field token)"
[[ -n "$DD_TOKEN" ]] || die "could not obtain DefectDojo API token (check DD_ADMIN_PASSWORD in .env)"
AUTH="Authorization: Token $DD_TOKEN"

# dd_post PATH JSON — POSTs once to the DD v2 API, prints the response body,
# dies on error. Writes the body to a temp file so status and body come from the
# same single request (never POST twice — that would create duplicate objects).
dd_post() {
  local path="$1" body="$2" tmpfile code err
  tmpfile="$(mktemp)"
  code="$(curl -s -o "$tmpfile" -w '%{http_code}' -X POST "$DD_HOST$path" \
    -H "$AUTH" -H 'content-type: application/json' -d "$body")"
  if [[ "$code" != "201" && "$code" != "200" ]]; then
    err="$(cat "$tmpfile")"
    rm -f "$tmpfile"
    die "POST $path returned HTTP $code: $err"
  fi
  cat "$tmpfile"
  rm -f "$tmpfile"
}

step "Seeding DefectDojo: product_type -> product -> engagement -> test"
STAMP="$(date +%s)"
PT_ID="$(dd_post "/api/v2/product_types/" "{\"name\":\"OSP Proof PT $STAMP\"}" | json_field id)"
PROD_ID="$(dd_post "/api/v2/products/" \
  "{\"name\":\"OSP Proof Product $STAMP\",\"description\":\"live proof harness\",\"prod_type\":$PT_ID}" | json_field id)"
TODAY="$(date +%Y-%m-%d)"
TOMORROW="$(python3 -c 'import datetime; print((datetime.date.today()+datetime.timedelta(days=1)).isoformat())')"
ENG_ID="$(dd_post "/api/v2/engagements/" \
  "{\"name\":\"OSP Proof Eng $STAMP\",\"product\":$PROD_ID,\"target_start\":\"$TODAY\",\"target_end\":\"$TOMORROW\",\"status\":\"In Progress\",\"engagement_type\":\"Interactive\"}" | json_field id)"

# Reuse an existing Test_Type (DD seeds defaults); fall back to creating one.
TT_ID="$(curl -s "$DD_HOST/api/v2/test_types/?limit=1" -H "$AUTH" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin).get("results",[]); print(r[0]["id"] if r else "")')"
if [[ -z "$TT_ID" ]]; then
  TT_ID="$(dd_post "/api/v2/test_types/" "{\"name\":\"OSP Proof Scanner $STAMP\"}" | json_field id)"
fi
TEST_ID="$(dd_post "/api/v2/tests/" \
  "{\"engagement\":$ENG_ID,\"test_type\":$TT_ID,\"target_start\":\"${TODAY}T00:00:00Z\",\"target_end\":\"${TOMORROW}T00:00:00Z\"}" | json_field id)"
log "seeded product_type=$PT_ID product=$PROD_ID engagement=$ENG_ID test_type=$TT_ID test=$TEST_ID"

step "Starting pentest-manager with the external-findings-push live gate ON"
cd "$REPO_ROOT/offensive/pentest-manager"
DEFECTDOJO_URL="$DD_HOST" DEFECTDOJO_API_KEY="$DD_TOKEN" DB_PATH=":memory:" PORT="$PM_PORT" \
  node --experimental-strip-types --no-warnings src/server.ts --live=external-findings-push \
  >"$PM_LOG" 2>&1 &
PM_PID=$!
# shellcheck disable=SC2329  # invoked via trap EXIT
cleanup() { kill "$PM_PID" 2>/dev/null || true; wait "$PM_PID" 2>/dev/null || true; }
trap cleanup EXIT

# The gate prints its state to stderr; assert the real feature is active.
sleep 2
grep -q "live-gate: ON \[external-findings-push\]" "$PM_LOG" \
  || die "pentest-manager did not open the live gate (log: $(cat "$PM_LOG"))"
log "confirmed: live-gate ON [external-findings-push] (Real DefectDojo sink constructed)"

wait_url "pentest-manager" "$PM_HOST/healthz" 30 200

step "Creating an engagement + finding through pentest-manager's HTTP API"
CLIENT_ID="$(curl -s -X POST "$PM_HOST/clients" -H 'content-type: application/json' \
  -d '{"name":"OSP Proof Client"}' | json_field id)"
PM_ENG_ID="$(curl -s -X POST "$PM_HOST/engagements" -H 'content-type: application/json' \
  -d "{\"client_id\":\"$CLIENT_ID\",\"name\":\"OSP Proof Engagement\"}" | json_field id)"

UNIQUE_TITLE="OSP Live Proof SQLi $STAMP"
# The DD-required fields (test, found_by, numerical_severity) ride along so
# mapFinding forwards them to the Real DefectDojo sink; the Mock path ignores
# them. numerical_severity mirrors DD's own severity->S-level mapping (High=S1).
PM_FINDING_ID="$(curl -s -X POST "$PM_HOST/engagements/$PM_ENG_ID/findings" \
  -H 'content-type: application/json' \
  -d "{\"title\":\"$UNIQUE_TITLE\",\"description\":\"unsanitized input in login form\",\"severity\":\"high\",\"cvss\":8.1,\"cwe\":89,\"test\":$TEST_ID,\"found_by\":[$TT_ID],\"numerical_severity\":\"S1\"}" \
  | json_field id)"
[[ -n "$PM_FINDING_ID" ]] || die "pentest-manager returned no finding id"
log "pentest-manager finding id=$PM_FINDING_ID"

step "Asserting the finding appears in DefectDojo (pushed via the Real FindingsSink)"
# pushToSink is best-effort/async; poll DD until the finding shows up.
DD_FINDINGS_JSON="$LIVE_TMP/dd-findings.json"
COUNT=0
for _ in $(seq 1 20); do
  curl -s --get "$DD_HOST/api/v2/findings/" \
    --data-urlencode "exact_title=$UNIQUE_TITLE" -H "$AUTH" -o "$DD_FINDINGS_JSON"
  COUNT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("count",0))' "$DD_FINDINGS_JSON")"
  [[ "$COUNT" -ge 1 ]] && break
  sleep 2
done

python3 - "$PM_FINDING_ID" "$UNIQUE_TITLE" "$TEST_ID" "$DD_FINDINGS_JSON" <<'EOF' || die "DefectDojo did not receive the pushed finding"
import json, sys
pm_id, title, test_id, path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
data = json.load(open(path))
results = data.get("results", [])
assert results, f"no findings with title {title!r} in DefectDojo"
f = results[0]
# DefectDojo title-cases finding titles on save, so compare case-insensitively.
assert f.get("title", "").lower() == title.lower(), \
    f"title mismatch: {f.get('title')!r} != {title!r}"
assert f.get("vuln_id_from_tool") == pm_id, \
    f"vuln_id_from_tool {f.get('vuln_id_from_tool')!r} != pentest-manager id {pm_id!r}"
assert f.get("severity") == "High", f"severity not mapped to High: {f.get('severity')!r}"
assert f.get("test") == test_id, f"finding attached to test {f.get('test')!r} != {test_id!r}"
print(f"DefectDojo finding id={f.get('id')} vuln_id_from_tool={f.get('vuln_id_from_tool')} severity={f.get('severity')}", file=sys.stderr)
EOF

pass "pentest-manager pushed a finding to DefectDojo through the Real FindingsSink (live gate open)"