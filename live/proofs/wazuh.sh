#!/usr/bin/env bash
# Proof: Wazuh single-node manager smoke check (local stack).
#
# HONEST SCOPE: this does NOT go through soc/open-soar's Wazuh connector. That
# connector's Real client targets `GET /alerts` with Basic auth — a placeholder
# whose own source header says "exact endpoints/payloads should be confirmed
# against the target version at deploy time". The real Wazuh 4.14 REST API has
# no GET /alerts route (alerts live in the indexer) and authenticates with a JWT
# from POST /security/user/authenticate. Rewriting the connector is out of scope
# for the harness (components stay untouched); what this script proves is that
# the pinned Wazuh stack in live/docker-compose.yml is real and healthy: the
# manager API answers, our credentials mint a JWT, and the reported version
# matches the pinned image.
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/common.sh"
require_cmds curl python3
load_env

WAZUH_API="https://127.0.0.1:15500"

step "Waiting for Wazuh manager API"
# Any HTTP response (even 401) means the API daemon is up.
wait_url "wazuh-manager" "$WAZUH_API/" 600

step "Authenticating via POST /security/user/authenticate (JWT)"
TOKEN="$(curl -sk -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" \
  -X POST "$WAZUH_API/security/user/authenticate?raw=true")"
# raw=true returns the bare token; a JSON error body means auth failed.
if [[ -z "$TOKEN" || "$TOKEN" == *"{"* ]]; then
  die "wazuh API auth failed: $TOKEN"
fi
log "JWT obtained (${#TOKEN} chars)"

step "GET /manager/info through the authenticated API"
INFO="$(curl -sk -H "Authorization: Bearer $TOKEN" "$WAZUH_API/manager/info")"
ITEM="$(echo "$INFO" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["data"]["affected_items"][0]))')"
VERSION="$(echo "$ITEM" | json_field version)"
TYPE="$(echo "$ITEM" | json_field type)"
[[ "$VERSION" == v4.14.* && "$TYPE" == "server" ]] \
  || die "unexpected manager info (version=$VERSION type=$TYPE)"
log "manager version=$VERSION type=$TYPE"

step "Manager status reports the daemons running"
STATUS_FILE="$LIVE_TMP/wazuh-status.json"
mkdir -p "$LIVE_TMP"
curl -sk -H "Authorization: Bearer $TOKEN" "$WAZUH_API/manager/status" -o "$STATUS_FILE"
python3 - "$STATUS_FILE" <<'EOF' || die "wazuh manager daemons not running per /manager/status"
import json, sys
d = json.load(open(sys.argv[1]))
item = d["data"]["affected_items"][0]
# Daemon states are direct keys of the affected item (see WazuhDaemonsStatus).
for required in ("wazuh-modulesd", "wazuh-analysisd", "wazuh-remoted", "wazuh-execd", "wazuh-apid"):
    assert item.get(required) == "running", f"{required} is {item.get(required)!r}, not running"
print("all required daemons running", file=sys.stderr)
EOF

pass "Wazuh single-node manager is healthy: JWT auth + manager info/status verified (see script header re: open-soar connector gap)"