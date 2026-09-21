#!/usr/bin/env bash
# Proof: OIDC smoke check against Keycloak.
#
# Deliberately NOT a full OIDC client (no authorization-code flow, no client
# registration): it proves the local IdP is real and usable by the platform's
# components — the realm imported at boot, the well-known discovery document
# serves correct endpoints, and the token endpoint actually mints a JWT via the
# master realm's admin-cli password grant. platform/auth consumes exactly these
# discovery semantics (its header docs name Keycloak as the production IdP).
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/common.sh"
require_cmds curl python3
load_env

KC="http://127.0.0.1:18080"
REALM="${KEYCLOAK_REALM:-osp}"

step "Waiting for Keycloak to serve the master realm"
# NOTE: KC 26 serves /health/* on the management port (9000, container-internal
# — the compose healthcheck probes it); the published main port serves realms.
# A ready server answers GET /realms/master with 200.
wait_url "keycloak" "$KC/realms/master" 300 200

step "Realm '$REALM' is served"
CODE="$(http_code "$KC/realms/$REALM")"
[[ "$CODE" == "200" ]] || die "GET /realms/$REALM returned HTTP $CODE (realm import failed?)"

step "Fetching .well-known/openid-configuration for realm '$REALM'"
WK="$LIVE_TMP/keycloak-well-known.json"
mkdir -p "$LIVE_TMP"
CODE="$(curl -s -o "$WK" -w '%{http_code}' "$KC/realms/$REALM/.well-known/openid-configuration")"
[[ "$CODE" == "200" ]] || die "well-known discovery returned HTTP $CODE"

python3 - "$WK" "$REALM" <<'EOF' || die "well-known document failed structural assertions"
import json, sys
doc = json.load(open(sys.argv[1]))
realm = sys.argv[2]
def need(cond, msg):
    if not cond:
        print(f"assertion failed: {msg}", file=sys.stderr)
        sys.exit(1)
need(doc.get("issuer", "").endswith(f"/realms/{realm}"), f"issuer {doc.get('issuer')!r} ends with /realms/{realm}")
for ep in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"):
    need(ep in doc, f"{ep} present")
    need(doc[ep].startswith("http"), f"{ep} is an absolute URL")
need(doc["token_endpoint"].endswith(f"/realms/{realm}/protocol/openid-connect/token"),
     "token_endpoint points at the realm's openid-connect token route")
need(doc["jwks_uri"].endswith(f"/realms/{realm}/protocol/openid-connect/certs"),
     "jwks_uri points at the realm's certs route")
print("well-known document structurally valid", file=sys.stderr)
EOF

step "jwks_uri serves signing keys"
KEYS="$(curl -s "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["jwks_uri"])' "$WK")" \
  | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("keys",[])))')"
[[ "$KEYS" -ge 1 ]] || die "jwks_uri returned $KEYS keys"
log "jwks exposes $KEYS signing key(s)"

step "Token endpoint mints a JWT (master realm, admin-cli password grant)"
TOKEN="$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  --data-urlencode "username=${KEYCLOAK_ADMIN_USER}" \
  --data-urlencode "password=${KEYCLOAK_ADMIN_PASSWORD}" \
  | json_field access_token)"
[[ -n "$TOKEN" ]] || die "token endpoint returned no access_token (bad admin credentials?)"

python3 - "$TOKEN" <<'EOF' || die "minted JWT failed claim assertions"
import base64, json, sys
parts = sys.argv[1].split(".")
assert len(parts) == 3, "not a JWS compact token"
payload = parts[1] + "=" * (-len(parts[1]) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
assert claims.get("preferred_username"), f"no preferred_username in {claims}"
assert "/realms/master" in claims.get("iss", ""), f"unexpected issuer {claims.get('iss')}"
print(f"JWT ok: user={claims['preferred_username']} iss={claims['iss']}", file=sys.stderr)
EOF

pass "Keycloak realm discovery + token endpoint round-trip verified (OIDC smoke)"