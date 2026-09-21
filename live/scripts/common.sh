#!/usr/bin/env bash
# Shared helpers for the live proof scripts. Source this file; do not execute.
#
# Every helper writes diagnostics to stderr so a proof script's stdout stays
# clean for its final PASS line.

LIVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC2034  # REPO_ROOT is used by the sourcing proof scripts.
REPO_ROOT="$(cd "$LIVE_DIR/.." && pwd)"
LIVE_TMP="$LIVE_DIR/tmp"

log()  { printf '[live] %s\n' "$*" >&2; }
step() { printf '==> %s\n' "$*" >&2; }

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'PASS: %s\n' "$*"
  exit 0
}

require_cmds() {
  local c
  for c in "$@"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      die "required command not found: $c (see live/README.md prerequisites)"
    fi
  done
}

load_env() {
  if [[ ! -f "$LIVE_DIR/.env" ]]; then
    die "live/.env is missing — run 'make env' in live/ first (generates random local-only credentials)"
  fi
  set -a
  # shellcheck source=/dev/null
  source "$LIVE_DIR/.env"
  set +a
}

ensure_tmp() {
  mkdir -p "$LIVE_TMP"
}

# http_code URL — prints the HTTP status code (000 when unreachable).
http_code() {
  curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null || true
}

# wait_url NAME URL TIMEOUT_SECS [EXPECTED_CODE]
# Polls URL until it returns EXPECTED_CODE (default: any HTTP response at all).
wait_url() {
  local name="$1" url="$2" timeout="${3:-300}" expected="${4:-}"
  local deadline code
  deadline=$(( $(date +%s) + timeout ))
  while true; do
    code="$(http_code "$url")"
    if [[ -n "$expected" ]]; then
      if [[ "$code" == "$expected" ]]; then
        log "$name is ready (HTTP $code)"
        return 0
      fi
    else
      if [[ "$code" != "000" ]]; then
        log "$name is responding (HTTP $code)"
        return 0
      fi
    fi
    if (( $(date +%s) >= deadline )); then
      die "timed out after ${timeout}s waiting for $name at $url (last HTTP code: ${code:-none})"
    fi
    sleep 3
  done
}

# json_field — reads a JSON object on stdin, prints one field (empty if absent).
json_field() {
  python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
value = data
for key in sys.argv[1].split("."):
    if isinstance(value, dict):
        value = value.get(key)
    else:
        value = None
        break
if value is not None:
    print(value)
' "$1"
}
