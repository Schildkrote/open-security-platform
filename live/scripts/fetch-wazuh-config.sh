#!/usr/bin/env bash
# Fetch the pinned Wazuh single-node configuration files (wazuh-docker
# v4.14.7) into live/config/wazuh/ and verify their sha256 checksums.
# These are third-party config files the wazuh containers bind-mount; they are
# git-ignored and regenerable. Requires network access on first run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIVE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST="$LIVE_DIR/config/wazuh"
REF="v4.14.7"
BASE="https://raw.githubusercontent.com/wazuh/wazuh-docker/$REF/single-node/config"

# path-in-upstream-repo  destination-filename  expected-sha256 (pinned $REF)
FILES="
certs.yml|certs.yml|01dfd585599e9b8d56c7cafd874eae7ff27ee538af250fc13d55afd1f80abd68
wazuh_indexer/wazuh.indexer.yml|wazuh.indexer.yml|8273837e2047a6a02a05c2ac3802c7d19e578a454e6250e0e1b5e2a8693bf295
wazuh_indexer/internal_users.yml|internal_users.yml|51aa50ddb9783a711b923f5fd32010a11fa6a5fa23fb140fd47a3ae3e0c82b2c
wazuh_cluster/wazuh_manager.conf|wazuh_manager.conf|b137a003c617aee4a980e9eb132ced34c746a7807089a67a107dbbae74518fce
"

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "need sha256sum or shasum" >&2
  exit 1
fi

mkdir -p "$DEST"

echo "$FILES" | while IFS='|' read -r src name expected; do
  [[ -z "$src" ]] && continue
  target="$DEST/$name"
  if [[ -f "$target" && "$(sha256_of "$target")" == "$expected" ]]; then
    chmod 644 "$target" # ensure container UIDs can read even if it was 600
    echo "ok (cached, sha256 verified): $name"
    continue
  fi
  tmp="$(mktemp)"
  if ! curl -fsSL "$BASE/$src" -o "$tmp"; then
    rm -f "$tmp"
    echo "FAIL: could not download $BASE/$src (network required on first run)" >&2
    exit 1
  fi
  actual="$(sha256_of "$tmp")"
  if [[ "$actual" != "$expected" ]]; then
    rm -f "$tmp"
    echo "FAIL: sha256 mismatch for $name (got $actual, want $expected) — upstream changed?" >&2
    exit 1
  fi
  mv "$tmp" "$target"
  chmod 644 "$target" # readable by container UIDs; upstream demo config, no secrets
  echo "fetched + verified ($REF): $name"
done
