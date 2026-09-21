#!/usr/bin/env bash
# Run every proof under live/proofs/ in order. Exits non-zero if any proof
# fails and prints a final tally. Each proof prints PASS on success.
#
# Written for bash >= 3.2 (macOS default): avoids `"${arr[@]}"` on possibly
# empty arrays under `set -u`, which errors before bash 4.4.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROOFS_DIR="$SCRIPT_DIR/../proofs"

failed=""
failed_count=0
passed=""
passed_count=0

for script in "$PROOFS_DIR"/*.sh; do
  name="$(basename "$script" .sh)"
  echo
  echo "############ PROOF: $name ############"
  if bash "$script"; then
    passed="$passed $name"
    passed_count=$((passed_count + 1))
  else
    failed="$failed $name"
    failed_count=$((failed_count + 1))
    echo "FAIL: $name" >&2
  fi
done

echo
echo "===== proof tally ====="
for p in $passed; do echo "  PASS $p"; done
for f in $failed; do echo "  FAIL $f"; done

if (( failed_count > 0 )); then
  echo "PROOFS FAILED: $failed_count failed, $passed_count passed" >&2
  exit 1
fi
echo "ALL PROOFS PASSED ($passed_count)"
