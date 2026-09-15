#!/usr/bin/env bash
# Drive the real ceremony step twice against two emulated tokens.  The wizard's
# documented loss-resilience path says to register a second token; this test
# proves the second identity does not overwrite the first in the rehearsal.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
export EMU_AGE_IDENTITY_DIR="$ROOT/age"
export PATH="$HERE/../bin:$PATH"

# shellcheck disable=SC1090
source "$HERE/../../scripts/ceremony.sh"
ask(){ return 0; }
pause(){ :; }

pass=0; fail=0
P(){ printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

export EMU_YUBIKEY_SERIAL=25923902
primary="$(step_yubikey_ops 2>&1)"; primary_rc=$?
export EMU_YUBIKEY_SERIAL=25923905
standby="$(step_yubikey_ops 2>&1)"; standby_rc=$?

[ "$primary_rc" = 0 ] && P "primary ceremony step succeeds" || F "primary ceremony step failed (rc=$primary_rc)"
[ "$standby_rc" = 0 ] && P "standby ceremony step succeeds" || F "standby ceremony step failed (rc=$standby_rc)"
primary_rec="$(printf '%s\n' "$primary" | grep '^age1' | tail -1)"
standby_rec="$(printf '%s\n' "$standby" | grep '^age1' | tail -1)"
[ -n "$primary_rec" ] && [ -n "$standby_rec" ] && P "both ceremony steps emit recipients" \
  || F "one ceremony step emitted no recipient"
[ "$primary_rec" != "$standby_rec" ] && P "primary and standby recipients differ" \
  || F "standby ceremony reused the primary recipient"
[ -s "$ROOT/age/ops-identity-25923902.txt" ] && P "primary identity survives second ceremony step" \
  || F "primary identity was overwritten"
[ -s "$ROOT/age/ops-identity-25923905.txt" ] && P "standby identity is stored independently" \
  || F "standby identity was not stored independently"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
