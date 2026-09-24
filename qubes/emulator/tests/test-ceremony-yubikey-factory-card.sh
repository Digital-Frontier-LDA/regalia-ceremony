#!/usr/bin/env bash
# step_yubikey_ops on a FACTORY YubiKey 5.7 (default PIN, default AES192 management key). Measured
# on 2026-09-23: age-plugin-yubikey 0.5.0 refuses that management key outright, and on a default PIN
# it sets the PUK to the new PIN. So the step must set the PIN and PUK to the values step 0 loaded
# for ESCROW (never prompt-typed ones), prove the escrowed PIN opens the card, switch to a
# PIN-protected TDES management key, and only then generate. A failed generation is a failure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin"
export CALLS="$ROOT/calls" PATH="$ROOT/bin:$PATH"
cat > "$ROOT/bin/ykman" <<'S'
#!/usr/bin/env bash
echo "ykman $*" >> "$CALLS"
if [ "$*" = "piv info" ]; then
  printf '%s\n' "PIV version:              5.7.4" "PIN tries remaining:      3/3" \
    "Management key algorithm: AES192" "WARNING: Using default PIN!" "WARNING: Using default PUK!" \
    "WARNING: Using default Management key!"
fi
S
cat > "$ROOT/bin/age-plugin-yubikey" <<'S'
#!/usr/bin/env bash
echo "age-plugin-yubikey $*" >> "$CALLS"
[ -n "${PLUGIN_FAILS:-}" ] && { echo "Custom unprotected non-TDES management keys are not supported." >&2; exit 1; }
echo "age1yubikey1qFACTORY000recipient"
S
chmod +x "$ROOT/bin/"*

# shellcheck disable=SC1090
source "$HERE/../../scripts/ceremony.sh"
ask(){ return 0; }
pause(){ :; }

pass=0; fail=0
P(){ printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

# Without step 0 there is no escrowed value to put on the card: refuse before touching it.
out="$(step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin" "$CALLS" && P "a factory card without step 0's values is refused before any change" \
  || F "rc=$rc; calls: $(tr '\n' ';' < "$CALLS")"

: > "$CALLS"
# shellcheck disable=SC2034  # read by the sourced step_yubikey_ops
yubikey_piv_pin=24681357 yubikey_piv_puk=24681357
out="$(step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin" "$CALLS" && P "an escrowed PIN equal to the PUK is refused" || F "equal PIN and PUK accepted"

: > "$CALLS"
# shellcheck disable=SC2034  # read by the sourced step_yubikey_ops
yubikey_piv_pin=24681357 yubikey_piv_puk=97531864
out="$(step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "the step succeeds on a factory card with step 0's values" || F "the step failed (rc=$rc): $out"
order="$(grep -oE 'change-pin -P [0-9]+ -n [0-9]+|change-puk -p [0-9]+ -n [0-9]+|change-management-key -a TDES --protect|--generate' "$CALLS" | tr '\n' ';')"
[ "$order" = "change-pin -P 123456 -n 24681357;change-puk -p 12345678 -n 97531864;change-pin -P 24681357 -n 24681357;change-management-key -a TDES --protect;--generate;" ] \
  && P "escrowed PIN, then escrowed PUK, then the binding proof, then a protected TDES key, then generate" \
  || F "wrong sequence: '$order'"
grep -q "PIN BINDING PROVEN" <<< "$out" && P "the binding proof is reported" || F "no binding proof"
grep -qE "24681357|97531864" <<< "$out" && F "a PIN or PUK was printed" || P "no PIN or PUK is printed"

# A second factory token in the same run must not receive the same escrowed PIN.
: > "$CALLS"
out="$(yubikey_pins_set_this_run=1 step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin" "$CALLS" && grep -q "separate run" <<< "$out" \
  && P "a second factory token in the same run is refused before its PIN is set" || F "second token got the same PIN (rc=$rc)"

: > "$CALLS"
out="$(PLUGIN_FAILS=1 step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && P "a failed generation is reported as a failure" || F "a failed generation returned success"
grep -q "no identity was created" <<< "$out" && P "the failure says no identity exists" || F "no failure message: $out"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
