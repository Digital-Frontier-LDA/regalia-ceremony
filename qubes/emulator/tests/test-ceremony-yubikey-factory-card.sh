#!/usr/bin/env bash
# step_yubikey_ops on a FACTORY YubiKey 5.7 (default PIN, default AES192 management key). Measured
# on 2026-09-23: age-plugin-yubikey 0.5.0 refuses that management key outright, and on a default PIN
# it sets the PUK to the new PIN. So the step must set the PIN and PUK to the values step 0 loaded
# for ESCROW (never prompt-typed ones), prove the escrowed PIN opens the card, switch to a
# PIN-protected TDES management key, and only then generate. A failed generation is a failure.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin"
export CALLS="$ROOT/calls" PATH="$ROOT/bin:$PATH"
# The stub records each call's ARGV, and for a PIN or PUK change what it read on STDIN, as the real
# ykman does when the -P/-p/-n options are left out and its stdin is not a terminal: one line per
# question, the current value and then the new one (ykman/_cli/util.py click_prompt). A change
# given no value is a failure, as a prompt nobody answers would be.
cat > "$ROOT/bin/ykman" <<'S'
#!/usr/bin/env bash
line="ykman $*"
if [ "${1:-}" = --device ]; then [ "$2" = "${YK_SERIAL:-36345471}" ] || { echo "$line" >> "$CALLS"; echo "Failed connecting to a YubiKey with serial: $2" >&2; exit 1; }; shift 2; fi
case "$*" in
  "piv access change-pin"|"piv access change-puk")
    cur=""; new=""
    [ -t 0 ] || { IFS= read -r cur; IFS= read -r new; }
    echo "$line STDIN $cur $new" >> "$CALLS"
    [ -n "$cur" ] && [ -n "$new" ] || { echo "Aborted: no value on stdin" >&2; exit 1; } ;;
  *) echo "$line" >> "$CALLS" ;;
esac
[ "$*" = "info" ] && { echo "Device type: YubiKey 5 NFC"; [ -n "${NO_SERIAL:-}" ] || echo "Serial number: ${YK_SERIAL:-36345471}"; }
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
# Step 0 generated the sets in this run (the normal case): a new token takes the next free set.
# shellcheck disable=SC2034  # read by the sourced step_yubikey_ops
state_step0_done=1 state_pins_generated_this_run=1
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
yubikey_a_piv_pin=24681357 yubikey_a_piv_puk=24681357
out="$(step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin" "$CALLS" && P "an escrowed PIN equal to the PUK is refused" || F "equal PIN and PUK accepted"

: > "$CALLS"
# shellcheck disable=SC2034  # read by the sourced step_yubikey_ops
yubikey_a_piv_pin=24681357 yubikey_a_piv_puk=97531864
out="$(step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "the step succeeds on a factory card with step 0's values" || F "the step failed (rc=$rc): $out"
order="$(grep -oE 'change-pin STDIN [0-9]+ [0-9]+|change-puk STDIN [0-9]+ [0-9]+|change-management-key -a TDES --protect|--generate' "$CALLS" | tr '\n' ';')"
unbound="$(grep -E 'change-pin|change-puk|change-management-key' "$CALLS" | grep -v -- '--device 36345471 ' || true)"
[ -z "$unbound" ] && grep -q -- "--generate --serial 36345471" "$CALLS" && P "every change and the generation are bound to serial 36345471" || F "unbound: $unbound"
[ "$order" = "change-pin STDIN 123456 24681357;change-puk STDIN 12345678 97531864;change-pin STDIN 24681357 24681357;change-management-key -a TDES --protect;--generate;" ] \
  && P "escrowed PIN, then escrowed PUK, then the binding proof, then a protected TDES key, then generate" \
  || F "wrong sequence: '$order'"
grep -q "PIN BINDING PROVEN" <<< "$out" && P "the binding proof is reported" || F "no binding proof"
grep -q "serial 36345471) is YubiKey A" <<< "$out" && P "the first token is YubiKey A, named with its serial" || F "set A not named: $(grep -i 'is YubiKey' <<< "$out")"
grep -qE "24681357|97531864" <<< "$out" && F "a PIN or PUK was printed" || P "no PIN or PUK is printed"
# NOT ON A COMMAND LINE (#98): argv is readable by every local user while the command runs. What
# the stub read on stdin is cut off; nothing left may hold a value or a value-taking option.
argv="$(sed 's/ STDIN .*//' "$CALLS")"
grep -qE "24681357|97531864|123456|12345678" <<< "$argv" && F "a PIN or PUK is on a command line: $(grep -E '24681357|97531864|123456|12345678' <<< "$argv" | head -2)" \
  || P "no PIN or PUK, new or factory, is in the argv of any call"
grep -E "change-pin|change-puk" <<< "$argv" | grep -qE -- " (-P|-p|-n|--pin|--puk|--new-pin|--new-puk)( |=|$)" \
  && F "a PIN or PUK change still passes a value option" || P "the PIN and PUK changes pass no value option at all"
[ "$(grep -cE 'change-(pin|puk) STDIN [0-9]+ [0-9]+$' "$CALLS")" = 3 ] && P "all three changes got both values on standard input" \
  || F "a change did not get its two values on stdin: $(grep -E 'change-(pin|puk)' "$CALLS" | tr '\n' ';')"
# The instrument: the same cut-and-search finds a PIN that IS on a command line.
grep -qE "24681357" <<< "$(sed 's/ STDIN .*//' <<< "ykman --device 1 piv access change-pin -P 123456 -n 24681357")" \
  && P "the check sees a PIN given as an option value" || F "the argv check cannot see a PIN on a command line"
# A value that would be read as a different answer never reaches the card.
: > "$CALLS"
out2="$(yk_piv_change 36345471 change-pin 123456 "" 2>&1)"; rc2=$?
[ "$rc2" != 0 ] && [ ! -s "$CALLS" ] && P "an empty new value is refused before ykman is run" || F "empty value sent (rc=$rc2): $(cat "$CALLS")"
out2="$(yk_piv_change 36345471 change-pin $'123456\n999999' 24681357 2>&1)"; rc2=$?
[ "$rc2" != 0 ] && [ ! -s "$CALLS" ] && ! grep -q 999999 <<< "$out2" && P "a value holding a line break is refused before ykman is run, and not printed" || F "line break sent (rc=$rc2): $(cat "$CALLS")"
out2="$(yk_piv_change 36345471 change-management-key 1 2 2>&1)"; rc2=$?
[ "$rc2" != 0 ] && [ ! -s "$CALLS" ] && P "only change-pin and change-puk are accepted" || F "another verb was run (rc=$rc2)"

# No serial, no change: an unidentified token is refused before anything is written.
: > "$CALLS"
out="$(NO_SERIAL=1 step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin" "$CALLS" && grep -q "cannot read this YubiKey's serial" <<< "$out" && P "no serial: refused before any change" || F "no-serial token (rc=$rc)"

# The token swapped after identification: the bound command fails instead of changing another card.
: > "$CALLS"
out="$( ykman(){ if [ "$*" = info ]; then echo "Serial number: 36345471"; else YK_SERIAL=99999999 command ykman "$@"; fi; }; step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin STDIN" "$CALLS" && P "a token swapped after identification is not changed" || F "a swapped token was changed (rc=$rc)"

# Three YubiKeys, three credential sets: a second factory token in the same run gets SET B (its own
# PIN and PUK), never set A's; the same token run again keeps its set; a fourth token is refused.
# shellcheck disable=SC2034  # read by the sourced step_yubikey_ops
yubikey_b_piv_pin=13572468 yubikey_b_piv_puk=86427531
: > "$CALLS"
out="$( YK_SET_OF[36345471]=a; YK_SERIAL=36344616 step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" = 0 ] && grep -q "change-pin STDIN 123456 13572468" "$CALLS" && grep -q "change-puk STDIN 12345678 86427531" "$CALLS" \
  && ! grep -q -- "24681357" "$CALLS" && P "a second token gets set B's own PIN and PUK" || F "second token (rc=$rc): $(tr '\n' ';' < "$CALLS")"
grep -q "serial 36344616) is YubiKey B" <<< "$out" && P "and is named YubiKey B" || F "set B not named"
: > "$CALLS"
out="$( YK_SET_OF[36345471]=a; YK_SET_OF[36344616]=b; YK_SERIAL=36345471 step_yubikey_ops 2>&1)"; rc=$?
grep -q "change-pin STDIN 123456 24681357" "$CALLS" && P "the same token run again keeps set A" || F "a re-run changed the set: $(tr '\n' ';' < "$CALLS")"
: > "$CALLS"
# shellcheck disable=SC2034  # YK_SET_OF is read by the sourced step_yubikey_ops
out="$( YK_SET_OF[1]=a; YK_SET_OF[2]=b; YK_SET_OF[3]=c; YK_SERIAL=35718625 step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin" "$CALLS" && grep -q "fourth token" <<< "$out" && P "a fourth token is refused before any change" || F "fourth token (rc=$rc)"

# Sets LOADED FROM A FILE (not generated this run): the operator names the set; no guessing.
# (state_pins_generated_this_run and YK_SET_OF below are read by the sourced step_yubikey_ops.)
# shellcheck disable=SC2034
: > "$CALLS"
out="$( state_pins_generated_this_run=0; step_yubikey_ops </dev/null 2>&1)"; rc=$?
[ "$rc" != 0 ] && ! grep -q "change-pin" "$CALLS" && grep -q "CEREMONY_YUBIKEY_SET" <<< "$out" && P "file-loaded sets, no set named: refused" || F "file-loaded sets guessed (rc=$rc): $(tail -2 <<< "$out")"
: > "$CALLS"
out="$( state_pins_generated_this_run=0; YK_SET_OF[11111111]=a; CEREMONY_YUBIKEY_SET=b step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" = 0 ] && grep -q "change-pin STDIN 123456 13572468" "$CALLS" && P "file-loaded sets: the named set B is used" || F "named set not used (rc=$rc)"
: > "$CALLS"
# shellcheck disable=SC2034
out="$( state_pins_generated_this_run=0; YK_SET_OF[11111111]=b; CEREMONY_YUBIKEY_SET=b step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "already on another token" <<< "$out" && ! grep -q "change-pin" "$CALLS" && P "a set already on another token is refused" || F "set reused (rc=$rc)"
# shellcheck disable=SC2034
out="$( state_pins_generated_this_run=0; CEREMONY_YUBIKEY_SET=z step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "not one of the sets" <<< "$out" && P "an unknown set is refused" || F "set z accepted"

: > "$CALLS"
out="$(PLUGIN_FAILS=1 step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && P "a failed generation is reported as a failure" || F "a failed generation returned success"
grep -q "no identity was created" <<< "$out" && P "the failure says no identity exists" || F "no failure message: $out"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
