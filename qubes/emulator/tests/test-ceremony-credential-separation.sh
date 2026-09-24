#!/usr/bin/env bash
# Step 0's credential separation (regalia#28 criterion 1, doc/CREDENTIAL-SEPARATION.md): every PIN,
# SO PIN, PUK and management key the ceremony escrows must be its OWN value and have the shape its
# device accepts. PROD refuses a file that breaks either rule; DEV warns and continues. No value is
# ever printed, in either mode.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"

pass=0; fail=0
P(){ printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

# shellcheck disable=SC1090
source "$HERE/../../scripts/ceremony.sh"
pause(){ :; }
ask(){ return 1; }   # never open an editor
init_work

GOOD_A_USER=417293 GOOD_A_SO=9F3C2A7710B4E6D5 GOOD_B_USER=860531 GOOD_B_SO=2B7E151628AED2A6
GOOD_PIN=73920514 GOOD_PUK=58204718 GOOD_MGMT=5A0C9E3B71D24F86A1E0735C2B9D4F6081A7C3E5920B6D4F
pins(){ # pins KEY=VALUE overrides...
  local a_user=$GOOD_A_USER a_so=$GOOD_A_SO b_user=$GOOD_B_USER b_so=$GOOD_B_SO pin=$GOOD_PIN puk=$GOOD_PUK mgmt=$GOOD_MGMT kv
  for kv in "$@"; do eval "${kv%%=*}=\${kv#*=}"; done
  printf 'hsm_a_user_pin=%s\nhsm_a_so_pin=%s\nhsm_b_user_pin=%s\nhsm_b_so_pin=%s\nyubikey_piv_pin=%s\nyubikey_piv_puk=%s\nyubikey_mgmt_key=%s\n' \
    "$a_user" "$a_so" "$b_user" "$b_so" "$pin" "$puk" "$mgmt" > "$WORK/pins.env"
}
run_step0(){ ( CEREMONY_MODE="$1" step_set_pins 2>&1 ); }
leaks(){ grep -qE "$GOOD_A_USER|$GOOD_A_SO|$GOOD_B_USER|$GOOD_B_SO|$GOOD_PIN|$GOOD_PUK|$GOOD_MGMT|111111" <<< "$1"; }

pins; out="$(run_step0 prod)"; rc=$?
[ "$rc" = 0 ] && grep -q "every loaded credential is distinct" <<< "$out" && P "a distinct, well-formed file is accepted" || F "good file refused: $out"

refuses(){ # refuses "why" "expected message" overrides...
  local why="$1" msg="$2"; shift 2
  pins "$@"; out="$(run_step0 prod)"; rc=$?
  if [ "$rc" != 0 ] && grep -qF "$msg" <<< "$out"; then P "PROD refuses $why"; else F "PROD accepted $why (rc=$rc): $out"; fi
  leaks "$out" && F "a value was printed while refusing $why" || true
}
refuses "card A's user PIN reused on card B" "hsm_a_user_pin and hsm_b_user_pin hold the same value" b_user=$GOOD_A_USER
refuses "a user PIN equal to its own SO PIN" "hsm_a_so_pin and hsm_a_user_pin hold the same value" a_user=1234567890ABCDEF a_so=1234567890ABCDEF
refuses "the same SO PIN on both cards, in another case" "hsm_a_so_pin and hsm_b_so_pin hold the same value" b_so="${GOOD_A_SO,,}"
refuses "a YubiKey PIN equal to its PUK" "yubikey_piv_pin and yubikey_piv_puk hold the same value" puk=$GOOD_PIN
refuses "a YubiKey PIN reused as an HSM user PIN" "hsm_a_user_pin and yubikey_piv_pin hold the same value" pin=$GOOD_A_USER
refuses "an SO PIN that is not 16 hex digits" "hsm_b_so_pin: a SmartCard-HSM SO PIN is exactly 16 hex digits" b_so=2B7E1516
refuses "a user PIN longer than 15" "hsm_a_user_pin: a SmartCard-HSM user PIN is 6-15" a_user=4172934172934172
refuses "a 5-character YubiKey PIN" "yubikey_piv_pin: a YubiKey PIV PIN or PUK is 6-8" pin=11111
refuses "a malformed management key" "yubikey_mgmt_key: a PIV management key" mgmt=0102

pins b_user=$GOOD_A_USER; out="$(run_step0 dev)"; rc=$?
[ "$rc" = 0 ] && grep -q "would REFUSE this file in PROD" <<< "$out" && P "DEV warns and continues" || F "DEV did not warn-and-continue (rc=$rc)"
leaks "$out" && F "DEV printed a value" || P "no value is printed in DEV either"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
