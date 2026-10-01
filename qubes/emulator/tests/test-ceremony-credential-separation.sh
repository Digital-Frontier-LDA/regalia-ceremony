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

# HSM user PINs are 10-15 digits (a 10-try counter, ADR-0002 D15); three HSMs (D17).
GOOD_A_USER=4172935068 GOOD_A_SO=9F3C2A7710B4E6D5 GOOD_B_USER=8605314927 GOOD_B_SO=2B7E151628AED2A6
GOOD_C_USER=3094718265 GOOD_C_SO=6D1F83A0C4E29B57
# YubiKey A is the one the cases below vary; B and C are fixed, distinct sets (three YubiKeys).
GOOD_PIN=73920514 GOOD_PUK=58204718 GOOD_MGMT=5A0C9E3B71D24F86A1E0735C2B9D4F6081A7C3E5920B6D4F
# Their 48-hex management keys are built at runtime, so no key-shaped literal sits in the repo (gitleaks).
YK_B="yubikey_b_piv_pin=61839025\nyubikey_b_piv_puk=40718263\nyubikey_b_mgmt_key=$(printf 'B7%.0s' {1..24})"
YK_C="yubikey_c_piv_pin=29470186\nyubikey_c_piv_puk=85016734\nyubikey_c_mgmt_key=$(printf 'C8%.0s' {1..24})"
pins(){ # pins KEY=VALUE overrides...
  local a_user=$GOOD_A_USER a_so=$GOOD_A_SO b_user=$GOOD_B_USER b_so=$GOOD_B_SO c_user=$GOOD_C_USER c_so=$GOOD_C_SO
  local pin=$GOOD_PIN puk=$GOOD_PUK mgmt=$GOOD_MGMT kv
  for kv in "$@"; do eval "${kv%%=*}=\${kv#*=}"; done
  local emk; emk="$(printf 'E5%.0s' {1..16})"   # 32-hex escrow MAC key placeholder, built at runtime
  for kv in "$@"; do [ "${kv%%=*}" = emk ] && emk="${kv#*=}"; done
  printf 'hsm_a_user_pin=%s\nhsm_a_so_pin=%s\nhsm_b_user_pin=%s\nhsm_b_so_pin=%s\nhsm_c_user_pin=%s\nhsm_c_so_pin=%s\nyubikey_a_piv_pin=%s\nyubikey_a_piv_puk=%s\nyubikey_a_mgmt_key=%s\n%b\n%b\nescrow_mac_key=%s\n' \
    "$a_user" "$a_so" "$b_user" "$b_so" "$c_user" "$c_so" "$pin" "$puk" "$mgmt" "$YK_B" "$YK_C" "$emk" > "$WORK/pins.env"
}
run_step0(){ ( CEREMONY_MODE="$1" step_set_pins 2>&1 ); }
leaks(){ grep -qE "$GOOD_A_USER|$GOOD_A_SO|$GOOD_B_USER|$GOOD_B_SO|$GOOD_C_USER|$GOOD_C_SO|$GOOD_PIN|$GOOD_PUK|$GOOD_MGMT|111111" <<< "$1"; }

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
refuses "a YubiKey PIN equal to its PUK" "yubikey_a_piv_pin and yubikey_a_piv_puk hold the same value" puk=$GOOD_PIN
refuses "a YubiKey PIN reused as an HSM user PIN" "hsm_a_user_pin and yubikey_a_piv_pin hold the same value" pin=$GOOD_A_USER
refuses "an SO PIN that is not 16 hex digits" "hsm_b_so_pin: a SmartCard-HSM SO PIN is exactly 16 hex digits" b_so=2B7E1516
refuses "a user PIN longer than 15" "hsm_a_user_pin: a production HSM user PIN is 10-15 digits" a_user=4172934172934172
refuses "a 6-digit HSM user PIN (too short for a 10-try counter)" "hsm_a_user_pin: a production HSM user PIN is 10-15 digits" a_user=417293
refuses "card C's user PIN reused from card A" "hsm_a_user_pin and hsm_c_user_pin hold the same value" c_user=$GOOD_A_USER
refuses "card C's SO PIN reused from card B" "hsm_b_so_pin and hsm_c_so_pin hold the same value" c_so=$GOOD_B_SO
refuses "YubiKey A's PIN reused on YubiKey B" "yubikey_a_piv_pin and yubikey_b_piv_pin hold the same value" pin=61839025
refuses "a 5-character YubiKey PIN" "yubikey_a_piv_pin: a YubiKey PIV PIN or PUK is 6-8" pin=11111
refuses "a malformed management key" "yubikey_a_mgmt_key: a PIV management key" mgmt=0102

refuses "the YubiKey factory PIN" "PROD GUARD: yubikey_a_piv_pin is unset or holds a recognised dev default" pin=123456
refuses "the YubiKey factory PUK" "PROD GUARD: yubikey_a_piv_puk is unset or holds a recognised dev default" puk=12345678
refuses "a 6-character PIN of 12 bytes" "yubikey_a_piv_pin: a YubiKey PIV PIN or PUK is 6-8" pin=éééééé

# A field the file omits entirely: without this, a file of comments passed step 0.
pins; grep -v '^hsm_b_so_pin=' "$WORK/pins.env" > "$WORK/pins.tmp" && mv "$WORK/pins.tmp" "$WORK/pins.env"
out="$(run_step0 prod)"; rc=$?
[ "$rc" != 0 ] && grep -qF "hsm_b_so_pin: missing from the PIN file" <<< "$out" && P "PROD refuses a file that omits a field" || F "an omitted field passed (rc=$rc): $out"

pins b_user=$GOOD_A_USER; out="$(run_step0 dev)"; rc=$?
[ "$rc" = 0 ] && grep -q "would REFUSE this file in PROD" <<< "$out" && P "DEV warns and continues" || F "DEV did not warn-and-continue (rc=$rc)"
leaks "$out" && F "DEV printed a value" || P "no value is printed in DEV either"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
