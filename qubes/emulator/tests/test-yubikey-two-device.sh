#!/usr/bin/env bash
# The emulator must model two independent YubiKeys, not one identity renamed twice.
# A two-site ceremony relies on both recipients remaining usable after the second
# token is commissioned; overwriting the first identity would make that rehearsal
# falsely green until recovery day.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../bin/age-plugin-yubikey"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

pass=0; fail=0
P(){ printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

out_a="$(EMU_AGE_IDENTITY_DIR="$ROOT" EMU_YUBIKEY_SERIAL=25923902 "$BIN" --generate 2>&1)"; rc_a=$?
out_b="$(EMU_AGE_IDENTITY_DIR="$ROOT" EMU_YUBIKEY_SERIAL=25923905 "$BIN" --generate 2>&1)"; rc_b=$?

[ "$rc_a" = 0 ] && P "primary token generation succeeds" || F "primary generation failed (rc=$rc_a)"
[ "$rc_b" = 0 ] && P "standby token generation succeeds" || F "standby generation failed (rc=$rc_b)"

rec_a="$(printf '%s\n' "$out_a" | grep '^age1' | tail -1)"
rec_b="$(printf '%s\n' "$out_b" | grep '^age1' | tail -1)"
[ -n "$rec_a" ] && P "primary recipient emitted" || F "primary recipient missing"
[ -n "$rec_b" ] && P "standby recipient emitted" || F "standby recipient missing"
[ -n "$rec_a" ] && [ "$rec_a" != "$rec_b" ] \
  && P "two devices have distinct recipients" \
  || F "standby generation reused the primary recipient"

[ -s "$ROOT/ops-identity-25923902.txt" ] && P "primary identity remains stored" \
  || F "primary identity was overwritten or not stored"
[ -s "$ROOT/ops-identity-25923905.txt" ] && P "standby identity is stored separately" \
  || F "standby identity was not stored separately"

read_a="$(EMU_AGE_IDENTITY_DIR="$ROOT" EMU_YUBIKEY_SERIAL=25923902 "$BIN" --identity 2>&1)"; rc_ra=$?
read_b="$(EMU_AGE_IDENTITY_DIR="$ROOT" EMU_YUBIKEY_SERIAL=25923905 "$BIN" --identity 2>&1)"; rc_rb=$?
[ "$rc_ra" = 0 ] && [ "$read_a" = "$(cat "$ROOT/ops-identity-25923902.txt")" ] \
  && P "primary identity remains readable after standby generation" \
  || F "primary identity lookup changed after standby generation"
[ "$rc_rb" = 0 ] && [ "$read_b" = "$(cat "$ROOT/ops-identity-25923905.txt")" ] \
  && P "standby identity remains readable" \
  || F "standby identity lookup failed"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
