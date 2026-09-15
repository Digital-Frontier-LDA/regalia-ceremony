#!/usr/bin/env bash
# test-go-nogo-guard.sh — the go/no-go gate must NEVER produce a false GO because of a
# mistyped --need token. An unrecognised device name must be a hard error BEFORE any probe,
# so an operator can't accidentally skip (e.g.) the SLE-4442 reader check and still get GO.
# Runs natively, no daemons needed (it asserts the arg-validation path, which exits early).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GN="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/go-nogo.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

hdr "a typo'd --need device is rejected (no false GO via a skipped check)"
out="$("$GN" --need yubikey,sle442 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && grep -qi "unrecognised device 'sle442'" <<< "$out"; then
  P "typo 'sle442' rejected with a hard error (exit $rc)"
else
  F "typo in --need was NOT rejected (exit $rc) — would skip the SLE-4442 check and still GO"
fi

hdr "an entirely unknown device is rejected"
out="$("$GN" --need wifi 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && grep -qi "unrecognised device 'wifi'" <<< "$out" && P "unknown 'wifi' rejected" || F "unknown device not rejected"

hdr "all valid device names are accepted (validation does not over-reject)"
# this will proceed past validation into preflight; we only assert it does NOT fail on the
# token validation (grep for the specific validation error, which must be absent).
out="$("$GN" --need yubikey,hsm,sle4442,printer,drives 2>&1 || true)"
if grep -qi "unrecognised device" <<< "$out"; then
  F "a valid device list was wrongly rejected by the validator"
else
  P "valid device list passes token validation"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
