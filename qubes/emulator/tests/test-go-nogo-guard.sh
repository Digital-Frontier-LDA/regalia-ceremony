#!/usr/bin/env bash
# test-go-nogo-guard.sh — the go/no-go gate must NEVER produce a false GO because of a
# mistyped --need token. An unrecognised device name must be a hard error BEFORE any probe,
# so an operator can't accidentally skip (e.g.) the SLE-4442 reader check and still get GO.
# Runs natively, no daemons needed (it asserts the arg-validation path, which exits early).
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
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

hdr "a bare --need is rejected, and cannot clear an earlier --need (review of #78)"
for args in "--need" "--need=" "--need hsm --need" "--need hsm --need --env-only"; do
  # shellcheck disable=SC2086
  out="$("$GN" $args 2>&1)"; rc=$?
  [ "$rc" = 2 ] && grep -qi "needs a device list" <<< "$out" && P "'$args' refused (exit 2)" || F "'$args' not refused (exit $rc)"
done

hdr "a test-only switch fails a real (non-simulated) preflight (d9 on #120)"
# the suite runner exports some of these switches itself: clear them all, then set one
CLEAN=(-u CEREMONY_SIMULATE -u CEREMONY_ALLOW_NONTMPFS -u CEREMONY_ALLOW_SWAP -u CEREMONY_ALLOW_CLASSICAL_BREAKGLASS)
for v in CEREMONY_ALLOW_CLASSICAL_BREAKGLASS CEREMONY_ALLOW_SWAP CEREMONY_ALLOW_NONTMPFS; do
  out="$(env "${CLEAN[@]}" "$v=1" "$GN" --env-only 2>&1)"; rc=$?
  [ "$rc" -ne 0 ] && grep -q "test-only switches set: $v — unset them" <<< "$out" && P "$v=1 without CEREMONY_SIMULATE fails" \
    || F "$v=1 without CEREMONY_SIMULATE did not fail (exit $rc)"
done
out="$(env "${CLEAN[@]}" CEREMONY_SIMULATE=1 CEREMONY_ALLOW_CLASSICAL_BREAKGLASS=1 "$GN" --env-only 2>&1)"
grep -q "test-only switches set: CEREMONY_ALLOW_CLASSICAL_BREAKGLASS — real ceremonies fail" <<< "$out" && P "under CEREMONY_SIMULATE it is a warning" \
  || F "under CEREMONY_SIMULATE the switch was not reported as a warning"

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
