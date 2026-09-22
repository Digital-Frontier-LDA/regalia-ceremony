#!/usr/bin/env bash
# test-reader-select-module-default.sh — the PKCS#11 module default must work on THIS platform,
# and a lookup with no module must refuse rather than answer emptily.
#
# WHAT WENT WRONG. HSM_P11_MODULE defaulted to /opt/homebrew/lib/opensc-pkcs11.so — a macOS
# Homebrew path — so on Linux it named a file that does not exist and every PKCS#11 lookup here
# returned NOTHING. Silently: pkcs11-tool's failure goes to /dev/null and the awk finds no match
# either way. Measured 2026-09-22 on the bench:
#
#     hsm_reader_for     ESP41D722E2 -> 3     (opensc-tool; needs no module, so it worked)
#     hsm_slot_index_for ESP41D722E2 -> ""    (pkcs11-tool; module missing, so it did not)
#
# The staging battery then fell back to slot 0 — a Virtual PCD — and reported
# "serial 'DENK0404144' != pinned 'ESP41D722E2'". It refused for the right reason about the wrong
# card, which is the most misleading way for a guard to be right.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RESOLVER="$REPO/tools/hsm-reader-select.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ -r "$RESOLVER" ] || { echo "no resolver at $RESOLVER" >&2; exit 1; }

hdr "with no HSM_PKCS11_MODULE set, the default finds a module that EXISTS"
mod="$(env -u HSM_PKCS11_MODULE bash -c '. "$1"; printf "%s" "$HSM_P11_MODULE"' _ "$RESOLVER")"
if [ -z "$mod" ]; then
  # Legitimate on a host with no OpenSC at all — but then it must be empty, not a path that lies.
  if command -v pkcs11-tool >/dev/null 2>&1 && ls /usr/lib/*/opensc-pkcs11.so >/dev/null 2>&1; then
    F "a module exists on this host but the default found none"
  else
    P "(no opensc-pkcs11.so on this host; the default is empty rather than a path that does not exist)"
  fi
else
  [ -f "$mod" ] && P "the default resolves to a real file: $mod" \
    || F "the default names a file that does not exist: $mod"
fi

hdr "an explicit HSM_PKCS11_MODULE still wins"
got="$(HSM_PKCS11_MODULE=/tmp/explicit.so bash -c '. "$1"; printf "%s" "$HSM_P11_MODULE"' _ "$RESOLVER")"
[ "$got" = /tmp/explicit.so ] && P "an explicit module is used verbatim" || F "explicit module ignored: $got"

hdr "NOTHING set and NOTHING found is a REFUSAL, not an empty answer"
# The case the guard is for. An explicit HSM_PKCS11_MODULE is the caller's business — harnesses
# stub pkcs11-tool on PATH and have no module on disk, and refusing those was wrong. What cannot
# be allowed is a lookup that CAN only answer emptily, because an empty answer is the one a caller
# reads as "that card is not attached", which is how a battery ends up targeting slot 0.
nomod='unset HSM_PKCS11_MODULE; . "$1"; HSM_P11_MODULE=""'
out="$(bash -c "$nomod"'; hsm_slot_index_for SOMESERIAL' _ "$RESOLVER" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "hsm_slot_index_for fails (exit $rc) when no module could be found" \
  || F "it returned success with no module — a caller cannot tell that from 'no such card'"
grep -q 'no PKCS#11 module found' <<<"$out" && P "…saying what is missing" || F "no explanation: $out"
grep -q 'would read as' <<<"$out" && P "…and why an empty answer would be worse" || F "the consequence is not stated"
out="$(bash -c "$nomod"'; hsm_slot_table' _ "$RESOLVER" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "hsm_slot_table refuses too" || F "hsm_slot_table returned success with no module"

hdr "an explicit module is NOT second-guessed"
# A harness that stubs pkcs11-tool has no module on disk and must still be able to look things up;
# refusing it broke test-hsm-staging-restore.sh's slot-table row for a reason unrelated to slots.
out="$(HSM_PKCS11_MODULE=/nonexistent.so bash -c '. "$1"; hsm_slot_index_for SOMESERIAL' _ "$RESOLVER" 2>&1)"
grep -q 'no PKCS#11 module found' <<<"$out" \
  && F "an explicitly named module was refused for not existing on disk" \
  || P "an explicit module is taken at face value, stub or not"

hdr "the serial-based lookups agree with each other on this bench"
# Only meaningful with cards attached; skipped honestly otherwise.
serials="$(bash -c '. "$1"; hsm_slot_table' _ "$RESOLVER" 2>/dev/null | awk '{print $2}' | grep -v '^$' || true)"
if [ -z "$serials" ]; then
  P "(no tokens attached, so there is nothing to cross-check)"
else
  bad=""
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    r="$(bash -c '. "$1"; hsm_reader_for "$2"' _ "$RESOLVER" "$s" 2>/dev/null || true)"
    ix="$(bash -c '. "$1"; hsm_slot_index_for "$2"' _ "$RESOLVER" "$s" 2>/dev/null || true)"
    [ -n "$r" ] && [ -n "$ix" ] || bad="$bad $s(reader='$r' slotix='$ix')"
  done <<< "$serials"
  [ -z "$bad" ] && P "every attached serial resolves to BOTH a reader index and a slot index" \
    || F "these serials resolve one way but not the other:$bad"
fi

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
