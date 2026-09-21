#!/usr/bin/env bash
# test-dkek-kcv-control.sh — the DKEK key check value as an identity control (regalia#460).
#
# WHY THIS IS A TEST AND NOT A COMMENT. `sc-hsm-tool --import-dkek-share` exits 0 whenever the
# password rebuilt from the typed shares decrypts dkek.pbe to something with valid PKCS#7 padding
# — which a WRONG password does about 1 time in 256. Measured over 180 wrong-share imports on
# DENK0404144 (2026-09-21): 180 refusals, 0 acceptances, excluding a systematic fallback but not
# chance. So a break-glass restore can succeed, report success, and hold a DIFFERENT DKEK.
#
# The key check value is what distinguishes them: two cards hold the same DKEK iff their KCVs
# match. This pins the parse (one definition, shared), the all-zero rejection (a Pico prints zeros
# and two unrelated cards would compare EQUAL), and the fact that the drill actually compares.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

. "$SCRIPTS/ceremony-kcv.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

hdr "the parse"
printf 'DKEK shares          : 1\nDKEK key check value : BC6DE92B2EABAC3E\n' > "$T/opensc.txt"
[ "$(kcv_of "$T/opensc.txt")" = bc6de92b2eabac3e ] \
  && P "OpenSC's 'DKEK key check value : <hex>' is read, folded to lowercase" \
  || F "OpenSC form not parsed: $(kcv_of "$T/opensc.txt")"
printf 'KCV DA4BF33D408C5C57\n' > "$T/emu.txt"
[ "$(kcv_of "$T/emu.txt")" = da4bf33d408c5c57 ] \
  && P "the emulator's 'KCV <hex>' form is read too (case-folded, so the same key never reads as a mismatch)" \
  || F "emulator form not parsed: $(kcv_of "$T/emu.txt")"

hdr "an all-zero value is the ABSENCE of a key check value, not a value"
printf 'DKEK key check value : 0000000000000000\n' > "$T/zero.txt"
if kcv_of "$T/zero.txt" >/dev/null 2>&1; then
  F "all-zero was returned as a KCV — two unrelated cards would compare EQUAL and print 'same domain confirmed'"
else
  P "all-zero is rejected (a Pico HSM 6.6 prints it for a populated domain; returning it is a false assurance)"
fi
: > "$T/empty.txt"
kcv_of "$T/empty.txt" >/dev/null 2>&1 && F "an empty capture yielded a KCV" || P "an empty capture yields nothing, not a match"
kcv_of "$T/does-not-exist" >/dev/null 2>&1 && F "a missing file yielded a KCV" || P "a missing capture yields nothing, not a match"

hdr "one definition, so the two callers cannot drift"
defs="$(grep -rlE '^kcv_of\(\) \{' "$SCRIPTS" | wc -l)"
[ "$defs" -eq 1 ] && P "kcv_of is defined exactly once (in ceremony-kcv.sh)" \
  || F "kcv_of is defined in $defs files — a drifted copy makes the same key read as a mismatch"
grep -q 'ceremony-kcv.sh' "$SCRIPTS/ceremony.sh" && P "ceremony.sh sources it" || F "ceremony.sh does not source it"
grep -q 'ceremony-kcv.sh' "$SCRIPTS/hsm-recovery-drill.sh" && P "hsm-recovery-drill.sh sources it" \
  || F "hsm-recovery-drill.sh does not source it"

hdr "the drill records the value at build time and compares it after the restore"
D="$SCRIPTS/hsm-recovery-drill.sh"
grep -q 'BREAKGLASS_KCV="\$(dkek_kcv_now' "$D" \
  && P "the KCV of the domain as BUILT is recorded" || F "the drill never records the build-time KCV"
grep -q 'installed a DIFFERENT DKEK (kcv' "$D" \
  && P "a restore that exits 0 with a different KCV is a FAILURE, not a pass" \
  || F "the positive arm still trusts exit status alone — a 1-in-256 wrong password reads as a successful restore"
grep -q 'U "restored DKEK identity not confirmed by key check value' "$D" \
  && P "a card that reports no KCV yields UNVERIFIED, never a PASS" \
  || F "an unreadable KCV does not produce UNVERIFIED — absence of evidence would read as agreement"
grep -q 'the wrong share was accepted card-side' "$D" \
  && P "when the negative control fires, the drill says WHICH side accepted the wrong material" \
  || F "the negative control still leaves the #397 question open"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
