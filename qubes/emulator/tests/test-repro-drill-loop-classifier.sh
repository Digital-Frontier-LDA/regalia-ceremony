#!/usr/bin/env bash
# test-repro-drill-loop-classifier.sh — run tools/repro-397-import-loop.sh's classifier self-test.
#
# WHY. The loop labels every failing iteration, and on 2026-09-14 it labelled both wrong-DKEK-share
# acceptances "enumeration-swap". It had matched "WRONG card" case-insensitively across the whole
# drill log, and every run, passing or failing, prints that phrase in an UNVERIFIED note (#460). The
# self-test holds that exact line as a regression case. It only runs when someone starts the loop on
# the bench, so without this suite a broken classifier would be found by a wasted hardware run.
#
# SELFTEST-ONLY MODE touches no bench: it exits after the self-test, before the bench lock is taken.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LOOP="${REPRO_LOOP:-$HERE/../../../../tools/repro-397-import-loop.sh}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
printf '\n\033[1m### the drill repro loop classifier self-test\033[0m\n'

[ -x "$LOOP" ] || { F "missing or not executable: $LOOP"; printf '\n  %s passed, %s failed\n' "$pass" "$fail"; exit 1; }
out="$(REPRO397_SELFTEST_ONLY=1 "$LOOP" 2>&1)"; rc=$?
if [ "$rc" = 0 ] && grep -q 'classifier self-test passed (selftest-only mode; no bench touched)' <<< "$out"; then
  P "the classifier self-test passes, without touching the bench"
else
  F "the classifier self-test did not pass (rc=$rc):"; printf '    | %s\n' "$out"
fi
if grep -q 'restoring bench posture' <<< "$out"; then
  F "selftest-only mode reached the posture restore; it must stop before anything destructive"
else
  P "selftest-only mode did not reach the posture restore"
fi

printf '\n  %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
