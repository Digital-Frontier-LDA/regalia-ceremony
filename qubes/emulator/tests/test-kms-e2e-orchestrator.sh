#!/usr/bin/env bash
set -euo pipefail
# The orchestrator under test is regalia-kms's e2e/run.sh: it drives this repository's emulator
# and battery, and lives in the repository whose suites it runs first. Point REGALIA_KMS_DIR at a
# checkout to exercise it; without one this SKIPS loudly, because a cross-repository check that
# quietly passes is worth nothing.
KMS_DIR="${REGALIA_KMS_DIR:-}"
if [ -z "$KMS_DIR" ]; then
  _repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
  for candidate in "$(dirname "$_repo")/regalia-kms" "$HOME/regalia-kms"; do
    if [ -f "$candidate/e2e/run.sh" ]; then KMS_DIR="$candidate"; break; fi
  done
fi
if [ -z "$KMS_DIR" ] || [ ! -f "$KMS_DIR/e2e/run.sh" ]; then
  echo "  (skipping: no regalia-kms checkout — set REGALIA_KMS_DIR to one to check the e2e orchestrator)"
  exit 0
fi
E2E="$KMS_DIR/e2e/run.sh"
pass=0; fail=0
P(){ echo "  PASS $1"; pass=$((pass+1)); }
F(){ echo "  FAIL $1"; fail=$((fail+1)); }

default="$($E2E --plan 2>&1)"
grep -q 'ceremony-emu all-tests' <<<"$default" && P "default reuses the full Docker battery" || F "default misses full Docker battery"
grep -q -- '--tier nightly' <<<"$default" && F "default selected destructive Pico tier" || P "default is non-destructive"

gate="$($E2E --mode pico-gate --plan 2>&1)"
grep -q -- '--tier gate' <<<"$gate" && P "Pico mode reuses non-destructive gate" || F "Pico gate not selected"

set +e
nightly="$($E2E --mode pico-nightly --plan 2>&1)"; rc=$?
set -e
[ "$rc" = 2 ] && grep -q REFUSING <<<"$nightly" && P "destructive Pico tier requires interlock" || F "destructive interlock failed"

allowed="$(REGALIA_ALLOW_DESTRUCTIVE_PICO=YES HSM_CI_SERIAL=ESPTEST $E2E --mode pico-nightly --plan 2>&1)"
grep -q -- '--tier nightly' <<<"$allowed" && P "explicitly armed Pico tier reaches existing nightly battery" || F "armed nightly not selected"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
