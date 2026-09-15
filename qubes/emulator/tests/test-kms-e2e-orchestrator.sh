#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
E2E="$ROOT/kms/e2e/run.sh"
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
