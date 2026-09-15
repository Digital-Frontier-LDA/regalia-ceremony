#!/usr/bin/env bash
# emu-entrypoint.sh — OPTIONAL Docker entrypoint. The supported test path is the native
# run-tests.sh (Docker is heavy on VRAM and the real target is a Debian box / CI runner).
# This just boots the shared emulator lib and dispatches a command.
set -uo pipefail
EMU_BIN="$(cd "$(dirname "$0")" && pwd)"
export CEREMONY_SCRIPTS="${CEREMONY_SCRIPTS:-/opt/vault-ceremony/scripts}"
# The ceremony preflight fails CLOSED on active swap (correct for a real vault qube). A
# container has swap, so turn it off for the test env — same prep run-tests.sh does.
swapoff -a 2>/dev/null || true
# shellcheck disable=SC1090
source "$EMU_BIN/emu-boot.sh"
boot_all
# shellcheck disable=SC1090
source "$EMU_RUN/env.sh"

T=/opt/vault-emu/tests
cmd="${1:-shell}"
case "$cmd" in
  shell)           exec bash -i ;;
  run-route-tests) exec "$T/route-coverage.sh" ;;
  dress-rehearsal) exec "$T/dress-rehearsal.sh" ;;
  go-nogo)         exec "$T/test-go-nogo.sh" ;;
  all-tests)
    rc=0
    python3 "$T/test_sle4442_model.py" || rc=1
    python3 "$T/test_schsm_crypto.py" || rc=1
    python3 "$T/test_derive_address.py" || rc=1
    python3 "$T/test_slip39_mint.py" || rc=1
    python3 "$T/test_metal_stamp.py" || rc=1
    python3 "$T/test_recovery_procedure.py" || rc=1
    "$T/test-secret-leak.sh" || rc=1
    "$T/test-ceremony-shamir-verify.sh" || rc=1
    "$T/route-coverage.sh" || rc=1
    "$T/test-go-nogo.sh"   || rc=1
    "$T/dress-rehearsal.sh" || rc=1
    echo; [ "$rc" = 0 ] && echo "===== ALL EMULATOR TEST SUITES PASSED =====" || echo "===== SOME SUITES FAILED ====="
    exit "$rc" ;;
  *)               exec "$@" ;;
esac
