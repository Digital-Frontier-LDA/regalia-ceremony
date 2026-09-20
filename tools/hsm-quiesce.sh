#!/usr/bin/env bash
# hsm-quiesce.sh — take one Pico HSM off the USB bus (and put it back) over SWD.
#
#   ./hsm-quiesce.sh --probe <serial> --expect-board <otp-id> hold
#   ./hsm-quiesce.sh --probe <serial> --expect-board <otp-id> release
#
# WHY THIS EXISTS. The Smart Card Shell selects a reader by NAME and matches by prefix. With two
# Pico HSMs attached, PC/SC names them "…Pico Key CCID Interface" and "…Pico Key CCID Interface 01"
# — the first is a strict PREFIX of the second, so no string can select it. Measured 2026-09-03:
# passing the exact full name of the intended card still returned the OTHER card's certificate.
#
# Every scsh-driven step here is destructive (INITIALIZE DEVICE erases the card), so "probably the
# right card" is not good enough. Rather than hand-roll the initializer's APDU, hold the other
# board in reset for the duration: with one card on the bus there is nothing to disambiguate.
#
# The OTP interlock is mandatory — halting the wrong board is how you lose the card you meant to keep.
set -uo pipefail

PROBE=""; EXPECT_BOARD=""; ACTION=""
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
while [ $# -gt 0 ]; do case "$1" in
  --probe) PROBE="$2"; shift 2;;
  --expect-board) EXPECT_BOARD="$2"; shift 2;;
  hold|release) ACTION="$1"; shift;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done
# --expect-board IS REQUIRED, because the comment above says the interlock is mandatory and a
# comment is not an interlock. It was optional, and the guard below is written `if [ -n ... ]`, so
# omitting it silently skipped the ONE check that stops this from halting the wrong board — the
# card you meant to keep. Observed on 2026-09-03: a caller that passed only --probe printed
# "held board  in reset" with an empty id, having verified nothing.
[ -n "$PROBE" ] && [ -n "$ACTION" ] && [ -n "$EXPECT_BOARD" ] || {
  [ -n "$PROBE" ] && [ -n "$ACTION" ] && [ -z "$EXPECT_BOARD" ] \
    && echo "REFUSING: --expect-board is required; halting a board without proving which one it is defeats the interlock" >&2
  sed -n '2,12p' "$0"; exit 2; }

ocd(){ "$OCD_BIN" -f interface/cmsis-dap.cfg -c "adapter serial $PROBE" -c "adapter speed 5000" \
        -f target/rp2350.cfg -c "gdb port disabled" -c "tcl port disabled" \
        -c "telnet port disabled" -c "init" "$@" -c "exit" 2>&1; }

if [ -n "$EXPECT_BOARD" ]; then
    otp="$(ocd -c "mdw 0x40130000 2")"
    lo="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$otp" | awk '{print $2}')"
    hi="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$otp" | awk '{print $3}')"
    [ -n "$lo" ] && [ -n "$hi" ] || { echo "FAIL: could not read OTP id via $PROBE" >&2; exit 1; }
    got="$(printf '%s%s' "$hi" "$lo" | tr 'a-f' 'A-F')"
    [ "$got" = "$(tr 'a-f' 'A-F' <<< "$EXPECT_BOARD")" ] \
      || { echo "REFUSING: probe $PROBE is on board $got, expected $EXPECT_BOARD" >&2; exit 1; }
fi

# REPORT WHAT HAPPENED, NOT WHAT WAS ATTEMPTED. `ocd ...; echo "held ..."` printed success
# unconditionally — OpenOCD could fail to reach the probe and the caller would still be told the
# board was held. This script exists to make a destructive operation unambiguous, so a false
# success here is the worst thing it can do.
#
# The old wording was wrong in a second way: it said "off the bus". A held RP2350 stays ENUMERATED
# (measured 2026-09-03 — two PC/SC readers remained throughout a 20 s hold), so the caller must
# still verify the bus rather than trust this line. hsm-fleet-drill.sh does exactly that.
case "$ACTION" in
  hold)
    if ocd -c "reset halt" >/dev/null 2>&1; then
      echo "held board $EXPECT_BOARD in reset — NOTE: a held board can stay enumerated; verify the bus"
    else
      echo "FAILED to hold board $EXPECT_BOARD: OpenOCD did not complete over probe $PROBE" >&2
      exit 1
    fi ;;
  release)
    if ocd -c "reset run" >/dev/null 2>&1; then
      echo "released board $EXPECT_BOARD"
    else
      echo "FAILED to release board $EXPECT_BOARD: OpenOCD did not complete over probe $PROBE — the board may still be held" >&2
      exit 1
    fi ;;
esac
