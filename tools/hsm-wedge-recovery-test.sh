#!/usr/bin/env bash
# hsm-wedge-recovery-test.sh — prove the bench can detect and clear a wedge WITHOUT hands.
#
#   tools/hsm-wedge-recovery-test.sh --serial ESP2202E14A --probe-map "PROBE:BOARD ..."
#
# WHY THIS EXISTS. The battery gained an automatic recovery path (hsm-staging-ci.sh's ensure_card),
# and a recovery path that has never run is not a capability — it is untested code sitting on the
# error branch, which is the branch least likely to work. The whole claim of this bench is that a
# wedge costs seconds instead of a human, and that claim needs a test that actually wedges a card.
#
# HOW IT INDUCES THE WEDGE. Attaching OpenOCD to a RUNNING Pico HSM is enough on its own to stop
# it answering: measured 2026-09-02, a read-only `init; mdw` session left a healthy provisioned
# card enumerated on USB but mute at the applet, needing `halt; reset run` to come back. That is
# the same "alive but not answering" state the soak data shows at ~6.6% of reboots, so it is a
# faithful stand-in and it is repeatable on demand.
#
# WHAT IT PROVES, IN ORDER: the card answers; it can be made to stop; the wedge is DETECTED; the
# platform is identified as RP-series so SWD is even applicable; the right probe is chosen for
# that board; the ladder clears it; the card answers again. A run that skips the "made to stop"
# step proves nothing, so that step is itself asserted.
set -uo pipefail

SERIAL=""; PROBE_MAP=""; BOARD_MAP=""
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
RECOVER="${HSM_CI_RECOVER_CMD:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hsm-swd-powman-recover.sh}"
while [ $# -gt 0 ]; do case "$1" in
  --serial) SERIAL="$2"; shift 2;;
  --probe-map) PROBE_MAP="$2"; shift 2;;
  --board-map) BOARD_MAP="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done
[ -n "$SERIAL" ] || { sed -n '2,6p' "$0"; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/hsm-reader-select.sh"

# The resolver requires a token->full-board-id map and refuses to infer one from the token serial,
# which carries only the board id's last four bytes. --board-map is how a STANDALONE run supplies
# it; under the CI battery it arrives in the environment already.
[ -n "$BOARD_MAP" ] && export HSM_BOARD_MAP="$BOARD_MAP"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

answers(){ # by OUTPUT, never exit status — sc-hsm-tool exits 0 while printing "Card not present"
  local r out
  r="$(hsm_reader_for "$SERIAL" 2>/dev/null)" || return 1
  out="$(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool -r "$r" 2>&1)"
  grep -qi '^Version' <<< "$out"
}

hdr "0 — the card answers to begin with (otherwise nothing below means anything)"
if answers; then P "$SERIAL is answering"; else
  F "$SERIAL is not answering before the test even starts — fix that first"; exit 1; fi

hdr "1 — platform: is SWD recovery applicable to this token at all?"
BOARD="$(hsm_board_for_token "$SERIAL" 2>/dev/null)" || BOARD=""
if [ -n "$BOARD" ]; then
  P "$SERIAL is an RP-series board ($BOARD) — SWD recovery is applicable"
else
  if [ -z "${HSM_BOARD_MAP:-}" ]; then
    F "no board map for $SERIAL — pass --board-map 'TOKEN:FULLBOARDID ...' (or set HSM_BOARD_MAP). The token serial carries only the last four bytes of the board id, so the resolver refuses to guess which board to halt and reset."
  else
    F "$SERIAL is mapped, but that board is not on the USB bus — or it is not an RP2350 Pico at all (a Nitrokey HSM 2 has no debug port)"
  fi
  exit 1
fi

PROBE=""
for pair in $PROBE_MAP; do case "$pair" in *":$BOARD") PROBE="${pair%%:*}"; break;; esac; done
if [ -n "$PROBE" ]; then P "probe $PROBE is mapped to board $BOARD"; else
  F "no probe mapped to board $BOARD — pass --probe-map 'PROBE:BOARD ...'"; exit 1; fi

hdr "2 — induce the wedge (halt the cores over SWD)"
# WHAT THIS REPRODUCES, AND WHAT IT DOES NOT CLAIM.
#
# Halting both cores leaves the device ENUMERATED on USB while nothing services the CCID applet —
# the same OBSERVABLE state as the spontaneous wedge (alive on the bus, mute to every APDU), which
# is the state the recovery ladder has to clear. It is NOT a claim that a halt shares the
# spontaneous wedge's internal cause; that cause is still open (polhenarejos/pico-keys-sdk#25).
# What is being tested here is the RESPONSE: detect, pick the right probe, clear it, unattended.
#
# A first version induced the wedge by merely attaching OpenOCD, because that had muted a healthy
# card twice on 2026-09-02. Measured here: it does NOT do so reliably — the card kept answering
# and the test correctly refused to go on rather than "prove" a recovery it had not exercised.
"$OCD_BIN" -f interface/cmsis-dap.cfg -c "adapter serial $PROBE" -c "adapter speed 5000" \
  -f target/rp2350.cfg -c "gdb port disabled" -c "tcl port disabled" -c "telnet port disabled" \
  -c "init" -c "halt" -c "exit" >/dev/null 2>&1
sleep 6
if answers; then
  F "the card still answers — the wedge was NOT induced, so this run cannot prove recovery"
  exit 1
else
  P "card is now MUTE — a real wedge, not a simulated one"
fi

hdr "3 — the wedge is DETECTED (not mistaken for a healthy card)"
if answers; then F "detection says healthy while the card is mute"; else
  P "detection reports the card as not answering"; fi

hdr "4 — recover it over SWD, unattended"
t0=$(date +%s)
HSM_RECOVER_PROBE="$PROBE" HSM_RECOVER_BOARD="$BOARD" HSM_RECOVER_SERIAL="$SERIAL" \
  OCD_PORT="${OCD_PORT:-4488}" \
  perl -e 'alarm 300; exec @ARGV' -- "$RECOVER" >/tmp/wedge-recover.log 2>&1
pkill -f "$(basename "$OCD_BIN")" 2>/dev/null; sleep 6
t1=$(date +%s)

hdr "5 — the card is back"
back=0
for _ in $(seq 1 10); do if answers; then back=1; break; fi; sleep 5; done
if [ "$back" = 1 ]; then
  P "$SERIAL answers again after $((t1-t0))s — recovered with no human intervention"
else
  F "$SERIAL did not come back (see /tmp/wedge-recover.log)"
fi

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
