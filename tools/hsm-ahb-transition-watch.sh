#!/usr/bin/env bash
# hsm-ahb-transition-watch.sh — sample the AHB continuously across a reboot and record the MOMENT it
# stops answering.
#
#   ./tools/hsm-ahb-transition-watch.sh [seconds] [outfile]
#
# WHY THIS EXISTS.
#
# Every stalled-bus capture so far photographs the SETTLED state: the AHB is already blocked, both
# MEM-APs already fail, and the record says where the failure is but nothing about how it got there.
# The two routes that could have said more are both closed:
#
#   * RISC-V Debug Module SBA reaches memory without a MEM-AP — but returns sberror=2 on every
#     region while the chip is in Arm mode. Tested, does not work here.
#   * A logic analyzer on the QSPI lines would show the flash mid-transaction — but RP2350 routes
#     QSPI to dedicated pins that reach only the flash die, the package on this board is LEADLESS,
#     and the only probing point is pads under the chip. Not worth doing to the one working card.
#
# What is left is timing. If the bus is sampled continuously across the reboot, the last successful
# read timestamps the block. That constrains the cause in a way the settled state cannot:
#
#   blocks DURING the XIP/flash scan       -> consistent with the QSPI interface holding the bus
#   blocks BEFORE any flash access         -> not flash; look at DMA or the other core
#   blocks AT the same offset every time   -> deterministic, a specific instruction or transaction
#   blocks at scattered offsets            -> a race, not a fixed code path
#
# Those four are distinguishable by timing alone, and none of them need a probe on the flash.
#
# RESOLUTION. Each sample is an OpenOCD telnet round trip, ~10-40 ms, so a 5 s boot yields roughly
# 150-500 samples. That is coarse against a bus transaction but fine against the boot phases, which
# is the distinction being drawn. The sample interval is recorded per line so the resolution is
# never guessed at later.
set -uo pipefail

SECS="${1:-30}"
OUT="${2:-/tmp/ahb-transition-$(date +%H%M%S).jsonl}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
AHB_AP="${HSM_AHB_AP:-0x2000}"
ARTIFACT="0x4c013477"     # this bench's "the read did not work" word

if [ -z "${HSM_SNAPSHOT_FORCE:-}" ] && pgrep -f 'hsm-reboot-soak|soak-frozen' >/dev/null 2>&1; then
    echo "REFUSING TO RUN: a soak owns the probe. Two OpenOCDs on one SWD link produce" >&2
    echo "  plausible-looking garbage rather than errors." >&2
    exit 2
fi

pkill -f "$(basename "$OCD_BIN")" 2>/dev/null; sleep 2
"$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
    -c "rp2350.cm0 configure -defer-examine; rp2350.cm1 configure -defer-examine" \
    -c "adapter speed 5000" > /tmp/ahb-watch-ocd.log 2>&1 &
OCD_PID=$!
sleep 8

# POWER UP THE DEBUG DOMAIN BY HAND.
#
# -defer-examine is used so the sampler never issues the abort that clears sticky bits — but examine
# is also what normally raises CDBGPWRUPREQ/CSYSPWRUPREQ. Without it every apreg read comes back
# empty, which the first run showed as 0 of 201 samples succeeding on a perfectly healthy card.
printf 'rp2350.dap dpreg 0x4 0x50000000\nexit\n' \
    | perl -e 'alarm 10; exec @ARGV' -- nc localhost 4444 >/dev/null 2>&1
sleep 1

: > "$OUT"
end=$(( $(date +%s) + SECS ))
n=0; last_ok=""; blocked_at=""

while [ "$(date +%s)" -lt "$end" ]; do
    t0=$(python3 -c 'import time;print(f"{time.time():.4f}")')
    v="$(printf 'rp2350.dap apreg %s 0xd04 0xe000edf0\nrp2350.dap apreg %s 0xd0c\nexit\n' \
            "$AHB_AP" "$AHB_AP" \
         | perl -e 'alarm 5; exec @ARGV' -- nc localhost 4444 2>/dev/null \
         | LC_ALL=C tr -d '\000' | LC_ALL=C grep -av 'apreg' \
         | LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' | sed -n 1p)"
    # INDEX AFTER FILTERING, NOT BEFORE. The snapshot takes the 2nd hex token from UNFILTERED output
    # — token 1 is the address echoed back in the command line, token 2 is the value. This sampler
    # strips the echo lines first, so the value is token 1. Copying the '2p' across returned nothing
    # every time: 0 of 159 samples on a healthy card, which the summary then had to be taught not to
    # call a clean run.
    t1=$(python3 -c 'import time;print(f"{time.time():.4f}")')

    # An unreadable value and the artifact word are the same answer: the read did not work.
    ok=1
    case "${v:-}" in ""|0x00000000|"$ARTIFACT") ok=0 ;; esac

    printf '{"t":%s,"dt":%s,"raw":"%s","ok":%s}\n' \
        "$t0" "$(python3 -c "print(f'{$t1-$t0:.4f}')")" "${v:-none}" "$ok" >> "$OUT"

    if [ "$ok" = "1" ]; then
        last_ok="$t0"
    elif [ -z "$blocked_at" ] && [ -n "$last_ok" ]; then
        blocked_at="$t0"
        printf 'AHB STOPPED ANSWERING at %s (last good %s, %s samples in)\n' \
            "$blocked_at" "$last_ok" "$n"
    fi
    n=$((n + 1))
done

kill "$OCD_PID" 2>/dev/null
printf 'samples %s -> %s\n' "$n" "$OUT"
if [ -n "$blocked_at" ]; then
    python3 - "$last_ok" "$blocked_at" <<'EOP'
import sys
last, blocked = float(sys.argv[1]), float(sys.argv[2])
print(f"  block window: {blocked-last:.4f}s wide (between the last good read and the first failure)")
print("  Narrow window => the block is abrupt. Wide => the sampler simply was not looking.")
EOP
elif [ -z "$last_ok" ]; then
    # NEVER ANSWERED IS NOT ANSWERED THROUGHOUT. The first version printed "the AHB answered for the
    # whole window" whenever no transition was seen — including the case where not one sample ever
    # succeeded, because blocked_at is only set after a good read. On a healthy card that produced
    # "answered for the whole window" alongside ok=0/201. Reporting a probe's total failure as a
    # clean result is the exact error this bench keeps making.
    echo "  THE AHB NEVER ANSWERED — 0 of $n samples succeeded."
    echo "  This is a BROKEN PROBE, not a healthy bus and not a wedge. Do not record it as either."
    exit 3
else
    echo "  the AHB answered for the whole window — no transition captured"
fi
