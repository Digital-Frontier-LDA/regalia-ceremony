#!/usr/bin/env bash
# hsm-wedge-hunt.sh — reboot the card until it WEDGES, then capture everything about that state.
#
#   tools/hsm-wedge-hunt.sh [max-reboots] [wait-seconds]
#
# WHY. The warm-boot wedge is the last known reliability defect: roughly 1 reboot in 20+ leaves the
# card off the USB bus. Every previous encounter with it was accidental, mid-soak, and got cleared
# as fast as possible so the run could continue — so nobody ever looked at it. This provokes it
# deliberately and then STOPS, holding the failed state still while it is photographed.
#
# WHAT IT CAPTURES, and why each matters:
#   * core states + PC        — is core0 running, halted, or unresponsive to halt? Which code is it
#                               in: firmware (0x10xxxxxx XIP / 0x20xxxxxx SRAM) or bootrom (<0x8000)?
#   * RTT buffer              — the firmware's OWN last words. The ring buffer lives in SRAM and a
#                               warm reset does not necessarily clear it, so this can show how far
#                               the boot got before it stopped.
#   * POWMAN_WDSEL / PSM      — whether the reset that just happened was warm or a switched-core
#                               power cycle, read from the hardware rather than assumed.
#   * WATCHDOG_CTRL / SCRATCH — whether the watchdog is armed, and what the firmware left behind.
#   * USB port state          — "power connect" without "enable" means the device is electrically
#                               present but never enumerated, which is a different fault from absent.
#
# Requires firmware built with -DPICO_STDIO_RTT=ON (build_rtt) for the RTT half to say anything.
set -u

OCD_PORT="${OCD_PORT:-4444}"
RTT_PORT="${RTT_PORT:-9091}"
N="${1:-40}"
WAIT="${2:-90}"
OUT="${HSM_WEDGE_OUT:-/tmp/hsm-wedge-$(date +%Y%m%d-%H%M%S)}"

# Host sleep suspends USB and reads as a wedge — see tools/hsm-reboot-soak.sh.
if [ -z "${HSM_CAFFEINATED:-}" ] && command -v caffeinate >/dev/null 2>&1; then
    export HSM_CAFFEINATED=1
    exec caffeinate -dimsu "$0" "$@"
fi

mkdir -p "$OUT"
say(){ printf '  %s\n' "$*"; }
# STRIP NULs: OpenOCD's telnet stream carries IAC negotiation bytes and a NUL after each response,
# and grep treats input containing a NUL as BINARY — so a pattern that is plainly present never
# matches. Measured 2026-08-08: a probe reading "0x40100030: 00000000" reported "cannot read the
# chip" on a healthy card every time. A check that fails constantly carries no information while
# reading exactly like a diagnosis.
ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 30; exec @ARGV' -- nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000'; }
alive(){ perl -e 'alarm 15; exec @ARGV' -- sc-hsm-tool 2>&1 | grep -qi '^Version'; }
reboot_card(){ perl -e 'alarm 45; exec @ARGV' -- opensc-tool \
    -s "00:A4:04:00:08:A0:58:3F:C1:9B:7E:4F:21" -s "80:1F:00:00" >/dev/null 2>&1; }

# CHECK THE INSTRUMENT BEFORE TRUSTING THE MEASUREMENT.
#
# Everything this script concludes is reached THROUGH the debug server, and every one of those
# paths fails SILENTLY and in the direction that makes the device look worse:
#
#   * `ocd "reset run"` with no server does nothing, so the "false alarm: the debugger was holding
#     the core" branch can never fire and every held core is counted as a genuine wedge;
#   * the RTT capture below writes an empty log, so a run can complete and report findings with no
#     firmware output behind them at all;
#   * the flash forensics read back nothing, and "no corruption found" is indistinguishable from
#     "nothing was read".
#
# A server that is merely LISTENING is not enough either — a long-lived OpenOCD keeps answering
# about a chip it can no longer see (measured on this bench four separate ways). So probe against
# ground truth: one register read that must come back with a word.
#
# This is the sibling of the defect found in hsm-reboot-soak.sh on 2026-08-08, where the cheap-rung
# probe was piped into a socket with nothing listening and MILD was unreachable by construction.
# A measurement tool that cannot verify its own instrument reports the harness, not the device.
if ! ocd "mdw 0x40100030" | LC_ALL=C grep -qaEi '40100030: *[0-9a-f]{8}'; then
    echo "REFUSING TO RUN: the debug server on port $OCD_PORT cannot read the chip." >&2
    echo "  Every conclusion here is reached through it, and it fails silently toward" >&2
    echo "  'wedged' — a held core would be counted as a real wedge and RTT would log nothing." >&2
    echo "  Start it:  \$OCD_BIN -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c 'adapter speed 5000'" >&2
    echo "  If it IS running, it has gone stale: kill it and start a fresh one." >&2
    exit 2
fi

# Start RTT once; the control block address moves per build, so search rather than hardcode.
ocd "rtt setup 0x20000000 0x80000 \"SEGGER RTT\"
rtt start" >/dev/null 2>&1
ocd "rtt server start $RTT_PORT 0" >/dev/null 2>&1
( perl -e 'alarm 100000; exec @ARGV' -- nc localhost "$RTT_PORT" 2>/dev/null | tr -d '\r' > "$OUT/rtt.log" & ) 2>/dev/null

# SAY SO WHEN THE FIRMWARE LOG IS NOT ACTUALLY BEING CAPTURED.
# MEASURED: the 40-reboot run of 2026-08-07 and the 60-reboot run of 2026-08-08 both finished with
# a rtt.log of ZERO BYTES, and neither said a word. RTT is the only channel that keeps working
# while the card is wedged, so a hunt without it collects the state of a wedge and none of the
# firmware's account of how it got there — and, because build_pz has no RTT while build_rtt does,
# a live capture is also the one piece of evidence that identifies WHICH BUILD is running. Losing
# it silently cost exactly that: those two runs can no longer be tied to a binary.
#
# Not fatal — the wedge state itself is still worth capturing — but it must be visible up front
# rather than discovered as an empty file afterwards.
if ocd "rtt channels" 2>/dev/null | grep -qaiE '^[0-9]+: *Terminal'; then
    say "RTT is live — the firmware's own log will be captured to $OUT/rtt.log"
else
    say "WARNING: no RTT channel is up — $OUT/rtt.log will stay EMPTY"
    say "  SEGGER_RTT initialises lazily on the firmware's first printf, so an idle card never"
    say "  gets there; a build without -DPICO_STDIO_RTT=ON never will at all (build_pz does not)."
    say "  Continuing: the wedge state is still worth capturing, but there will be no firmware"
    say "  narrative behind it, and no RTT evidence of which build produced this run."
fi

capture(){
    say "capturing the wedged state into $OUT"
    {
        echo "=== timestamp ==="; date

        # RP-AP POWER STATE FIRST, BEFORE ANY HALT OR RESET.
        #
        # The RP-AP answers when the core MEM-APs do not, and it carries the live power-sequencer
        # state of the four domains. Everything else in this capture goes through the MEM-AP, so on
        # the wedges worth investigating it is the only thing that returns anything at all.
        #
        # Baselines measured on a HEALTHY card 2026-08-08:
        #     SWCORE 0x0000095e   XIP 0x0000015e   SRAM0 0x0000015e   SRAM1 0x0000015e
        #
        # Read it before halting: a halt is a state change, and the question this answers — which
        # domain stopped — must be asked of the chip as the wedge left it. Raw words only; the bit
        # meanings are not verified on this bench and an invented decoder is worse than the value.
        echo; echo "=== RP-AP power state (SWCORE / XIP / SRAM0 / SRAM1) ==="
        ocd "rp2350.dap apreg 0x80000 0x08
rp2350.dap apreg 0x80000 0x0c
rp2350.dap apreg 0x80000 0x10
rp2350.dap apreg 0x80000 0x14"
        echo "    (healthy baseline: 0x095e / 0x015e / 0x015e / 0x015e)"
        echo "    SRAM0+SRAM1 at baseline => the dirty sector cache and flash_pages are probably"
        echo "    still physically present, and a rescue reset is what would destroy them."

        echo; echo "=== DP CTRL/STAT (sticky error bits) ==="; ocd "rp2350.dap dpreg 0x4"

        echo; echo "=== targets ==="; ocd "targets"
        echo; echo "=== core0 halt attempt + registers ==="; ocd "targets rp2350.cm0
halt
reg pc
reg sp
reg xpsr"
        echo; echo "=== core1 ==="; ocd "targets rp2350.cm1
halt
reg pc"
        echo; echo "=== POWMAN_WDSEL / PSM_WDSEL ==="; ocd "mdw 0x40100030
mdw 0x40018008"
        echo; echo "=== WATCHDOG_CTRL + SCRATCH[0..3] ==="; ocd "mdw 0x400d8000
mdw 0x400d800c 4"
        echo; echo "=== flash vector table (is the image intact?) ==="; ocd "mdw 0x10000000 4"

        # FLASH-SIDE FORENSICS, requested explicitly by upstream in pico-keys-sdk#25 Bug 6:
        # "the raw physical record header, the cached-sector copy, all flash_pages entries and the
        # original unaligned prev_addr from the same halted state." Fault registers alone cannot
        # distinguish physical-flash corruption from a corrupted dirty SRAM sector cache or an
        # invalid file->data, which is the distinction he needs to decide whether the corruption
        # is upstream's or an artefact of my patches. Captured from the SAME halted state, which is
        # the part that makes it usable.
        #
        # Symbols are resolved from the ELF rather than hardcoded: they move on every rebuild.
        ELF="${HSM_ELF:-/Users/jonathanborduas/code/pico-hsm/build_rtt/pico_hsm.elf}"
        NM="${HSM_NM:-$HOME/toolchains/arm-gnu-15.2/bin/arm-none-eabi-nm}"
        sym(){ "$NM" "$ELF" 2>/dev/null | awk -v n="$1" '$3==n {print "0x"$1; exit}'; }
        S_DET=$(sym fs_corruption_detected); S_ADDR=$(sym fs_corruption_addr)
        S_PREV=$(sym fs_corruption_prev);    S_PAGES=$(sym flash_pages)
        echo; echo "=== fs corruption state (detected/addr/prev) ==="
        [ -n "$S_DET" ]  && ocd "mdw $S_DET"
        [ -n "$S_ADDR" ] && ocd "mdw $S_ADDR"
        [ -n "$S_PREV" ] && ocd "mdw $S_PREV"
        echo; echo "=== flash_pages (the dirty sector cache) ==="
        [ -n "$S_PAGES" ] && ocd "mdw $S_PAGES 32"
        # The offending link and the one before it, read as RAW PHYSICAL FLASH — this is the record
        # header upstream asked for, and reading it here shows what is actually on the device
        # rather than what the in-memory structures claim.
        BAD=$( [ -n "$S_ADDR" ] && ocd "mdw $S_ADDR" | grep -aoE '[0-9a-f]{8}$' | tail -1 )
        PRV=$( [ -n "$S_PREV" ] && ocd "mdw $S_PREV" | grep -aoE '[0-9a-f]{8}$' | tail -1 )
        echo; echo "=== raw record header at the OFFENDING link (0x$BAD) ==="
        [ -n "$BAD" ] && [ "$BAD" != "00000000" ] && ocd "mdw 0x$BAD 8"
        echo; echo "=== raw record header at the PRECEDING link (0x$PRV) ==="
        [ -n "$PRV" ] && [ "$PRV" != "00000000" ] && ocd "mdw 0x$PRV 8"
        echo; echo "=== USB port ==="; uhubctl 2>/dev/null | grep -iE 'Pico Key|Port [0-9]:'
        echo; echo "=== ioreg ==="; ioreg -p IOUSB -w0 2>/dev/null | sed 's/<.*//' | grep -iE 'pico|probe'
        echo; echo "=== sc-hsm-tool ==="; perl -e 'alarm 20; exec @ARGV' -- sc-hsm-tool 2>&1 | head -5
    } > "$OUT/wedge-state.txt" 2>&1
    # The firmware's own last words, if RTT survived.
    tail -40 "$OUT/rtt.log" 2>/dev/null > "$OUT/rtt-tail.txt"
    say "captured: $OUT/wedge-state.txt and $OUT/rtt-tail.txt"
}

alive || { echo "card not answering before the hunt started"; exit 2; }
say "hunting a warm-boot wedge: up to $N reboots, ${WAIT}s window, output -> $OUT"

for i in $(seq 1 "$N"); do
    reboot_card
    w=0; back=0
    while [ "$w" -lt "$WAIT" ]; do
        sleep 3; w=$((w+3))
        if alive; then back=1; break; fi
    done
    if [ "$back" = 1 ]; then
        printf '  %2d/%d back in %2ds\n' "$i" "$N" "$w"
        continue
    fi
    # RULE OUT THE DEBUGGER BEFORE CALLING IT A WEDGE. OpenOCD halts the target when it
    # re-examines it after the device drops off USB, and a halted core cannot enumerate — which
    # presents identically to a device wedge. MEASURED 2026-08-07: this tool reported a wedge whose
    # signature was core0 HALTED with the watchdog clear and the flash image intact, and a plain
    # `reset run` returned the card in 4 s. That is the instrument creating its own finding, the
    # same defect the recovery ladder had.
    printf '  %2d/%d not back — checking whether the DEBUGGER is holding it\n' "$i" "$N"
    ocd "reset run" >/dev/null 2>&1
    w=0
    while [ "$w" -lt 30 ]; do
        sleep 3; w=$((w+3))
        if alive; then break; fi
    done
    if alive; then
        printf '      false alarm: the debugger was holding the core (reset run cleared it in %ss)\n' "$w"
        continue
    fi

    printf '  %2d/%d \033[31mWEDGED\033[0m — survives a reset run; holding the state still\n' "$i" "$N"
    capture
    echo
    echo "================ WEDGE CAPTURED after $i reboots ================"
    sed -n '1,60p' "$OUT/wedge-state.txt"
    echo
    echo "--- firmware's last words over RTT ---"
    cat "$OUT/rtt-tail.txt" 2>/dev/null | tail -20
    exit 0
done

say "no wedge in $N reboots — the fault did not reproduce this run"
exit 1
