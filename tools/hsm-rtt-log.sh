#!/usr/bin/env bash
# hsm-rtt-log.sh — stream the Pico HSM firmware's own printf output over SWD, via RTT.
#
#   tools/hsm-rtt-log.sh                  # stream until interrupted
#   tools/hsm-rtt-log.sh 120 out.log      # capture 120s to a file
#
# WHY RTT AND NOT THE UART. The Debug Probe carries a UART bridge, but this board (Waveshare
# RP2350-PiZero) puts PICO_DEFAULT_UART on **uart1, GPIO4/GPIO5** — not the usual GPIO0/1 — so the
# probe's UART wires read nothing unless they happen to be on those pins. RTT needs no wires at
# all: the firmware writes into an SRAM ring buffer and OpenOCD reads it through the same SWD
# connection already used for everything else.
#
# WHY IT MATTERS. This is the only channel that keeps working when the card is wedged. USB is gone
# in exactly the states worth diagnosing, and breakpoints race the USB stack rather than observing
# it. RTT reports what the firmware itself thinks it is doing:
#
#   INIT: wipe done, committing flash synchronously
#   INIT: scheduling reset in 500 ms
#   CARD: scheduled reset firing
#   CARD: rebooting via rom_reboot (shallow)      <- which reset path was actually taken
#   SCAN / scan fid 2f02, len 443                 <- the fs the firmware found on the way back
#
# REQUIRES firmware built with RTT stdio. build_pz does NOT have it; build_rtt does:
#   PICO_SDK_PATH=$HOME/pico-sdk cmake -S . -B build_rtt \
#     -DPICO_BOARD=waveshare_rp2350_pizero -DPICO_TOOLCHAIN_PATH=$HOME/toolchains/arm-gnu-15.2 \
#     -DPICO_STDIO_RTT=ON -DPICO_STDIO_UART=ON -DCMAKE_BUILD_TYPE=Release
# Flash it over SWD, no BOOTSEL button needed:
#   printf 'halt\nprogram .../build_rtt/pico_hsm.elf verify reset\nexit\n' | nc localhost 4444
set -u

OCD_PORT="${OCD_PORT:-4444}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
OCD_LOG="${OCD_LOG:-/tmp/openocd.log}"
RTT_PORT="${RTT_PORT:-9090}"
SECS="${1:-0}"                 # 0 = stream until interrupted
OUT="${2:-}"

# START FROM A FRESH SERVER. A long-lived OpenOCD stops delivering RTT even though `rtt channels`
# still lists an initialised channel — the check passes and the capture yields zero bytes.
# MEASURED 2026-08-08: two captures returned 0 bytes with `0: Terminal 1024 0` reported, and the
# identical sequence against a freshly started server captured the boot scan immediately.
#
# This is the fourth way a stale OpenOCD has lied on this bench (also: "Unable to reset target"
# until restarted; `targets` reporting a phantom `reset` state; and holding cores halted after a
# USB drop). RTT capture is a diagnostic session, so paying ~9s for a clean server is cheap
# insurance against silently logging nothing. HSM_RTT_KEEP_OCD=1 opts out.
if [ -z "${HSM_RTT_KEEP_OCD:-}" ]; then
    pkill -f "$(basename "${OCD_BIN:-openocd}")" 2>/dev/null
    sleep 2
    "${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}" \
        -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c "adapter speed 5000" \
        > "${OCD_LOG:-/tmp/openocd.log}" 2>&1 &
    sleep 9
fi

# STRIP NULs: OpenOCD's telnet stream carries IAC negotiation bytes and a NUL after each response,
# and grep treats input containing a NUL as BINARY — so a pattern that is plainly present never
# matches. Measured 2026-08-08: a probe reading "0x40100030: 00000000" reported "cannot read the
# chip" on a healthy card every time. A check that fails constantly carries no information while
# reading exactly like a diagnosis.
ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 30; exec @ARGV' -- nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000'; }

# The control block lives in SRAM and MOVES when the firmware is rebuilt, so search rather than
# hardcode. A reset re-initialises it, which is why `rtt start` may need re-running after one.
#
# Do NOT gate on "control block found": that line only appears on a FRESH start, so a session that
# was already polling (a previous run, an interactive debug session) makes this look like a
# failure. It cost a whole nightly's worth of firmware logs — the script exited 2 before creating
# its output file while RTT was, in fact, working perfectly. Ask what is true now instead: can we
# enumerate channels?
# WAIT FOR AN ACTUAL CHANNEL, NOT JUST "up=N". SEGGER_RTT initialises its channels LAZILY, on the
# firmware's first printf. Before that the control block is already findable — it lives in .data
# and is populated by crt0 — so OpenOCD reports `Channels: up=3` with an EMPTY channel list, and a
# `rtt start` issued in that window never picks the channel up afterwards. Checking for "up="
# therefore succeeds while delivering nothing, which is exactly how a nightly's worth of firmware
# logs was lost: the capture looked healthy and produced zero bytes.
#
# An idle card does not print, so this retries the setup while waiting for the firmware to say
# something (a reboot, an INITIALIZE, any command that logs).
rtt_ready(){
    ocd "rtt setup 0x20000000 0x80000 \"SEGGER RTT\"
rtt start
rtt channels" 2>/dev/null | grep -qaiE '^[0-9]+: *Terminal'
}
tries=0
until rtt_ready; do
    tries=$((tries+1))
    if [ "$tries" -ge "${RTT_SETUP_TRIES:-10}" ]; then
        echo "RTT control block found but NO channel is initialised." >&2
        echo "SEGGER_RTT initialises on the firmware's first printf — an idle card never gets there." >&2
        echo "Reboot the card or run a command that logs, then retry; or check the build has" >&2
        echo "-DPICO_STDIO_RTT=ON (build_pz does not, build_rtt does)." >&2
        exit 2
    fi
    sleep 3
done

ocd "rtt server start $RTT_PORT 0" | grep -qai 'listening' || true
sleep 1

if [ "$SECS" -gt 0 ] 2>/dev/null; then
    if [ -n "$OUT" ]; then
        perl -e "alarm $SECS; exec @ARGV" -- nc localhost "$RTT_PORT" | tr -d '\r' > "$OUT"
        echo "captured $(wc -l < "$OUT") lines to $OUT"
    else
        perl -e "alarm $SECS; exec @ARGV" -- nc localhost "$RTT_PORT" | tr -d '\r'
    fi
else
    nc localhost "$RTT_PORT" | tr -d '\r'
fi
