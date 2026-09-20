#!/usr/bin/env bash
# Recover a Pico HSM that has stopped answering, over SWD, with no physical access.
#
# WHY THIS EXISTS. This bench has no SRST line — OpenOCD reports `reset_config: none separate` —
# so there is no reset pin to pull. The levers available over SWD are a warm reset and a POWMAN
# switched-core power cycle, which the RP2350 datasheet describes as "the same effect as a
# power-on reset for the switched core power domain": the closest thing to an unplug without hands.
#
#   ./hsm-swd-powman-recover.sh
#   OCD_PORT=4444 MAX_PASSES=8 ./hsm-swd-powman-recover.sh
#
# Exits 0 once the card actually answers, 1 if it never does.
set -uo pipefail

OCD_PORT="${OCD_PORT:-4444}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"

# PIN THE PROBE. From 2026-09-02 there are TWO debug probes on this bench, one per board. With no
# `adapter serial`, OpenOCD binds to whichever it finds first, so this ladder — which issues
# resets, POWMAN power cycles and rescue-DP resets — could aim all of that at the wrong card.
# HSM_RECOVER_BOARD is the OTP chip id it must find there; recovery refuses if it does not match,
# because "reset the other HSM" is not a recoverable mistake.
# card_answers() resolves HSM_RECOVER_SERIAL to a reader, which needs the shared resolver.
_rl_rs="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hsm-reader-select.sh"
# shellcheck source=/dev/null
[ -f "$_rl_rs" ] && . "$_rl_rs"

PROBE="${HSM_RECOVER_PROBE:-}"
EXPECT_BOARD="${HSM_RECOVER_BOARD:-}"
OCD_SERIAL_ARG=()
[ -n "$PROBE" ] && OCD_SERIAL_ARG=(-c "adapter serial $PROBE")
OCD_PID=""
OCD_LOG="${OCD_LOG:-/tmp/openocd.log}"
MAX_PASSES="${MAX_PASSES:-4}"
# Seconds to wait for the card after each remedy. MEASURED 2026-08-07: with SETTLE=45 the script
# ran eight POWMAN cycles, reported "a physical reseat is needed" — and the card was answering
# moments later, having come back only once the script STOPPED cycling. Recovery after a
# switched-core power cycle can take longer than 45 s, and re-cycling on top of an in-progress
# recovery restarts it. Fewer passes, each given real time, beats hammering.
SETTLE="${SETTLE:-100}"
# One last long wait before declaring failure, for the same reason: the expensive, human-costing
# verdict must not be reported while the device is still on its way back.
FINAL_WAIT="${FINAL_WAIT:-180}"
# HARD OVERALL DEADLINE. Without one, this script's runtime is the SUM of its parts and every
# caller has to guess it: MAX_PASSES x (SETTLE + SETTLE) + FINAL_WAIT, plus each card_answers()
# overshooting its window by up to its own 25 s alarm. That summed to ~1204 s against a caller
# budget of 1200 — so the caller SIGALRM'd it, which also skips the EXIT trap that leaves the
# target running. Twice this produced "NOT recovered — this one needs a human" for a card that
# answered moments later.
#
# A recovery tool must have a runtime its caller can rely on. This is that number: the script
# gives up cleanly when the budget is spent, so it always exits through its own trap.
BUDGET="${HSM_RECOVER_BUDGET:-900}"
DEADLINE=$(( $(date +%s) + BUDGET ))
budget_left(){ [ "$(date +%s)" -lt "$DEADLINE" ]; }

say(){ printf '  %s\n' "$*"; }

# OpenOCD's USB handle goes stale when the device drops, and a dead server looks exactly like a
# dead card. Make sure the server is up AND has examined the target before trusting anything.
# MEASURED 2026-08-07: a long-lived server that had watched several wedges answered `program`
# with "** Unable to reset target **" until it was restarted, after which the same command worked.
start_ocd(){
    "$OCD_BIN" -f interface/cmsis-dap.cfg "${OCD_SERIAL_ARG[@]}" -f target/rp2350.cfg \
        -c "adapter speed 5000" -c "telnet port $OCD_PORT" \
        > "$OCD_LOG" 2>&1 &
    OCD_PID=$!
    sleep 8
}

# Kill OUR OpenOCD, not every OpenOCD. `pkill -f openocd` also killed the session driving the
# OTHER board — with two probes attached that turns a recovery of one card into an outage of two.
stop_ocd(){
    if [ -n "$OCD_PID" ]; then kill "$OCD_PID" 2>/dev/null; wait "$OCD_PID" 2>/dev/null; OCD_PID=""
    elif [ -z "$PROBE" ]; then pkill -f "$(basename "$OCD_BIN")" 2>/dev/null   # legacy single-probe host
    fi
    return 0
}

# DEFINED HERE, ABOVE ITS FIRST CALLER. The board interlock below uses it, and a helper defined
# further down the file is not in scope yet when the interpreter reaches that point — the same
# ordering mistake that once left a SIGTERM'd run with no JUnit report at all.
ocd_out(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 40; exec @ARGV' -- nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000'; }

# ASK ABOUT *OUR* SERVER, NOT ABOUT ANY OpenOCD.
#
# This was `pgrep -f openocd`, i.e. "is some OpenOCD running anywhere?". With one probe that was a
# fair proxy; with two it is not — the OTHER board's server satisfies it, so this skips starting
# its own and then every ocd_out talks to whatever is listening on OCD_PORT, which may be a server
# attached to a different chip. Measured 2026-09-03: a leftover server on port 4470 made three
# consecutive runs report "cannot read the OTP chip id" while the board answered perfectly.
#
# The right question is whether OUR port is answering.
#
# But first: CLEAR ANY ORPHAN HOLDING **OUR PROBE**. A CMSIS-DAP probe admits ONE session, so a
# leaked server from an earlier run owns the probe while answering on some other port — our own
# server then starts, binds nothing useful, and every SWD read fails. That is not hypothetical:
# measured 2026-09-03, a nightly left three orphaned servers behind, recovery reported "cannot read
# the OTP chip id over SWD" three times running, and the card came back on the FIRST attempt after
# they were killed. The interlock read that as "the board is unproven" — a correct refusal for a
# wrong reason, which sent the diagnosis at the chip instead of at the stale process.
#
# Scoped to OUR probe serial, never a blanket `pkill openocd`: with two probes attached, killing
# every server turns one card's recovery into an outage of two.
if [ -n "$PROBE" ]; then
    for _orphan in $(pgrep -f "$PROBE" 2>/dev/null); do
        [ "$_orphan" = "$$" ] && continue
        case "$(ps -p "$_orphan" -o command= 2>/dev/null)" in
            *openocd*) say "killing orphaned OpenOCD $_orphan — it holds probe $PROBE"
                       kill "$_orphan" 2>/dev/null; sleep 2 ;;
        esac
    done
fi
if ! nc -z localhost "$OCD_PORT" 2>/dev/null; then
    say "no OpenOCD on :$OCD_PORT — starting one${PROBE:+ pinned to probe $PROBE}"; start_ocd
fi
if ! grep -q "Examination succeed" "$OCD_LOG" 2>/dev/null; then
    say "target not examined — restarting OpenOCD"
    stop_ocd; sleep 2; start_ocd
fi

# INTERLOCK: PROVE WE ARE ON THE BOARD WE WERE ASKED TO RECOVER.
#
# Everything below issues resets, POWMAN switched-core power cycles and rescue-DP resets. Aimed at
# the wrong board that is not a failed recovery, it is an outage of a healthy card — and with two
# probes on the bench "the probe" is not a thing. The OTP chip id is the board; reader indices and
# USB ordering are not (measured 2026-09-03: they flip across a replug and mid-run).
#
# Read it over SWD and refuse on mismatch. Retried because a freshly attached OpenOCD can answer
# an empty first read (measured the same day — a telnet query issued too soon returned nothing at
# all against a target that answered correctly a second later, which would look like a mismatch).
if [ -n "$EXPECT_BOARD" ]; then
    _rb_got=""
    for _rb_try in 1 2 3; do
        _rb_raw="$(ocd_out 'mdw 0x40130000 2')"
        _rb_lo="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$_rb_raw" | awk '{print $2}')"
        _rb_hi="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$_rb_raw" | awk '{print $3}')"
        if [ -n "$_rb_lo" ] && [ -n "$_rb_hi" ]; then
            _rb_got="$(printf '%s%s' "$_rb_hi" "$_rb_lo" | tr 'a-f' 'A-F')"; break
        fi
        sleep 2
    done
    if [ -z "$_rb_got" ]; then
        say "REFUSING: cannot read the OTP chip id over SWD, so the target board is unproven"
        exit 2
    fi
    if [ "$_rb_got" != "$(tr 'a-f' 'A-F' <<< "$EXPECT_BOARD")" ]; then
        say "REFUSING: probe ${PROBE:-<unpinned>} is on board $_rb_got, expected $EXPECT_BOARD"
        exit 2
    fi
    say "probe confirmed on board $_rb_got"
fi

# sc-hsm-tool can exit 0 while printing nothing useful, so require an actual Version line —
# otherwise this reports success on a card that is still absent.
#
# CAPTURE FIRST, THEN MATCH — DO NOT PIPE INTO `grep -q` UNDER `pipefail`.
#
# `grep -q` exits the instant it matches. That closes the pipe, the producer gets SIGPIPE and dies
# with 141, and `pipefail` then makes the whole pipeline return 141 — so the predicate reports
# FALSE precisely BECAUSE it matched. It is inverted, not flaky.
#
# MEASURED 2026-08-08, on a card answering `sc-hsm-tool` normally in the same second:
#     with    pipefail:  FALSE (rc=141)  x5
#     without pipefail:  TRUE            x5
#
# This is the worst bug found on this bench. card_answers() is the ONLY way this script recognises
# success, so with it inverted the ladder could never see a healthy card: it ran its full remedy
# sequence against working hardware — halting and resetting an HSM that was fine — and then always
# reached "a physical reseat is needed". Several of the premature human-needed verdicts, and every
# unexplained reset of a healthy card, are this.
#
# The lesson generalises: any `producer | grep -q` under `pipefail` is a predicate that can invert
# itself, and it does so silently and in the direction that manufactures failure.
# The here-string matters: it is a redirect from a temporary file, not a pipe with a live producer,
# so there is no process to SIGPIPE and no pipeline status to poison. Capturing into a variable and
# then piping with `printf ... | grep -q` would reintroduce the identical bug for large outputs —
# `ioreg` in particular prints far more than a pipe buffer holds.
card_answers(){
    local out
    # ASK ABOUT *OUR* CARD. Bare sc-hsm-tool talks to PC/SC reader 0, which with two HSMs attached
    # may be the OTHER one — so this could report "card is back" because the healthy spare
    # answered while the card being recovered is still wedged. A recovery tool that can succeed
    # without recovering anything is worse than one that fails.
    local _rdr=""
    if [ -n "${HSM_RECOVER_SERIAL:-}" ] && command -v hsm_reader_for >/dev/null 2>&1; then
        _rdr="$(hsm_reader_for "$HSM_RECOVER_SERIAL" 2>/dev/null)" || return 1
    fi
    out="$(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool ${_rdr:+-r "$_rdr"} 2>&1)"
    grep -qi '^Version' <<< "$out"
}
usb_present(){
    local out
    # PRESENCE OF *THIS* BOARD, not of any Pico. Matching "Pico Key" anywhere in ioreg is true
    # whenever EITHER card is attached, so with two boards a target that is completely ABSENT from
    # USB still looks "enumerated but mute" — and the ladder then picks the warm-reset rung when it
    # should escalate. Measured 2026-09-03: the staging card was off the bus entirely (0 ioreg
    # entries) and only a rescue-DP reset brought it back, but this predicate saw the spare.
    #
    # The USB serial IS the OTP board id, so EXPECT_BOARD identifies it exactly.
    out="$(ioreg -p IOUSB -l -w0 2>/dev/null)"
    if [ -n "$EXPECT_BOARD" ]; then
        grep -qi "$EXPECT_BOARD" <<< "$out"
    else
        grep -qi 'Pico Key' <<< "$out"
    fi
}

# Where to cut VBUS. This has to be resolved while the device is PRESENT and remembered, because
# by the time the power cut is needed the device is gone and there is nothing left to search for.
# Explicit env wins; otherwise detect from uhubctl now and cache; otherwise fall back to the cache
# from a previous run.
PORT_CACHE="${HSM_UHUBCTL_CACHE:-${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}/uhubctl-port}"
HSM_PICO_VIDPID="${HSM_PICO_VIDPID:-2e8a:10fd}"

detect_power_port(){
    command -v uhubctl >/dev/null 2>&1 || return 1
    # Walk uhubctl's output: remember the most recent "Current status for hub X", and when the
    # Pico's VID:PID shows up on a port line, that hub/port pair is the one that powers it.
    uhubctl 2>/dev/null | awk -v want="$HSM_PICO_VIDPID" '
        /^Current status for hub /{ hub=$5 }
        /^[ \t]*Port [0-9]+:/ && index($0, want) > 0 {
            gsub(/:/, "", $2); print hub, $2; exit
        }'
}

resolve_power_port(){
    if [ -n "${HSM_UHUBCTL_LOC:-}" ] && [ -n "${HSM_UHUBCTL_PORT:-}" ]; then return 0; fi
    local found
    found="$(detect_power_port)"
    if [ -n "$found" ]; then
        HSM_UHUBCTL_LOC="${found%% *}"; HSM_UHUBCTL_PORT="${found##* }"
        mkdir -p "$(dirname "$PORT_CACHE")" 2>/dev/null
        printf '%s %s\n' "$HSM_UHUBCTL_LOC" "$HSM_UHUBCTL_PORT" > "$PORT_CACHE" 2>/dev/null
        return 0
    fi
    if [ -r "$PORT_CACHE" ]; then
        read -r HSM_UHUBCTL_LOC HSM_UHUBCTL_PORT < "$PORT_CACHE"
        [ -n "${HSM_UHUBCTL_LOC:-}" ] && [ -n "${HSM_UHUBCTL_PORT:-}" ] && return 0
    fi
    return 1
}
# HSM_RECOVER_NO_VBUS=1 — pretend there is no switchable hub.
#
# THE DEPLOYMENT QUESTION THIS ANSWERS. Soaks on this bench report "0 human interventions", but the
# bench has a per-port-switchable hub and cut_vbus is one of the ladder's rungs. A deployed HSM
# generally does NOT have one: if recovery ever depends on cutting VBUS, "0 human interventions"
# here means "a human, or a power-cycling PDU, in the field".
#
# Three of the four rungs work over SWD alone (rescue_reset, warm_reset, powman_cycle) and only
# cut_vbus needs the hub — but which rung actually clears a given wedge had never been recorded,
# because the soak sent the ladder's output to /dev/null. Setting this makes the ladder refuse the
# power switch, so a soak arm can measure whether SWD alone is sufficient instead of assuming it.
if [ -n "${HSM_RECOVER_NO_VBUS:-}" ]; then
    HSM_UHUBCTL_LOC=""; HSM_UHUBCTL_PORT=""
    say "power control: DISABLED by HSM_RECOVER_NO_VBUS — SWD rungs only"
else
    resolve_power_port && say "power control: hub $HSM_UHUBCTL_LOC port $HSM_UHUBCTL_PORT (VBUS can be cut)"
fi

ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 40; exec @ARGV' -- nc localhost "$OCD_PORT" >/dev/null 2>&1; }

# ocd() discards output because most callers only care that the command was accepted. Probing the
# server needs to READ the answer, so this variant returns it.
#
# STRIP NULs *AND* GREP WITH -a. OpenOCD's telnet stream carries IAC negotiation bytes (0xff ...)
# and a NUL after each response. Both make grep treat the input as BINARY, and a binary-mode grep
# silently declines to match a pattern that is plainly there — stripping the NULs alone was NOT
# enough, because the IAC bytes still tripped it. MEASURED 2026-08-08: `mdw 0x40100030` returned "0x40100030: 00000000" and
# the probe still reported "cannot read the chip", on a perfectly healthy card, every single time.
# That is the worst shape a probe can fail in: it was not merely unreliable, it was CONSTANT, so it
# carried no information at all while reading like a diagnosis.

# TRUST NOTHING A LONG-LIVED OpenOCD SAYS ABOUT THE CHIP. A server that has watched several wedges
# keeps answering — but about a chip it can no longer really see. MEASURED on this bench, four
# distinct ways it has lied: `targets` reporting core0 in state `reset` with every memory read
# failing and persisting across `reset run` (a fresh server on the same chip said `halted`, and one
# `reset run` returned the card in 4 s); "** Unable to reset target **" until restarted; holding
# cores halted after a USB drop; and delivering zero RTT bytes from a channel it listed as up.
#
# Every remedy below is spent THROUGH this server, so a stale one does not just waste a pass — it
# makes the ladder conclude "a human is needed" about a card that is fine. Probe against ground
# truth (one register read that must return a word) and restart when the probe fails.
#
# Bounded, because on a genuinely dead chip the probe fails every time and restarting forever would
# eat the budget doing nothing. Two restarts is enough to tell "stale server" from "absent chip".
OCD_REFRESHES=0
refresh_ocd_if_stale(){
    local probe
    probe="$(ocd_out "mdw 0x40100030")"
    if LC_ALL=C grep -qaEi '40100030: *[0-9a-f]{8}' <<< "$probe"; then
        OCD_REFRESHES=0        # it can see the chip; a later failure earns a fresh allowance
        return 0
    fi
    if [ "$OCD_REFRESHES" -ge "${OCD_MAX_REFRESH:-2}" ]; then
        say "OpenOCD still cannot read the chip after ${OCD_REFRESHES} restarts — treating the chip as the problem"
        return 1
    fi
    OCD_REFRESHES=$((OCD_REFRESHES+1))
    say "OpenOCD answers but cannot read the chip — restarting it (${OCD_REFRESHES}/${OCD_MAX_REFRESH:-2})"
    stop_ocd; sleep 2; start_ocd
    return 0
}

# POWMAN switched-core power cycle.
#   0x40100030  POWMAN_WDSEL   0x5AFE is the mandatory POWMAN write password;
#                              RESET_PSM|RESET_SWCORE|RESET_POWMAN_ASYNC = 0x1101
#   0x40018008  PSM_WDSEL      all domains
#   0x400d8000  WATCHDOG_CTRL  TRIGGER
#
# DO NOT HALT FIRST — the single most important line in this script. Every attempt used to open
# with `halt`, and `halt` TIMES OUT in exactly the state this remedy exists for: measured
# 2026-08-07, core0 "running" but refusing every halt request ("Halt timed out, wake up GDB"),
# core1 parked in the bootrom, USB gone. OpenOCD then dropped the connection, so the writes below
# NEVER RAN and the script reported "a physical reseat is needed" having never attempted the
# recovery. The writes go through the DAP memory port and need no halted core; issued without the
# halt they recovered an unhaltable core0 immediately.
powman_cycle(){
    ocd "mww 0x40100030 0x5AFE1101
mww 0x40018008 0x01ffffff
mww 0x400d8000 0x80000000"
}

# Warm reset, for a card whose firmware is alive but whose card session is stuck. Halting FIRST
# is what makes it take: with no SRST, the reset is driven through the debug interface and a core
# spinning with interrupts disabled rides straight through a bare `reset run` (measured
# 2026-08-06 — bare reset did nothing, halt-then-reset revived the same card in seconds).
warm_reset(){ ocd "halt
reset run"; }

# A HALTED CORE CANNOT ENUMERATE USB. warm_reset() halts deliberately, so if the `reset run` after
# it does not take — or the run is interrupted between the two — this script leaves the chip
# halted, which presents EXACTLY as the wedge it exists to clear: port shows "power connect" with
# no enable, sc-hsm-tool sees nothing, and the ladder then escalates to VBUS cuts that cannot help
# because the chip cold-boots and OpenOCD is still holding it.
#
# MEASURED 2026-08-07: a ladder run ended with both cores halted, two VBUS cuts failed to recover
# the card, and a plain `reset run` brought it back in 4 s. The tool had manufactured the failure
# it was reporting.
#
# So: never leave the target halted, on ANY exit path.
ensure_running(){
    card_answers && return 0
    # Do NOT gate this on a point-in-time "is the target halted" check: OpenOCD re-examines the
    # target asynchronously after power returns and can halt it AFTER the check passes, so the
    # race is unwinnable. If the card is not answering, just reset it — a `reset run` costs
    # nothing on a chip that is already not working, and it is exactly what cleared this state
    # by hand every time.
    say "card not answering — reset run, in case the debugger is holding the core"
    ocd "reset run"
    return 0
}
trap ensure_running EXIT

# COUNT WALL TIME, NOT SLEEPS. This used to do `sleep 5; w=$((w+5))` — but card_answers() runs
# sc-hsm-tool under `alarm 25`, and on an ABSENT card it burns the whole 25 s. So each iteration
# cost up to 30 s of real time while the counter advanced by 5, making SETTLE=100 mean up to 600 s.
# Eight such waits per run put the ladder far past any caller's timeout: measured 2026-08-07, a
# soak killed it at 1200 s twice and recorded "this one needs a human" for a card that answered
# moments later. A timeout that does not measure time is not a timeout.
wait_for_card(){
    local deadline
    deadline=$(( $(date +%s) + ${1:-$SETTLE} ))
    # Never wait past the overall budget, or the sum of the waits defeats it.
    [ "$deadline" -gt "$DEADLINE" ] && deadline="$DEADLINE"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        card_answers && return 0
        sleep 3
    done
    return 1
}

# THE TWO FAILURE STATES ALTERNATE, which is why this is a loop and not a ladder.
#
#   enumerated but mute   ("Pico Key" present, sc-hsm-tool says "Card not present")
#       -> warm reset. The firmware is alive; only the card session is stuck.
#   absent from the USB bus
#       -> POWMAN power cycle.
#
# MEASURED 2026-08-07: a POWMAN cycle brought an absent card back onto the bus but left it MUTE,
# and the following warm reset dropped it off the bus again. A linear ladder walks past the state
# it just created and gives up; re-evaluating every pass converges instead. That single structural
# difference is what turns "a physical reseat is needed" into unattended recovery.
SWD_PASSES="${SWD_PASSES:-2}"   # SWD attempts before reaching for the power switch

# CAPTURE THE POWER STATE BEFORE DESTROYING IT.
#
# The RP-AP stays reachable when the core MEM-APs do not — that is the whole reason the rescue path
# works — and it carries live power-sequencer state for the four domains. Reading it costs nothing
# and must happen BEFORE any rescue, because the rescue is what removes the evidence.
#
# MEASURED 2026-08-08 on a HEALTHY card, and these are the baselines everything is compared against:
#     0x08 SWCORE 0x0000095e     0x0c XIP    0x0000015e
#     0x10 SRAM0  0x0000015e     0x14 SRAM1  0x0000015e
#
# WHY IT MATTERS MORE THAN IT LOOKS. Rescue costs the SRAM half of the evidence: after RESCUE_RESTART
# the SRAM reads back RANDOM (measured, four separated addresses, four different values) while both
# scratch banks read back ZERO (POWMAN SCRATCH0..7 and WATCHDOG SCRATCH0..3, both measured). Zeroed
# registers plus randomised SRAM is not the signature of a software scrub — a scrub would zero both.
# It is the signature of the SRAM DOMAINS BEING POWER-CYCLED. Which means: if a wedge leaves SRAM0
# and SRAM1 still powered and only SWCORE stalled, the cached sector and flash_pages array are still
# physically present, and anything that restores bus access WITHOUT a rescue would recover them.
#
# So this reads the four domains and says plainly whether the SRAM domains still look powered. It
# does NOT decode individual bits — the bit meanings are not verified on this bench, and a decoder
# that invents field names is worse than the raw word.
RP_AP="${RP_AP:-0x80000}"
rp_ap_state(){
    local raw swcore xip sram0 sram1
    raw="$(ocd_out "${OCD_CHIPNAME:-rp2350}.dap apreg $RP_AP 0x08
${OCD_CHIPNAME:-rp2350}.dap apreg $RP_AP 0x0c
${OCD_CHIPNAME:-rp2350}.dap apreg $RP_AP 0x10
${OCD_CHIPNAME:-rp2350}.dap apreg $RP_AP 0x14")"
    swcore="$(LC_ALL=C grep -aoE '0x[0-9a-f]{8}' <<< "$raw" | sed -n 1p)"
    xip="$(LC_ALL=C   grep -aoE '0x[0-9a-f]{8}' <<< "$raw" | sed -n 2p)"
    sram0="$(LC_ALL=C grep -aoE '0x[0-9a-f]{8}' <<< "$raw" | sed -n 3p)"
    sram1="$(LC_ALL=C grep -aoE '0x[0-9a-f]{8}' <<< "$raw" | sed -n 4p)"
    if [ -z "$swcore" ]; then
        say "RP-AP power state: UNREADABLE (the rescue port itself is not answering)"
        return 1
    fi
    say "RP-AP power state: SWCORE=$swcore XIP=$xip SRAM0=$sram0 SRAM1=$sram1  (healthy: 095e/015e/015e/015e)"
    if [ "$sram0" = "0x0000015e" ] && [ "$sram1" = "0x0000015e" ]; then
        say "  SRAM0/SRAM1 match the powered baseline — the cached sector and flash_pages are LIKELY STILL LIVE."
        say "  A rescue reset will destroy them. If this wedge is being investigated rather than just"
        say "  cleared, capture SRAM before rescuing (HSM_RECOVER_NO_RESCUE=1 stops short of it)."
    else
        say "  SRAM domains DIFFER from the powered baseline — SRAM contents are probably already gone."
    fi
    return 0
}

# RESCUE RESET — the remedy for a STALLED BUS, and the only one that reaches this state.
#
# Every other rung here talks to the chip THROUGH its memory bus: warm_reset halts and resets a
# core, powman_cycle writes POWMAN registers. When the AHB bus itself is hung, all of them fail at
# the same place and for the same reason — OpenOCD reports "stalled AP operation, issuing ABORT"
# and cannot read or WRITE a single register. There is nothing left to ask.
#
# MEASURED 2026-08-08, and this is the state that had been costing the replugs. The card was down
# with:
#     SWD DPIDR 0x4c013477          <- the debug port itself answers fine
#     [rp2350.cm0] Examination failed   Failed to read memory at 0xe000ed00
#     [rp2350.cm1] Examination failed   Failed to read memory at 0x40100000
# The chip was powered, the DP was alive, and the entire bus behind it was stalled. Four ladder
# passes — two POWMAN cycles and two VBUS cuts — did nothing, because none of them can be delivered
# over a stalled AP.
#
# RP2350 has a debug port that survives exactly this: the RP_AP's RESCUE_RESTART bit resets
# everything EXCEPT the DP and RP_AP, so it is reachable when nothing else is. Writing it brought
# the card back in one attempt, and it then passed the full HSM battery. It is the difference
# between "a human must walk to the bench" and "recovered unattended" for the hardest wedge class
# this device produces.
#
# Cores stop in the bootrom afterwards, and the server's failed examination is cached, so the
# server must be restarted before the chip is asked to run.
rescue_reset(){
    # Record the power state first — the rescue is what destroys it.
    rp_ap_state || true

    if [ -n "${HSM_RECOVER_NO_RESCUE:-}" ]; then
        say "HSM_RECOVER_NO_RESCUE set — stopping BEFORE the rescue so the wedge can be examined"
        say "  SRAM still holds the cached sector and flash_pages if the SRAM domains are up."
        return 1
    fi

    say "rescue reset: the bus is stalled, resetting everything except the DP"
    ocd "poll off
${OCD_CHIPNAME:-rp2350}.dap apreg $RP_AP 0 0x80000000
${OCD_CHIPNAME:-rp2350}.dap apreg $RP_AP 0 0
dap init
poll on"
    say "restarting OpenOCD so it re-examines the cores the rescue left in the bootrom"
    stop_ocd
    sleep 2
    start_ocd

    # DUMP THE FILESYSTEM BEFORE LETTING THE FIRMWARE RUN.
    #
    # Flash is non-volatile, so the corrupt chain link and the raw record header survive the rescue
    # — but only until the firmware boots and touches the filesystem. The rescue leaves both cores
    # stopped in the bootrom, and that window is the ONLY chance to photograph the on-flash state.
    # MEASURED 2026-08-08: the first hard wedge was rescued and immediately `reset run`, and the
    # firmware booted straight through the structure that was the whole point of catching it.
    #
    # The fs lives in the UPPER HALF of flash (low_flash.c: data_start_addr = FLASH_SIZE_BYTES >> 1)
    # with records allocated DOWNWARD from the top, so the tail is where the chain actually is.
    # Dumping the tail rather than all 16 MB keeps this to seconds instead of minutes.
    if [ -n "${HSM_WEDGE_DUMP_DIR:-}" ]; then
        local out size base
        size="${HSM_FS_DUMP_BYTES:-0x100000}"
        base="${HSM_FS_DUMP_BASE:-0x10f00000}"
        mkdir -p "$HSM_WEDGE_DUMP_DIR" 2>/dev/null
        out="$HSM_WEDGE_DUMP_DIR/fs-tail-$(date +%Y%m%d-%H%M%S).bin"
        say "capturing the filesystem tail ($size bytes @ $base) BEFORE the firmware runs"
        ocd "halt
dump_image $out $base $size"
        if [ -s "$out" ]; then
            say "  captured $(wc -c < "$out" | tr -d ' ') bytes -> $out"
        else
            say "  WARNING: the dump is empty — the on-flash evidence was NOT captured"
        fi
    fi

    ocd "reset run"
}

# ALWAYS PASS -e. uhubctl APPLIES "USB3 DUALITY HANDLING" BY DEFAULT AND WILL SWITCH A DIFFERENT HUB.
#
# A USB3-capable hub enumerates as two virtual hubs — a USB2 one and a USB3 one — and without
# --exact, uhubctl silently remaps the location you asked for onto its sibling. MEASURED 2026-08-09:
# `uhubctl -l 1-1.3 -p 3 -a off` printed "New status for hub 1-2.3", i.e. it powered a port on the
# USB3 hub while the device sat on the USB2 one. Adding `-n 2109:2817` did not help; only `-e` did.
#
# This matters far beyond a cosmetic mismatch. On 2026-08-08 this ladder concluded that the bench's
# hub "advertises ppps and does not implement it", and that finding was written into the forensics
# doc, the instrumentation plan, and an upstream comment as the reason power-loss testing was
# impossible. With -e, a port cut is REAL: the card stops answering and its USB registry id changes,
# which is re-enumeration and therefore genuine power removal.
#
# Verify any hub the same way, and do not trust the port status bits alone: power off the port a
# KNOWN-GOOD device is on, then check that it stops ANSWERING and that its registry id changes when
# it returns. macOS may keep a stale ioreg entry for a device that is already dead, so presence in
# ioreg proves nothing.
cut_vbus(){
    say "cutting VBUS on hub $HSM_UHUBCTL_LOC port $HSM_UHUBCTL_PORT (exact location)"
    uhubctl -e -l "$HSM_UHUBCTL_LOC" -p "$HSM_UHUBCTL_PORT" -a cycle -d "${HSM_UHUBCTL_DELAY:-3}" \
        >/dev/null 2>&1 || say "uhubctl reported an error (is the port switchable?)"
    # RESTART OPENOCD AFTER CUTTING POWER. The target disappears and comes back, so the server's
    # handle on it is stale — and every subsequent `reset run` goes into that stale handle and does
    # nothing. MEASURED 2026-08-08: the ladder cut VBUS, its own ensure_running `reset run` failed
    # to revive the card, and a FRESH server issuing the identical `reset run` returned it in 4 s.
    # Without this the power cut — the strongest remedy available — is routinely wasted.
    say "restarting OpenOCD after the power cut (its target handle is now stale)"
    stop_ocd
    sleep 2
    start_ocd
}

for pass in $(seq 1 "$MAX_PASSES"); do
    budget_left || { say "recovery budget (${BUDGET}s) spent — stopping cleanly"; break; }
    if card_answers; then
        say "card answers: $(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool 2>&1 | grep -i '^Version' | head -1)"
        exit 0
    fi
    # Before spending a pass THROUGH the debug server, make sure it can still see the chip.
    # Guarded by the budget: a restart costs ~10 s and must not push us past the deadline.
    # A failure here is not just a stale server — after two restarts it means the chip's own bus
    # is not answering, which decides the remedy below.
    chip_readable=1
    budget_left && { refresh_ocd_if_stale || chip_readable=0; }

    # PICK THE REMEDY BY WHAT IS ACTUALLY BROKEN, not by how many passes have gone by.
    #
    # If the memory bus will not answer, EVERY rung that goes over it is a no-op: warm_reset cannot
    # halt, powman_cycle cannot write POWMAN, and cutting VBUS is beside the point because the chip
    # is powered and it is the bus that is hung. The rescue DP is the only path left, so take it
    # immediately instead of spending three passes proving the others cannot work.
    if [ "$chip_readable" = 0 ]; then
        say "pass $pass/$MAX_PASSES: the debug bus is STALLED — nothing over it can be delivered"
        rescue_reset
    # Once SWD has had a couple of goes, STOP asking the chip to fix itself and remove its power.
    # A wedged core0 that will not halt cannot be reset over SWD at all, and cutting VBUS is
    # electrically what a human replug does — so if power control exists there is no reason to
    # keep escalating a remedy that is known not to reach this state.
    elif [ "$pass" -gt "$SWD_PASSES" ] && [ -n "${HSM_UHUBCTL_LOC:-}" ] && [ -n "${HSM_UHUBCTL_PORT:-}" ] \
       && command -v uhubctl >/dev/null 2>&1; then
        say "pass $pass/$MAX_PASSES: SWD did not clear it — going to the power switch"
        cut_vbus
    elif usb_present; then
        say "pass $pass/$MAX_PASSES: enumerated but MUTE — warm reset"
        warm_reset
    else
        say "pass $pass/$MAX_PASSES: ABSENT from the USB bus — POWMAN power cycle"
        powman_cycle
    fi
    if wait_for_card; then
        say "card is back after pass $pass: $(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool 2>&1 | grep -i '^Version' | head -1)"
        exit 0
    fi
    # The settle window expired. Before escalating, rule out the possibility that the chip is
    # HELD rather than wedged — a halted core cannot enumerate USB, and OpenOCD halts the target
    # when it re-examines it after a power cycle.
    budget_left || { say "recovery budget (${BUDGET}s) spent — stopping cleanly"; break; }
    ensure_running
    if wait_for_card; then
        say "card is back after releasing the debugger: $(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool 2>&1 | grep -i '^Version' | head -1)"
        exit 0
    fi
done

# LAST ESCALATION: actually cut VBUS. Everything above asks the chip to reset itself, which cannot
# help if it has stopped responding to the debug interface altogether.
#
# REQUIRES the device on a port whose power can be switched (a hub advertising `ppps`). On this
# bench it is NOT — the Pico is on an Apple root port, and was previously behind a self-powered
# hub where cycling the upstream port left the board powered (verified: the hub re-enumerated, the
# card did not). Until it moves to a switchable port this stage cannot run, and says so.
#
#   HSM_UHUBCTL_LOC=2-1 HSM_UHUBCTL_PORT=2 ./hsm-swd-powman-recover.sh
#
if ! budget_left; then
    say "recovery budget (${BUDGET}s) spent — not starting a VBUS cycle there is no time to wait out"
elif [ -n "${HSM_UHUBCTL_LOC:-}" ] && [ -n "${HSM_UHUBCTL_PORT:-}" ] && command -v uhubctl >/dev/null 2>&1; then
    say "SWD exhausted — cutting VBUS on ${HSM_UHUBCTL_LOC} port ${HSM_UHUBCTL_PORT}"
    uhubctl -l "$HSM_UHUBCTL_LOC" -p "$HSM_UHUBCTL_PORT" -a cycle -d "${HSM_UHUBCTL_DELAY:-3}" \
        >/dev/null 2>&1 || say "uhubctl reported an error (is the port switchable?)"
    wait_for_card && { say "card is back after a USB power cycle"; exit 0; }
    say "still absent after a full VBUS power cycle"
elif command -v uhubctl >/dev/null 2>&1; then
    say "uhubctl is installed but HSM_UHUBCTL_LOC/HSM_UHUBCTL_PORT are unset — cannot cut power"
    say "run 'uhubctl' to find the device's hub/port; it must be on a hub advertising 'ppps'"
else
    say "uhubctl not installed — no way to cut power without hands"
fi

# THE LAST WAIT BEFORE THE EXPENSIVE VERDICT. "A physical reseat is needed" costs a human, and
# this script has already cried it once while the card was on its way back — an earlier version
# gave up after eight fast cycles and the card was answering moments later. FINAL_WAIT existed as
# a variable for exactly this and was never actually used; that gap is what made the premature
# verdict possible. ensure_running first, in case the debugger is the thing holding it.
ensure_running

# LAST RESORT BEFORE SPENDING SOMEONE'S TIME: the rescue DP, unconditionally.
# It is cheap, it is the only remedy that survives a stalled bus, and it is the one that turned
# today's four-pass failure into a recovery. Declaring "a human is needed" without having tried it
# is claiming the device is unreachable while the one port designed to stay reachable went unused.
if budget_left; then
    rescue_reset
    if wait_for_card 60; then
        say "card is back after a rescue reset: $(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool 2>&1 | grep -i '^Version' | head -1)"
        exit 0
    fi
fi

say "last chance: waiting ${FINAL_WAIT}s before declaring that a human is needed"
if wait_for_card "$FINAL_WAIT"; then
    say "card came back during the final wait: $(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool 2>&1 | grep -i '^Version' | head -1)"
    exit 0
fi

say "card did NOT come back after $MAX_PASSES passes — a physical reseat is needed"
exit 1
