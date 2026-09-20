#!/usr/bin/env bash
# hsm-reboot-soak.sh — measure how reliably the card comes back from the rescue applet's reboot,
# and whether the wedges that remain recover WITHOUT a human.
#
#   tools/hsm-reboot-soak.sh [iterations] [wait-seconds]
#   tools/hsm-reboot-soak.sh 25 90
#
# WHAT IT EXERCISES. The exact APDU pair scenario S5 uses: select the rescue applet
# (A0:58:3F:C1:9B:7E:4F:21) then 80:1F:00:00 (reboot to normal mode). rescue.c services that with
# watchdog_reboot(). This is the single most load-bearing reliability property of the device —
# an HSM that does not survive a restart is not one — and it is the path that regressed silently
# when POWMAN_WDSEL was armed globally (hardware/pico-hsm/UPSTREAM-WDSEL-SCOPE.md).
#
# WHY IT LIVES IN THE REPO. It was written as a throwaway in a scratch directory and lost to a
# session restart mid-measurement. It is not a throwaway: it is how the reboot number is produced,
# and every claim about that number has to be re-derivable.
#
# TWO NUMBERS COME OUT, and conflating them would hide the thing that matters:
#   * how often the reboot returns the card BY ITSELF   — the device's own reliability
#   * how many of the remaining wedges recover UNATTENDED — whether a human is still required
# A run needing hands is reported as such no matter how good the first number looks.
set -u

# HSM_REPO overrides self-location, because this script is sometimes run from a FROZEN COPY.
#
# Editing a running bash script corrupts it — bash reads lazily, so an edit shifts the offsets and
# the interpreter dies mid-run. Soak 5 lost its final summary that way. The fix was to copy the
# script to /tmp and run the copy, which introduced a worse bug: REPO is derived from BASH_SOURCE,
# so from /tmp it resolved to "/" and every snapshot call became //tools/hsm-wedge-snapshot.sh.
# That path does not exist, the invocation ended in `|| true`, and ELEVEN consecutive wedges — one
# of them a stalled-bus capture, which arrives about once per 500 reboots — were recorded as a
# two-line header with no forensic content at all. Silently.
#
# So: freeze the copy AND pin the repo.  HSM_REPO=/path/to/repo /tmp/frozen-soak.sh ...
REPO="${HSM_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
if [ ! -x "$REPO/tools/hsm-wedge-snapshot.sh" ]; then
    echo "REFUSING TO RUN: \$REPO=$REPO has no tools/hsm-wedge-snapshot.sh." >&2
    echo "  Every wedge would be recorded as an empty header. Set HSM_REPO to the repo root." >&2
    exit 2
fi
RECOVER="${HSM_RECOVER_CMD:-$REPO/tools/hsm-swd-powman-recover.sh}"
# CHECKED HERE, FOR THE SAME REASON THE SNAPSHOT HELPER IS. The ladder runs under `perl -e alarm`
# with its status unexamined, so a missing or non-executable RECOVER produces no recovery and no
# error: the card stays down, the run records "this one needs a human", and the verdict describes
# the device instead of the harness. A soak is hours long and unattended; the refusal belongs at
# the start.
if [ ! -x "$RECOVER" ]; then
    echo "REFUSING TO RUN: the recovery command '$RECOVER' is missing or not executable." >&2
    echo "  Every wedge would be recorded as 'needs a human' without the ladder ever running." >&2
    echo "  Set HSM_RECOVER_CMD, or HSM_REPO to the repository root." >&2
    exit 2
fi
N="${1:-10}"
WAIT="${2:-90}"

# A SLEEPING HOST SILENTLY CORRUPTS THIS MEASUREMENT. System sleep suspends USB, so the card
# "does not come back", the recovery ladder "fails", and the run records a device verdict that is
# really a laptop lid. MEASURED 2026-08-07: a clamshell sleep at 15:06 landed mid-soak and produced
# a "this one needs a human" for a card that was fine — the run had to be thrown away, and the
# overlap was only found by correlating pmset -g log against file timestamps afterwards.
#
# Hold the machine awake for the duration rather than asking anyone to watch a lid.
if [ -z "${HSM_CAFFEINATED:-}" ] && [ -z "${HSM_NO_CAFFEINATE:-}" ] && command -v caffeinate >/dev/null 2>&1; then
    export HSM_CAFFEINATED=1
    exec caffeinate -dimsu "$0" "$@"
fi

OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"

# Bring a server up ONLY to run the cheap-rung probe, then it gets detached again. Deliberately
# separate from the ladder's own start_ocd: this one must never be left running, because an
# attached debugger is the single largest source of false wedges in this measurement.
start_ocd_for_probe(){
    pgrep -f "$(basename "$OCD_BIN")" >/dev/null 2>&1 && return 0
    [ -x "$OCD_BIN" ] || return 1
    "$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c "adapter speed 5000" \
        > "${OCD_LOG:-/tmp/openocd-soak.log}" 2>&1 &
    sleep 8
}

# ---- POWMAN_DBGMODE VERIFICATION, for the A/B experiment ------------------------------------
#
# HSM_DBGMODE_EXPECT=0|1 turns this on. It asserts the bit on EVERY iteration, not per wedge.
#
# WHY PER-WEDGE IS NOT ENOUGH, and this is the whole point: the result that matters from the
# DBGMODE arm is "240 reboots, no wedge". If some reset path clears the bit at iteration 54 and no
# wedge happens afterwards, there is no wedge snapshot to reveal it, and the run reports 240/240
# clean with DBGMODE while having actually measured the CONTROL condition for three quarters of it.
# The failure is invisible in exactly the outcome it would invalidate.
#
# THE ATTACH PROBLEM. This soak detaches OpenOCD on purpose: an attached debugger halts the core
# when it re-examines after a USB drop, and a halted core cannot enumerate — measured, 4 of 5
# apparent wedges in one run were that. Reading RP-AP CTRL needs SWD, so naive verification would
# corrupt the measurement it is meant to protect.
#
# The resolution is that the false-wedge mechanism is EXAMINATION. `configure -defer-examine` means
# OpenOCD brings up the DAP and stops — it never examines, never halts a core — while dpreg/apreg
# still answer. RP-AP CTRL is readable without touching the cores at all.
#
# NOT YET VALIDATED: that holding a deferred-examine server across a long soak does not perturb it.
# That must be demonstrated before the DBGMODE arm is trusted — run a control soak with the server
# held and confirm the wedge rate is unchanged. Until then this is instrumentation, not evidence.
DBGMODE_EXPECT="${HSM_DBGMODE_EXPECT:-}"
dbg_ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 25; exec @ARGV' -- nc localhost 4444 2>&1 | LC_ALL=C tr -d '\000'; }
dbg_start_server(){
    pgrep -f "$(basename "$OCD_BIN")" >/dev/null 2>&1 && return 0
    [ -x "$OCD_BIN" ] || return 1
    "$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
        -c "rp2350.cm0 configure -defer-examine; rp2350.cm1 configure -defer-examine" \
        -c "adapter speed 5000" > "${OCD_LOG:-/tmp/openocd-soak.log}" 2>&1 &
    sleep 9
}
dbg_read_ctrl(){ LC_ALL=C grep -aoE '^0x[0-9a-f]{8}' <<< "$(dbg_ocd "rp2350.dap apreg 0x80000 0x00")" | head -1; }
# Returns the observed bit, or empty when unreadable. Never aborts on its own — the caller decides.
dbg_observed(){
    local c; c="$(dbg_read_ctrl)"
    [ -n "$c" ] || { echo ""; return; }
    [ $(( c & 4 )) -ne 0 ] && echo 1 || echo 0
}
dbg_assert(){   # $1 = when (before/after), $2 = iteration
    [ -n "$DBGMODE_EXPECT" ] || return 0
    local ctrl obs
    ctrl="$(dbg_read_ctrl)"; obs="$(dbg_observed)"
    printf '      iteration=%s phase=%s rp_ap_ctrl=%s dbgmode_expected=%s dbgmode_observed=%s\n' \
        "$2" "$1" "${ctrl:-UNREADABLE}" "$DBGMODE_EXPECT" "${obs:-UNREADABLE}"
    if [ -z "$obs" ] || [ "$obs" != "$DBGMODE_EXPECT" ]; then
        echo
        echo "RESULT=INVALID_EXPERIMENT"
        echo "  POWMAN_DBGMODE was ${obs:-UNREADABLE} at iteration $2 ($1), expected $DBGMODE_EXPECT."
        echo "  Every reboot from the last verified one onward measured an unknown condition."
        echo "  Do not report this run. Re-assert the bit and restart the arm."
        exit 3
    fi
}

alive(){ perl -e 'alarm 15; exec @ARGV' -- sc-hsm-tool 2>&1 | grep -qi '^Version'; }
reboot_card(){ perl -e 'alarm 45; exec @ARGV' -- opensc-tool \
    -s "00:A4:04:00:08:A0:58:3F:C1:9B:7E:4F:21" -s "80:1F:00:00" >/dev/null 2>&1; }

# DETACH THE DEBUGGER FOR THE MEASUREMENT. OpenOCD halts the target when it re-examines it after
# the device drops off USB, and a halted core cannot enumerate — so an attached debugger
# manufactures the exact failure this soak counts. MEASURED 2026-08-07: a 40-reboot run produced 4
# such false wedges against 1 genuine one, i.e. 80% of apparent failures were the instrument.
#
# The soak needs no debug access of its own; the recovery ladder starts OpenOCD on demand when it
# is actually needed. So the honest configuration is: no debugger attached while measuring.
# HSM_KEEP_OPENOCD=1 opts out (e.g. when capturing RTT alongside).
# LEAVE THE TARGET RUNNING FIRST. Killing OpenOCD while the core is halted strands it halted, and
# a halted core cannot enumerate — so a "detach" that skips this creates the very wedge the detach
# exists to avoid. Measured: the first soak after adding the detach wedged on iteration 2.
detach_openocd(){
    [ -n "${HSM_KEEP_OPENOCD:-}" ] && return 0
    # When verifying DBGMODE the deferred-examine server must stay up; it never examines, so it is
    # not the thing that manufactures wedges. Killing it here would break the assertion instead.
    [ -n "${HSM_DBGMODE_EXPECT:-}" ] && return 0
    pgrep -f 'openocd' >/dev/null 2>&1 || return 0
    printf 'reset run\nexit\n' | perl -e 'alarm 20; exec @ARGV' -- nc localhost 4444 >/dev/null 2>&1
    sleep 3
    pkill -f 'openocd' 2>/dev/null
    sleep 2
}
if [ -z "${HSM_KEEP_OPENOCD:-}" ]; then
    echo "  detaching OpenOCD for the duration (it manufactures false wedges by halting the core)"
    detach_openocd
fi

ok=0; fail=0; total=0; recovered=0; cheap=0; needed_hands=0
alive || { echo "card is not answering before the soak started — nothing to measure"; exit 2; }

echo "rescue-applet reboot soak: $N iterations, ${WAIT}s window"
echo
[ -n "$DBGMODE_EXPECT" ] && { dbg_start_server || { echo "cannot start a debug server for DBGMODE verification" >&2; exit 2; }; }

for i in $(seq 1 "$N"); do
    t0=$(date +%s)
    # START THE AHB SAMPLER *BEFORE* THE REBOOT.
    #
    # HSM_AHB_WATCH=1 samples the bus across the reset so the moment it stops answering is
    # timestamped — the settled-state captures cannot say when the block formed, only that it did.
    #
    # ORDERING IS THE WHOLE BUG THAT MADE THE FIRST VERSION USELESS. Starting it after reboot_card
    # looked right and never produced a single sample: the watcher spends ~10 s bringing up its own
    # OpenOCD (2 s to clear the old one, 8 s to settle), while a healthy boot returns in ~6 s. The
    # wait loop therefore exited and killed the watcher before it sampled once, leaving an empty log
    # and no .jsonl — which reads exactly like "the bus was clean".
    #
    # Started here, OpenOCD is already up and reading when the reset lands.
    _watch_log=""; _watch_pid=""
    if [ -n "${HSM_AHB_WATCH:-}" ]; then
        _watch_log="${HSM_WEDGE_DUMP_DIR:-/tmp}/ahb-iter${i}.jsonl"
        HSM_SNAPSHOT_FORCE=1 "$REPO/tools/hsm-ahb-transition-watch.sh" \
            "${HSM_AHB_WATCH_SECS:-$((WAIT + 10))}" "$_watch_log" > "${_watch_log%.jsonl}.log" 2>&1 &
        _watch_pid=$!
        # Let it reach the sampling loop before the card is told to reboot.
        sleep "${HSM_AHB_WATCH_LEAD:-12}"
    fi

    dbg_assert before "$i"
    # RESET THE CLOCK AFTER THE LEAD-IN. t0 was taken at the top of the iteration, so the watcher's
    # 12 s start-up was being counted as boot time — the first wired run reported "BACK in 19s" for
    # a boot that has taken 6 s all week. That number feeds the USB re-enumeration finding, which
    # rests entirely on boot time moving between arms, so letting the instrument inflate it would
    # corrupt the one result this bench has actually explained.
    [ -n "${_watch_pid:-}" ] && t0=$(date +%s)
    # MARK THE RESET IN THE SAMPLE STREAM.
    #
    # The watcher's own t0 is when IT started sampling, which is ~10 s after launch (its OpenOCD
    # setup) and therefore ~2 s BEFORE the reboot, given the 12 s lead. Offsets quoted against that
    # t0 are not reset-relative, and I reported transients as "t+1.5 s into boot" when 1.5 s into
    # the sampling window is roughly 0.5 s BEFORE the reset was even requested.
    #
    # Writing the reset timestamp beside the samples makes every offset recomputable against the
    # event that matters, instead of against when a helper happened to finish starting up.
    [ -n "${_watch_pid:-}" ] && python3 -c 'import time,sys;open(sys.argv[1],"w").write(f"{time.time():.4f}\n")' \
        "${_watch_log%.jsonl}.reset" 2>/dev/null
    reboot_card

    # OPTIONAL: SAMPLE THE AHB ACROSS THE BOOT WINDOW.
    #
    # HSM_AHB_WATCH=1 starts hsm-ahb-transition-watch.sh immediately after the reboot APDU, so the
    # bus is being read WHILE the card boots. Every stalled-bus capture so far has photographed the
    # settled state; this is the only way to timestamp the moment the bus stops answering, which is
    # what separates "the flash scan holds the bus" from "DMA or the other core does".
    #
    # THE WATCHER MUST OWN THE PROBE ALONE. Two OpenOCDs on one SWD link return plausible-looking
    # garbage rather than errors (measured — a contended run reported a false MEMAP_STALL on a
    # healthy card). So it is killed before the wait loop ends, well before the snapshot or the
    # recovery ladder can start, and its OpenOCD is reaped with it.
    w=0; back=0
    while [ "$w" -lt "$WAIT" ]; do
        sleep 3; w=$((w+3))
        if alive; then back=1; break; fi
    done
    # RELEASE THE PROBE BEFORE ANYTHING ELSE WANTS IT.
    if [ -n "${_watch_pid:-}" ]; then
        kill "$_watch_pid" 2>/dev/null; wait "$_watch_pid" 2>/dev/null
        pkill -f 'xpack-openocd.*rp2350' 2>/dev/null
        sleep 2
        _watch_pid=""
        if [ -s "$_watch_log" ]; then
            _blk="$(LC_ALL=C grep -c '"ok":0' "$_watch_log" 2>/dev/null)"
            _tot="$(wc -l < "$_watch_log" | tr -d ' ')"
            [ "${_blk:-0}" != "0" ] && printf '      AHB samples: %s/%s failed during boot\n' "$_blk" "$_tot"
        fi
    fi

    t=$(( $(date +%s) - t0 ))
    dbg_assert after "$i"
    if [ "$back" = 1 ]; then
        ok=$((ok+1)); total=$((total+t)); printf '  %2d/%d  BACK in %2ds\n' "$i" "$N" "$t"
        continue
    fi

    fail=$((fail+1)); printf '  %2d/%d  DID NOT COME BACK within %ds\n' "$i" "$N" "$WAIT"

    # PHOTOGRAPH THE WEDGE BEFORE ANYTHING TOUCHES IT — including the cheap-rung probe below.
    #
    # The severity probe attaches an ORDINARY (examining) OpenOCD and issues `reset run`. On a
    # stalled bus that examination provokes OpenOCD's abort, which writes
    # DAPABORT|STKCMPCLR|STKERRCLR|WDERRCLR|ORUNERRCLR and clears every sticky bit worth reading —
    # and a `reset run` that succeeds has already destroyed the volatile state as well.
    #
    # So a MILD wedge previously produced NO forensic record at all: it never reached the recovery
    # command, and the probe that classified it also erased it. Measured in the first A/B control
    # run — two wedges in 32 reboots, both MILD, both unphotographed.
    #
    # The snapshot is read-only and uses deferred examination, so it can run first without
    # perturbing the classification that follows. HSM_WEDGE_SNAPSHOT=1 enables it.
    if [ -n "${HSM_WEDGE_SNAPSHOT:-}" ]; then
        _wd="${HSM_WEDGE_DUMP_DIR:-$HOME/.local/share/akash-hsm-staging/wedges}"
        mkdir -p "$_wd" 2>/dev/null
        _snap="$_wd/wedge-$(date +%Y%m%d-%H%M%S)-iter$i.snapshot.txt"
        { echo "# iteration $i of $N"; echo "# dbgmode_expected ${DBGMODE_EXPECT:-unset}"; } > "$_snap"
        HSM_SNAPSHOT_FORCE=1 perl -e 'alarm 180; exec @ARGV' -- "$REPO/tools/hsm-wedge-snapshot.sh" >> "$_snap" 2>&1 || true
        printf '      snapshot: %s -> %s\n' \
            "$(grep -aoE '^VERDICT=[A-Z_]+' "$_snap" | head -1 || echo VERDICT=UNCAPTURED)" "$_snap"
        # The snapshot leaves a deferred-examine server up; the probe below wants a normal one.
        [ -z "${DBGMODE_EXPECT:-}" ] && { pkill -f "$(basename "$OCD_BIN")" 2>/dev/null; sleep 2; }
    fi
    # CLASSIFY THE SEVERITY, don't just recover. "Did not return in 90s" spans everything from a
    # stuck card session that one reset clears to a chip that needs its power removed, and lumping
    # them together makes the device look far worse than it is — or far better, depending which way
    # the tooling happens to lean. The wedge hunt reported 0 failures in 40 reboots while this soak
    # reported 4 in 60 on the same firmware, purely because the hunt issued a reset run before
    # counting and this did not.
    #
    # Escalate cheapest-first and record which rung actually sufficed.
    sev="unrecovered"
    # THE CHEAP RUNG NEEDS A SERVER TO GO THROUGH, AND THIS RUN DELIBERATELY KILLED IT.
    # OpenOCD is detached for the duration (it manufactures wedges by halting the core), so this
    # `reset run` was being piped to `nc localhost 4444` with NOTHING LISTENING. The command never
    # reached the chip, the probe could not succeed, and MILD was therefore unreachable BY
    # CONSTRUCTION — every wedge scored HARD regardless of what would actually have cleared it.
    #
    # MEASURED 2026-08-08: a 27-iteration run reported "MILD 0 / HARD 2" and I nearly wrote that up
    # as "the residual wedges are hard ones needing a power cut". That conclusion was manufactured
    # by the harness. The wedge hunt, which DOES hold a server open, saw the opposite on the same
    # firmware — 0 hard wedges in 100 reboots once a `reset run` was permitted.
    #
    # So start a server just for the probe. It costs ~10s and only on a wedge, and it is the whole
    # point of the classification: telling "one reset clears it" from "this needs its power removed"
    # is the difference between a device that is fine and one that needs a switchable port.
    start_ocd_for_probe
    printf 'reset run\nexit\n' | perl -e 'alarm 20; exec @ARGV' -- nc localhost 4444 >/dev/null 2>&1
    w=0; while [ "$w" -lt 30 ]; do sleep 3; w=$((w+3)); alive && break; done
    if alive; then
        sev="reset-run"; cheap=$((cheap+1))
        printf '      severity: MILD — a plain reset run cleared it (%ss)\n' "$w"
        # We started that server; leave the bench as the run expects to find it.
        detach_openocd
    fi
    # Recover through the REAL ladder rather than a private copy of it, so this run also measures
    # whether unattended recovery actually works. Counted as a reboot FAILURE either way — the
    # reboot returned the card by itself or it did not, and recovery does not change that verdict.
    # Give the ladder MORE than its own worst case, or this kills a recovery in progress and
    # records "needs a human" for a card that was coming back. Measured 2026-08-07: alarm 600 cut
    # the ladder off mid-run and the card was answering immediately afterwards — a false verdict
    # produced by the harness, not the device. Ladder worst case is roughly
    # MAX_PASSES x (SETTLE + SETTLE) + FINAL_WAIT ~= 980s.
    if [ "$sev" != "reset-run" ]; then
    # KEEP THE RECOVERY OUTPUT. It was going to /dev/null, so the log recorded that the ladder ran
    # and the card came back, but not WHICH RUNG did it. That erases the one fact a deployment
    # decision turns on: three of the four rungs work over SWD alone, but cut_vbus needs a
    # per-port-switchable USB hub. "0 human interventions" means something very different if it
    # depended on hardware a deployed HSM will not have.
    _rlog="${HSM_RECOVER_LOG_DIR:-${HSM_WEDGE_DUMP_DIR:-/tmp}}/recover-iter${i}.log"
    perl -e "alarm ${HSM_RECOVER_TIMEOUT:-1200}; exec @ARGV" -- "$RECOVER" > "$_rlog" 2>&1
    _rungs="$(grep -aoE 'rescue reset|cutting VBUS|warm reset|POWMAN power cycle' "$_rlog" 2>/dev/null \
              | sort -u | tr '\n' ',' | sed 's/,$//')"
    printf '      rungs used: %s\n' "${_rungs:-none recorded}"
    if grep -qa 'cutting VBUS' "$_rlog" 2>/dev/null; then
        printf '      NOTE: needed a VBUS cut — this recovery required the switchable hub\n'
    fi
    # GRACE PERIOD. The ladder issues its final `reset run` from an EXIT trap, i.e. as it exits, so
    # the card can come up moments AFTER it returns. Checking immediately records "needs a human"
    # for a card already on its way back — measured twice. Poll before judging.
    g=0
    while [ "$g" -lt "${HSM_RECOVER_GRACE:-60}" ]; do
        alive && break
        sleep 5; g=$((g+5))
    done
    if alive; then
        recovered=$((recovered+1)); sev="ladder"
        printf '      severity: HARD — needed the full ladder\n' 
        # RE-DETACH. The ladder starts OpenOCD to do its work and leaves it running, so without
        # this the debugger is attached for every iteration after the first wedge — and it
        # manufactures this exact symptom. MEASURED 2026-08-07: a 60-reboot run wedged at 5, then
        # at 23, 26, 47 and 60, all of the later ones with the debugger back on. The first was
        # clean; the rest are not trustworthy.
        detach_openocd
    else
        needed_hands=$((needed_hands+1))
        printf '      \033[31mNOT recovered — this one needs a human\033[0m\n'
        echo "  stopping: the bench cannot continue without a physical replug"
        break
    fi
    fi
done

echo
echo "================ RESULT ================"
printf '  reboot returned the card by itself : %d/%d\n' "$ok" "$((ok+fail))"
[ "$ok" -gt 0 ] && printf '  mean time back                     : %ds\n' "$((total/ok))"
printf '  MILD  (a plain reset run sufficed) : %d\n' "$cheap"
printf '  HARD  (needed the full ladder)     : %d\n' "$recovered"
printf '  wedges that needed a human         : %d\n' "$needed_hands"
[ "$needed_hands" -eq 0 ] && echo "  -> no human intervention was required in this run"
