#!/usr/bin/env bash
# hsm-wedge-snapshot.sh — READ-ONLY forensic snapshot of a wedged RP2350, taken before anything
# changes its state. Requires SWD. Changes nothing on the target.
#
#   tools/hsm-wedge-snapshot.sh [outfile]
#
# WHY THIS EXISTS, AND WHY IT STARTS ITS OWN SERVER.
#
# OpenOCD's ordinary connection path EXAMINES the cores, and on a stalled MEM-AP that examination
# fails and OpenOCD responds with:
#
#     Connecting DP: stalled AP operation, issuing ABORT
#
# That is not just a DAPABORT. OpenOCD's SWD layer writes
# DAPABORT|STKCMPCLR|STKERRCLR|WDERRCLR|ORUNERRCLR in one go — it clears sticky compare, sticky
# error, write-data error and sticky overrun at the same time. So by the time a normally-attached
# server gives you a prompt, THE STICKY BITS YOU WANTED ARE ALREADY GONE. Reading CTRL/STAT after
# seeing that warning reports the state OpenOCD left behind, not the state the chip wedged in.
#
# The fix is to never let it examine: `configure -defer-examine` on both cores. OpenOCD then brings
# up the DAP and stops, and DP and AP registers remain readable. VERIFIED on this bench — with
# deferral there is no examination and no abort in the log, and `dpreg`/`apreg` both answer.
#
# WHAT IT READS, and why each matters on a stalled-bus wedge:
#   * DP CTRL/STAT     — the pristine sticky bits, plus the power-up request/acknowledge pairs.
#                        CDBGPWRUPREQ set with CDBGPWRUPACK clear is the signature of a debug
#                        power-up that never completed.
#   * RP-AP 0x08..0x14 — the live power-sequencer state of SWCORE / XIP / SRAM0 / SRAM1. The RP-AP
#                        is reachable when the core MEM-APs are not; that is the whole reason the
#                        rescue path works, and it is the only diagnostic surface that survives.
#
# It deliberately does NOT halt, reset, rescue, or write anything. Deciding what to do is the
# operator's job and the answer depends on what this prints.
set -uo pipefail

OCD_PORT="${OCD_PORT:-4444}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
# NAME THE PROBE. Without it the server binds whichever probe OpenOCD finds first, so a snapshot
# can describe the OTHER board while reading as a valid wedge capture — and the startup sweep-up
# below would end that board's session too. HSM_SNAPSHOT_PROBE (or --probe) is the serial; with
# none, this stays on the legacy single-probe behaviour and says so.
PROBE="${HSM_SNAPSHOT_PROBE:-}"
# MODE. Observation and intervention are separated deliberately.
#
#   --classify  (default)  read everything, THEN arp_examine last, then print a VERDICT.
#                          Right for soak statistics, where the question is "what kind of wedge".
#   --preserve             read everything and STOP. No examination, no VERDICT.
#                          Right for a deliberately frozen wedge that is about to be experimented
#                          on, because arp_examine is the first thing that intentionally sends a
#                          transaction into the questionable MEM-AP path and can trigger OpenOCD's
#                          ABORT machinery. Once the recovery experiment begins, the pre-experiment
#                          state must not already have been perturbed by the classifier.
MODE=classify
# A loop, not a single `case`, so --probe and --preserve can be given in either order; the
# remaining positional argument is still the optional output file.
while [ $# -gt 0 ]; do
  case "$1" in
    --preserve) MODE=preserve; shift ;;
    --classify) MODE=classify; shift ;;
    --probe)    PROBE="${2:-}"; shift 2 ;;
    *) break ;;
  esac
done
OUT="${1:-}"
# DO NOT RUN WHILE A SOAK OWNS THE BENCH.
#
# A soak's recovery ladder drives its own OpenOCD. Starting a second one against the same probe puts
# two masters on one SWD link, and the result is not a failed read — it is a PLAUSIBLE-LOOKING one.
# MEASURED 2026-08-11: a validation run launched while soak 9 was mid-recovery reported
# VERDICT=MEMAP_STALL_WITH_DOMAINS_HEALTHY on a card that was fine, with DHCSR, PC and xPSR all
# reading 0x4c013477 — the same recurring artifact word seen in the "shifted" captures.
#
# That is worth pausing on: some of the shifted captures in this file may have been contention with
# the soak's own recovery rather than a device fault. The canary catches the state but cannot say
# what caused it.
#
# HSM_SNAPSHOT_FORCE=1 overrides, for the soak itself, which is the legitimate caller.
if [ -z "${HSM_SNAPSHOT_FORCE:-}" ] && pgrep -f 'hsm-reboot-soak|soak-frozen' >/dev/null 2>&1; then
    echo "REFUSING TO RUN: a soak is active and owns the debug probe." >&2
    echo "  Two OpenOCD instances on one SWD link produce plausible-looking garbage, not errors." >&2
    echo "  Wait for the soak, or set HSM_SNAPSHOT_FORCE=1 if you are the soak." >&2
    exit 2
fi

RP_AP="${RP_AP:-0x80000}"

say(){ printf '  %s\n' "$*"; }
ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 40; exec @ARGV' -- nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000'; }

# A server that has already examined has already aborted. Always start fresh with deferral.
if [ -n "$PROBE" ]; then
    pkill -f "$(basename "$OCD_BIN").*${PROBE}" 2>/dev/null
else
    say "no --probe given: sweeping up every OpenOCD and binding whichever probe answers first"
    say "  (single-probe hosts only — on the two-probe bench this can snapshot the wrong board)"
    pkill -f "$(basename "$OCD_BIN")" 2>/dev/null
fi
sleep 2
OCD_ADAPTER=()
[ -n "$PROBE" ] && OCD_ADAPTER=(-c "adapter serial $PROBE")
"$OCD_BIN" -f interface/cmsis-dap.cfg ${OCD_ADAPTER[@]+"${OCD_ADAPTER[@]}"} -f target/rp2350.cfg \
    -c "rp2350.cm0 configure -defer-examine; rp2350.cm1 configure -defer-examine" \
    -c "adapter speed ${ADAPTER_SPEED:-5000}" > /tmp/ocd-snapshot.log 2>&1 &
OCD_PID=$!
# STOP THE SERVER WE STARTED. It was left running on every exit path, holding the SWD link — and
# this script refuses to run while another master is on that link, so one snapshot poisoned the
# next one and any recovery ladder that came after it. Killed by PID, never `pkill -f openocd`:
# there is a second probe on this bench and its session is not ours to end.
cleanup(){ [ -n "${OCD_PID:-}" ] && kill "$OCD_PID" 2>/dev/null; return 0; }
trap cleanup EXIT INT TERM
sleep 9

if LC_ALL=C grep -qai 'issuing ABORT' /tmp/ocd-snapshot.log; then
    say "WARNING: this server aborted despite deferral — the sticky bits below are NOT pristine"
fi

w(){ LC_ALL=C grep -aoE '^0x[0-9a-f]{8}' <<< "$1" | sed -n "$2p"; }

# Default so the verdict logic can call sb() even when SWCORE never answered.
sb(){ echo no; }

dp="$(ocd "rp2350.dap dpreg 0x4")"
ap="$(ocd "rp2350.dap apreg $RP_AP 0x00
rp2350.dap apreg $RP_AP 0x08
rp2350.dap apreg $RP_AP 0x0c
rp2350.dap apreg $RP_AP 0x10
rp2350.dap apreg $RP_AP 0x14
rp2350.dap apreg $RP_AP 0x18")"

CTRLSTAT="$(w "$dp" 1)"
RPCTRL="$(w "$ap" 1)"; SWCORE="$(w "$ap" 2)"; XIP="$(w "$ap" 3)"; SRAM0="$(w "$ap" 4)"; SRAM1="$(w "$ap" 5)"; OVRD="$(w "$ap" 6)"

{
echo "=== hsm-wedge-snapshot $(date '+%Y-%m-%d %H:%M:%S') ==="
echo
echo "DP CTRL/STAT : ${CTRLSTAT:-UNREADABLE}"
if [ -n "$CTRLSTAT" ]; then
    v=$(( CTRLSTAT ))
    # ADIv5/v6 CTRL/STAT. The power-up pairs are the diagnostic ones here: a REQ set with its ACK
    # clear means a power-up handshake that never completed, which is what a stalled switched-core
    # domain looks like from the DP side.
    bit(){ [ $(( (v >> $1) & 1 )) = 1 ] && echo yes || echo no; }
    printf '  CSYSPWRUPACK(31)=%s CSYSPWRUPREQ(30)=%s CDBGPWRUPACK(29)=%s CDBGPWRUPREQ(28)=%s\n' \
        "$(bit 31)" "$(bit 30)" "$(bit 29)" "$(bit 28)"
    printf '  WDATAERR(7)=%s READOK(6)=%s STICKYERR(5)=%s STICKYCMP(4)=%s STICKYORUN(1)=%s\n' \
        "$(bit 7)" "$(bit 6)" "$(bit 5)" "$(bit 4)" "$(bit 1)"
    [ "$(bit 28)" = yes ] && [ "$(bit 29)" = no ] && \
        echo "  ==> CDBGPWRUPREQ set but NOT acknowledged: a debug power-up that never completed."
fi
echo
printf 'RP-AP CTRL   : %s   (POWMAN_DBGMODE bit2 = %s)\n' "${RPCTRL:-UNREADABLE}" \
    "$([ -n "$RPCTRL" ] && { [ $(( RPCTRL & 4 )) -ne 0 ] && echo on || echo off; } || echo '?')"
echo
echo "RP-AP power sequencers   (healthy: SWCORE 0x0000095e, others 0x0000015e)"
printf '  SWCORE 0x08 : %s\n' "${SWCORE:-UNREADABLE}"
printf '  XIP    0x0c : %s\n' "${XIP:-UNREADABLE}"
printf '  SRAM0  0x10 : %s\n' "${SRAM0:-UNREADABLE}"
printf '  SRAM1  0x14 : %s\n' "${SRAM1:-UNREADABLE}"
printf '  OVRD   0x18 : %s\n' "${OVRD:-UNREADABLE}"

if [ -n "$SWCORE" ]; then
    s=$(( SWCORE ))
    sb(){ [ $(( (s >> $1) & 1 )) = 1 ] && echo yes || echo no; }
    echo
    echo "  SWCORE decode:"
    printf '    USING_FAST_POWCK(11)=%s  WAITING_POWCK(10)=%s  WAITING_TIMCK(9)=%s  IS_PU(8)=%s\n' \
        "$(sb 11)" "$(sb 10)" "$(sb 9)" "$(sb 8)"
    [ "$(sb 10)" = yes ] && echo "    ==> waiting for its power-manager clock — a clock transition has stalled."
    [ "$(sb 9)"  = yes ] && echo "    ==> waiting for the AON-timer clock transition. Per the datasheet, if this is stuck"
    [ "$(sb 9)"  = yes ] && echo "        during power-down the only recourse is a reset — non-reset recovery will not help."
fi

# IS THE MEM-AP ACTUALLY DEAD? — the one deliberate state-changing step, and it comes LAST.
#
# Deferring examination is what preserves the sticky bits, but it also means we never learn whether
# the core MEM-AP works. Without that, a healthy card and a wedged one look identical here, and a
# tool that cries wolf on a healthy card will be disbelieved on the one wedge that matters. Reading
# the MEM-AP CSW does not settle it either — on a healthy card, under a deferred-examine server, CSW
# and IDR both read 0x00000000 (measured), so zero carries no information.
#
# `arp_examine` does settle it: on a healthy card it detects the Cortex-M33 and the target goes to
# `running`; on a stalled bus it fails exactly as the normal connection path does. It is run only
# after every pristine value above has been captured, so the abort it may provoke costs nothing.
if [ "$MODE" = preserve ]; then
    echo
    echo "MODE=preserve — stopping here. arp_examine NOT attempted, so nothing has been sent into"
    echo "  the questionable MEM-AP path and OpenOCD's ABORT machinery has not been triggered."
    echo "  The state above is exactly as the wedge left it. Run the recovery experiment now;"
    echo "  re-read SRAM0/SRAM1 before and after every intervention and abandon the attempt if"
    echo "  either leaves 0x0000015e, because the forensic evidence is gone at that point."
    exit 0
fi

# READ THE MEM-AP's OWN REGISTERS BEFORE ASKING OPENOCD TO EXAMINE IT.
#
# `arp_examine` gives one bit — worked or did not — and the failure it reports covers several very
# different states. The 2026-08-10 iteration-26 capture showed every power domain healthy AND no
# sticky error of any kind (STICKYERR/WDATAERR/STICKYORUN all clear) while examine still failed. So
# the AP is not returning a FAULT; something else is wrong, and that distinction is invisible from
# examine alone.
#
# IDR is the discriminator, and it is read-only so this costs nothing:
#   IDR reads a plausible AHB-AP id  -> the AP is present and answering; the stall is downstream,
#                                       in the bus fabric or an outstanding transaction
#   IDR reads 0x00000000             -> the AP is not present/enabled at all — a different fault,
#                                       and one the "outstanding AHB transaction" story does not fit
#   IDR read errors                  -> the DP-to-AP path itself is broken
#
# CSW is read second: TrInProg (bit 7) set is direct evidence of a transfer that never completed,
# which is exactly the outstanding-transaction hypothesis this snapshot has been unable to test.
# RP2350 IS ADIv6: APs ARE ADDRESSED, AND THE AP REGISTERS MOVED.
#
# Two separate mistakes were needed to get this wrong, and both were made:
#
#   1. AP NUMBER. rp2350.cfg creates the cores with `-ap-num 0x2000` (cm0) / `0x4000` (cm1) and the
#      DAP with `-adiv6`. AP 0 is not a MEM-AP at all — `dap info` shows it as a ROM table whose
#      first entry reads 0x00002003. That entry is exactly the value an earlier version of this
#      probe reported as "CSW".
#
#   2. REGISTER OFFSETS. ADIv6 relocated the AP registers: CSW 0x00 -> 0xd00, IDR 0xfc -> 0xdfc,
#      BASE 0xf8 -> 0xdf8. Reading the ADIv5 offsets returns 0x00000000 even on a perfectly healthy
#      card, which is why `dap info` succeeded while direct reads looked like a dead AP.
#
# The combination produced IDR 0x00000000 / CSW 0x00002003 IDENTICALLY on two hard-wedged and three
# healthy cards, and very nearly became two reported findings ("the AP is not present" and
# "TrInProg is clear, so there is no outstanding transaction"). Neither was real.
#
# VALIDATED against a healthy card, which is the only thing that makes the numbers below meaningful:
#     IDR 0x34770008   CSW 0x02800052   -> DeviceEn(6)=1, TrInProg(7)=0
#
# So on a healthy card the AP is enabled and idle. A wedge capture is interpretable only against
# that baseline: TrInProg=1 means a transfer really is outstanding, DeviceEn=0 means memory access
# is disabled. If a wedge ever reads the healthy values exactly, distrust the probe again.
#
# From target/rp2350.cfg — the cores are created with `-ap-num 0x2000` (cm0) and `0x4000` (cm1),
# and the DAP with `-adiv6`. AP "0" is not an AP address on this part.
#
# A first version of this probe used 0 and read IDR 0x00000000 / CSW 0x00002003 / BASE 0x00000000 —
# IDENTICALLY on hard-wedged and perfectly healthy cards across four captures. Constant values that
# do not move with the thing being measured are not a measurement, and they nearly became a reported
# finding ("the AP is not present", "TrInProg is clear, so no outstanding transaction"). Both were
# artifacts of reading a nonexistent AP.
#
# THE CHECK THAT MATTERS: these registers must read DIFFERENTLY on a healthy card than on a wedged
# one. If a future capture shows the wedged and healthy values agreeing again, distrust the probe
# before drawing any conclusion from it.
AHB_AP="${HSM_AHB_AP:-0x2000}"
# READ EACH REGISTER IN ITS OWN CALL AND LABEL IT.
#
# A first version issued both reads in one telnet command and took the two hex values positionally.
# That produced IDR 0x00000000 next to a readable CSW 0x00002003, which is self-inconsistent enough
# that the mapping could not be trusted — an AP that is absent does not return a plausible CSW. One
# read per call removes the ambiguity entirely, at the cost of one extra round trip on a card that
# is already wedged and going nowhere.
memap_idr="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg $AHB_AP 0xdfc")" | sed -n 1p)"
memap_csw="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg $AHB_AP 0xd00")" | sed -n 1p)"
memap_base="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg $AHB_AP 0xdf8")" | sed -n 1p)"

# THREE DISCRIMINATORS, because one capture every ~500 reboots has to earn its keep.
#
# The 2026-08-10 iter-448 capture showed cm0's AP returning CSW == BASE == 0x4c013477 with IDR
# unreadable — incoherent, so the AP was not describing itself. It was tempting to call that "the
# DP-to-AP path is broken", but the SAME snapshot had already read the RP-AP power sequencers at
# 0x80000 successfully, in the same session, moments earlier. Some AP traffic works. So the fault is
# narrower than the whole path, and these three reads say how much narrower:
#
#   1. IDR read TWICE. Identical garbage twice => a stale latched value. Different garbage each time
#      => the link is shifting/desyncing per transfer. Those are different faults.
#   2. cm1's AHB-AP (0x4000). If cm1 answers while cm0 does not, the failure is core-scoped, not
#      DAP-wide — and core 0 is the one that owns low_flash_task().
#   3. RP-AP IDR (0x80000) read HERE, adjacent to the others, so its success or failure is recorded
#      at the same instant rather than inferred from the power-sequencer block above.
memap_idr2="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg $AHB_AP 0xdfc")" | sed -n 1p)"
cm1_idr="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg 0x4000 0xdfc")" | sed -n 1p)"
rpap_idr="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg $RP_AP 0xdfc")" | sed -n 1p)"

# DOES A MEMORY READ *THROUGH* THE AP WORK?
#
# This is the discriminator the earlier reads cannot supply. Three stalled-bus captures
# (2026-08-11, iters 67/498/817) read the AP as completely healthy — IDR 0x34770008, CSW
# 0x02800052, BASE 0xe00ff003, stable on re-read, cm1 and RP-AP fine — while arp_examine still
# failed. So the DP-to-AP path is NOT the fault in those cases, and my read of the single iter-448
# capture ("the DP-to-AP path is broken") does not generalise.
#
# arp_examine does more than read AP registers: it reads memory THROUGH the AP. So the remaining
# suspect is the AHB bus behind a healthy AP. DHCSR (0xe000edf0) is the cheapest probe of that — a
# core debug register that any working AHB path returns, and one that does not perturb state.
#
#   DHCSR reads plausibly  -> AHB works; the examine failure is higher up (core/ROM enumeration)
#   DHCSR errors or hangs  -> the AHB path behind the AP is hung, which is the case the phrase
#                             "outstanding AHB transaction" was always reaching for
# REVERTED TO THE FORM THAT VALIDATES. Two commands, no echo stripping, take the 2nd hex token.
#
# I "improved" this into a three-command posted-read version with the echoes filtered, and it then
# returned 0x00000000 on a healthy card three times running — while the code treated non-empty as
# success and printed "AHB reads WORK". A probe that reads zero and calls it working is worse than
# no probe. The two-command form below is the one that produced 0x00130003 / 0x03130003 on healthy
# cards, which is what the iter-971/1230/1274 captures were taken with.
dhcsr="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg $AHB_AP 0xd04 0xe000edf0
rp2350.dap apreg $AHB_AP 0xd0c")" | sed -n 2p)"

# PLAUSIBILITY GATE. DHCSR always has S_REGRDY or the debug-enable bits set on a live core; an
# all-zero read is a failed read wearing the costume of a successful one. Treat it as unreadable so
# the AHB branch below cannot be satisfied by a zero.
# 0x00000000 AND 0x4c013477 ARE BOTH FAILED READS WEARING A VALUE'"'"'S COSTUME.
#
# Zero is the obvious one. 0x4c013477 is this bench'"'"'s recurring artifact word — it has shown up as
# CSW, as BASE, as SWCORE, and now as DHCSR, on captures where the read path was not working. It is
# never a real DHCSR (which always carries debug-enable or status bits). Letting it through as a
# successful read suppressed the cm1 fallback entirely: the fallback only runs when DHCSR is empty.
case "$dhcsr" in
    0x00000000|0x4c013477) dhcsr="" ;;
esac

# IF cm0's PATH IS BLOCKED, TRY cm1's.
#
# Every AHB-hung capture (iters 971, 1230, 245) reads cm1's AHB-AP as perfectly healthy — IDR
# 0x34770008, same as cm0's. Both APs front the same bus, so if the blockage is specific to cm0's
# AP-to-AHB path rather than the fabric itself, cm1's AP should still reach memory.
#
# This is the only route currently available that does not traverse the blocked path. The RP-AP does
# reset and power control, not memory; the rescue DP resets everything and destroys the state under
# investigation. So cm1 is the one probe that can distinguish:
#
#   cm1 reads DHCSR while cm0 cannot  -> the fault is in cm0's AP path, and the bus is fine. The
#                                        core can then be read THROUGH cm1, which is what the PC
#                                        probe needs and cannot get from cm0.
#   cm1 also fails                    -> the fabric or a bus master is genuinely stalled, and no
#                                        AP-based route will reach it.
#
# Either answer is progress; the current instrument gives neither.
dhcsr_cm1=""
if [ -z "$dhcsr" ]; then
    dhcsr_cm1="$(LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' <<< "$(ocd "rp2350.dap apreg 0x4000 0xd04 0xe000edf0
rp2350.dap apreg 0x4000 0xd0c")" | sed -n 2p)"
    # SAME GATE AS cm0. I applied the artifact filter to cm0's DHCSR and forgot cm1's, so the very
    # first capture to use this route printed "BUT cm1's AP READS IT: DHCSR = 0x4c013477" — the
    # bench's artifact word, i.e. a FAILED read reported as a successful one. That would have
    # produced exactly the wrong conclusion: "the bus is fine, the fault is cm0's AP path".
    case "$dhcsr_cm1" in
        0x00000000|0x4c013477) dhcsr_cm1="" ;;
    esac
fi

# WHICH PART OF THE BUS IS HUNG?
#
# "The AHB path is hung" is where iters 971 and 1230 left it, and that is a location, not an
# explanation. A hang caused by an outstanding XIP/QSPI transaction and one caused by a stuck core
# look identical from a single DHCSR read — but they differ in WHICH regions still answer.
#
# So read one word from each major region through the AP's TAR/DRW (no examined target needed):
#
#   ROM   0x00000000  bootrom — always mapped, never behind XIP
#   XIP   0x10000000  flash through the QSPI/XIP interface — the card was doing flash work
#   SRAM  0x20000000  main SRAM — behind the same AHB fabric, not behind XIP
#   PPB   0xe000edf0  core debug (DHCSR) — private peripheral bus
#
# XIP dead while SRAM and ROM answer  => the QSPI/XIP interface is stuck, not the whole fabric.
#                                        That points straight at flash activity, which is what
#                                        low_flash_task() is doing when these wedges occur.
# Everything dead                     => the fabric or the core's bus master is stalled globally.
# XIP fine but PPB dead               => the core, not the bus.
# DRW READS ARE POSTED — READ IT TWICE AND TAKE THE SECOND.
#
# On ADIv5/v6 the first DRW read after writing TAR returns the PREVIOUS transaction's data; the
# requested word arrives on the following read. A single-read version of this sweep returned
# ROM=0xf0000000 (the DP CTRL/STAT value read earlier in the snapshot) and XIP==SRAM==0x20082000 —
# each region reporting its predecessor's value, on a perfectly healthy card.
#
# THIS ALSO CASTS DOUBT ON THE "READ PIPELINE DESYNC" SUB-CLASS. Some of the lag-by-one seen in
# iters 448 and 1274 may be this same posted-read behaviour rather than a device fault. The canary
# still stands on its own (RP-AP IDR is a plain apreg read, not a TAR/DRW pair, and it read a value
# that is not its constant), but any lag observed through TAR/DRW must now be discounted.
probe_region(){   # $1 = address
    # STRIP THE COMMAND ECHO FIRST. The telnet transcript echoes
    # "rp2350.dap apreg 0x2000 0xd04 0x10000000", whose ADDRESS ARGUMENT is itself an 8-hex-digit
    # token. Matching hex across the whole transcript therefore returns the address you asked for
    # and calls it the value you read — which looks like a plausible answer and is not one. This is
    # the third time this exact trap has bitten in this file (read_memory, the first sweep, here).
    ocd "rp2350.dap apreg $AHB_AP 0xd04 $1
rp2350.dap apreg $AHB_AP 0xd0c
rp2350.dap apreg $AHB_AP 0xd0c" \
        | LC_ALL=C grep -av 'apreg' \
        | LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' | sed -n 2p
}
r_rom="$(probe_region 0x00000000)"
r_xip="$(probe_region 0x10000000)"
r_sram="$(probe_region 0x20000000)"
# read_memory is NOT usable here and was removed after one validation run.
#
# It requires an EXAMINED target, which is exactly what fails in the wedge being investigated. On a
# perfectly healthy card it returned "unreadable", which tripped the "AHB path is hung" branch — a
# false positive that would have fired on every capture, healthy or wedged, and pointed at the AHB
# bus in all of them. Caught on the validation run rather than in a report, which is the only reason
# it is a footnote instead of a sixth retraction.
#
# The TAR/DRW pair is the sound probe: it drives the AP's own address and data registers, needs no
# examined target, and returned a plausible DHCSR (0x00130003 — C_DEBUGEN|C_HALT|S_REGRDY|S_HALT)
# on a healthy card. That is a genuine AHB read through the AP.
echo
echo "MEM-AP raw   : IDR ${memap_idr:-unreadable}   CSW ${memap_csw:-unreadable}   BASE ${memap_base:-unreadable}   (AP $AHB_AP)"
if [ -n "$memap_csw" ]; then
    _csw=$(( memap_csw ))
    printf '  CSW decode : TrInProg(7)=%s  DeviceEn(6)=%s\n' \
        $(( (_csw >> 7) & 1 ))  $(( (_csw >> 6) & 1 ))
    [ $(( (_csw >> 7) & 1 )) = 1 ] && echo "  TrInProg SET — a transfer really is outstanding; the AHB hypothesis fits."
fi
case "${memap_idr:-}" in
    0x00000000) echo "  IDR is ZERO — the AP is not present or not enabled. This is NOT an outstanding" ;
                echo "  transaction; the AP itself is gone, and the bus-fabric story does not explain it." ;;
    "")         echo "  IDR unreadable — the DP-to-AP path is broken, upstream of the MEM-AP." ;;
    *)          echo "  IDR reads back — the AP is present and answering, so the stall is downstream of it." ;;
esac

echo "  re-read IDR : ${memap_idr2:-unreadable}   (first read: ${memap_idr:-unreadable})"
if [ -n "$memap_idr" ] && [ -n "$memap_idr2" ]; then
    if [ "$memap_idr" = "$memap_idr2" ]; then
        echo "    SAME both times — a stable latched value, not a per-transfer desync."
    else
        echo "    DIFFERENT each read — the link is shifting per transfer, not returning one stale word."
    fi
fi
echo "  cm1 AHB-AP  : IDR ${cm1_idr:-unreadable}   (AP 0x4000)"
# COHERENCE CANARY — is this capture shifted?
#
# MEASURED 2026-08-11. Two captures show the read pipeline returning responses LAGGED BY ONE
# TRANSFER, with 0x4c013477 filling the vacated slot:
#
#   iter448   CSW == BASE == 0x4c013477, IDR unreadable
#   iter1274  SWCORE=0x4c013477, XIP=0x0000095e   <- XIP is holding SWCORE'"'"'s healthy value
#
# In that state every other number in the capture is displaced by one, so a register can read
# "healthy" while actually showing its neighbour. iter1274'"'"'s DHCSR looked readable and that
# conclusion is worthless for exactly this reason.
#
# RP-AP IDR is the canary: it is a fixed constant (0x09260040 on this part), so any other value
# means the pipeline is shifted and NOTHING in this capture can be trusted at face value.
if [ -n "$rpap_idr" ] && [ "$rpap_idr" != "0x09260040" ]; then
    echo
    echo "  *** CAPTURE IS SHIFTED — RP-AP IDR reads $rpap_idr, expected 0x09260040."
    echo "      The read pipeline is returning lagged responses. Every value in this capture is"
    echo "      displaced by one transfer and must NOT be read at face value, including any that"
    echo "      look healthy. Classify this as READ_PIPELINE_DESYNC, not as an AHB result."
    echo
fi
echo "  AHB through AP: DHCSR via TAR/DRW = ${dhcsr:-unreadable}   (healthy card reads ~0x00130003)"
# REGION SWEEP: RAW VALUES ONLY — NOT VALIDATED, DO NOT INTERPRET.
#
# The intent was to localise the hang: XIP dead while SRAM answers would point at the QSPI/XIP
# interface, everything dead would point at the fabric. The read does not yet produce trustworthy
# values, so no conclusion is drawn from it.
#
# On a HEALTHY card it reports SRAM holding XIP's word and DHCSR reading 0x00000000, which are both
# wrong. Three attempts failed to fix it: reading DRW twice for the posted-read rule, stripping the
# telnet command echo (whose address argument is itself an 8-hex token), and both together. The
# residual error is somewhere in how TAR/DRW is driven through `dap apreg`, and is not yet found.
#
# The values are still printed, because they cost nothing to collect and a later session may be able
# to interpret them. They are labelled UNVALIDATED so that no one — including me — reads a
# localisation out of them. Shipping a discriminator that fires on healthy cards is exactly how the
# read_memory probe nearly poisoned every capture in this file.
# WHERE IS THE CORE STUCK?
#
# This is the question "why does it hang" actually reduces to, and it is answerable whenever the AHB
# is alive — which two of the captured signatures are (iter96 read DHCSR fine while examine still
# failed).
#
# DCRSR/DCRDR is the core-register access pair: write a register selector to DCRSR (0xe000edf4),
# read the value from DCRDR (0xe000edf8). Register 15 is the PC, 16 is xPSR. Both go through the
# same TAR/DRW path that DHCSR does, so if DHCSR read, these will too.
#
# It needs the core HALTED, which means writing C_HALT|C_DEBUGEN|DBGKEY to DHCSR. That is a state
# change, and this snapshot is otherwise read-only — but the card is about to be recovered anyway,
# halting does not disturb SRAM (the flash-cache evidence the tool exists to preserve), and knowing
# the PC is worth far more than the last few microseconds of a wedged core's execution.
#
# Skipped entirely when the AHB is dead: there is nothing to read, and the write would just hang.
core_pc=""; core_psr=""
if [ -n "$dhcsr" ]; then
    ocd "rp2350.dap apreg $AHB_AP 0xd04 0xe000edf0
rp2350.dap apreg $AHB_AP 0xd0c 0xa05f0003" >/dev/null 2>&1
    read_core_reg(){   # $1 = DCRSR selector
        ocd "rp2350.dap apreg $AHB_AP 0xd04 0xe000edf4
rp2350.dap apreg $AHB_AP 0xd0c $1
rp2350.dap apreg $AHB_AP 0xd04 0xe000edf8
rp2350.dap apreg $AHB_AP 0xd0c" | LC_ALL=C grep -av 'apreg' \
            | LC_ALL=C grep -aoE '0x[0-9a-fA-F]{8}' | sed -n 1p
    }
    core_pc="$(read_core_reg 0x0000000f)"
    core_psr="$(read_core_reg 0x00000010)"
    echo "  core state  : PC ${core_pc:-unreadable}   xPSR ${core_psr:-unreadable}"
    case "${core_pc:-}" in
        0x1000*|0x1010*) echo "    PC is in XIP/flash — the core is executing firmware from flash." ;;
        0x0000*)         echo "    PC is in bootrom." ;;
        0x2000*)         echo "    PC is in SRAM." ;;
        "")              echo "    PC unreadable despite a live DHCSR — the halt did not take." ;;
        *)               echo "    PC is outside the expected regions." ;;
    esac
fi

printf '  region sweep (UNVALIDATED, do not interpret): ROM %s  XIP %s  SRAM %s\n' \
    "${r_rom:-none}" "${r_xip:-none}" "${r_sram:-none}"
echo "    NOTE: this read is known to return wrong values on a HEALTHY card. Recorded for a future"
echo "    session, not for classification. The AHB verdict above rests on DHCSR alone."
if [ -n "$memap_idr" ] && [ -z "$dhcsr" ]; then
    echo "    AP REGISTERS FINE BUT MEMORY READ FAILS — the AHB path behind a healthy AP is hung."
    if [ -n "$dhcsr_cm1" ]; then
        echo "    BUT cm1's AP READS IT: DHCSR = $dhcsr_cm1"
        echo "    => the bus is NOT stalled. The blockage is specific to cm0's AP-to-AHB path, and"
        echo "       core state is reachable through cm1."
    else
        echo "    cm1's AP also cannot read memory (DHCSR unreadable via AP 0x4000)."
        echo "    => the fabric or a bus master is stalled, not one AP. No AP-based route will reach"
        echo "       the core; this needs a path that is not a MEM-AP at all."
    fi
    echo "    This is the case, and the ONLY case, in which 'outstanding AHB transaction' is the"
    echo "    right description. AP-register health alone never established it."
elif [ -n "$dhcsr" ]; then
    # Phrased without assuming a failure: on a healthy card examine SUCCEEDS, and claiming "the
    # examine failure is higher up" there is simply false. The wedge interpretation belongs in the
    # verdict section, which knows whether examine actually failed.
    echo "    AHB reads WORK through the AP — the bus behind the AP is not hung."
fi
echo "  RP-AP       : IDR ${rpap_idr:-unreadable}   (AP $RP_AP)"
if [ -n "$rpap_idr" ] && [ -z "$memap_idr" ]; then
    echo "    RP-AP ANSWERS while the core AHB-AP does not — the DAP and the SWD link are fine."
    echo "    The fault is scoped to the core AP / AHB path, NOT the debug port as a whole."
fi
if [ -n "$cm1_idr" ] && [ -z "$memap_idr" ]; then
    echo "    cm1 answers while cm0 does not — the fault is CORE-SCOPED, and core 0 is the core that"
    echo "    owns low_flash_task()."
fi

# arp_examine FAILING IS NOT THE SAME AS THE BUS BEING STALLED.
#
# The verdict below has always been derived from this one call, and named MEMAP_STALL_*. That name
# is wrong, and it has steered this whole investigation.
#
# MEASURED (soak 16, iter 924): the snapshot read IDR, CSW, BASE, cm1's IDR, the RP-AP canary AND
# DHCSR-through-the-AP (0x00100001) all successfully, and arp_examine still failed — so the verdict
# said "the bus is stalled" about a bus that was demonstrably answering. The AHB watcher had also
# sampled that same card 1426 times without a single failure over the preceding 91 seconds.
#
# So arp_examine fails for reasons of its own: it does more than touch the bus (ROM table walk, core
# identification, halt state), and any of that can fail on a card whose AHB is fine. Whether the bus
# works is answered by the DHCSR read above, not by this.
MEMAP_ALIVE=no
if LC_ALL=C grep -qai 'processor detected' <<< "$(ocd "rp2350.cm0 arp_examine")"; then
    MEMAP_ALIVE=yes
fi

# Cross-check: does the direct bus read agree with examine? Disagreement is the interesting case and
# was previously invisible, because only examine reached the verdict.
BUS_READS=no
[ -n "${dhcsr:-}" ] && BUS_READS=yes
if [ "$MEMAP_ALIVE" = no ] && [ "$BUS_READS" = yes ]; then
    echo
    echo "  *** examine FAILED but the AHB READS FINE (DHCSR $dhcsr)."
    echo "      The bus is not stalled. Whatever arp_examine could not do, it was not bus access."
    echo "      Do not read the verdict below as evidence of a hung bus."
fi
echo
echo "MEM-AP examine : $([ "$MEMAP_ALIVE" = yes ] && echo 'SUCCEEDED — the bus is alive, this card is not wedged' || echo 'FAILED — the bus is stalled')"

echo
# ONE MACHINE-READABLE CLASSIFICATION LINE, then the prose.
#
# The wedge worth capturing is rare and it will be found by a tired person at an awkward hour. Raw
# hex invites exactly the wrong call — rescuing while the evidence is still live, or spending risk
# trying to preserve evidence that the bug already destroyed. Ordering matters below: WAITING_TIMCK
# is checked first because the datasheet says a reset is the only recourse in that state, which
# settles the question regardless of what the SRAM domains report.
verdict=UNKNOWN
if [ -z "$SWCORE" ]; then
    verdict=RPAP_UNREADABLE
elif [ "$MEMAP_ALIVE" = yes ]; then
    verdict=HEALTHY_NO_WEDGE
elif [ "$(sb 9)" = yes ]; then
    verdict=RESET_ONLY_WAITING_TIMCK
elif [ "$(sb 10)" = yes ]; then
    verdict=POWER_CLOCK_STALL
elif [ "$SWCORE" = "0x0000095e" ] && [ "$SRAM0" = "0x0000015e" ] && [ "$SRAM1" = "0x0000015e" ]; then
    verdict=MEMAP_STALL_WITH_DOMAINS_HEALTHY
elif [ "$SRAM0" = "0x0000015e" ] && [ "$SRAM1" = "0x0000015e" ]; then
    verdict=VOLATILE_EVIDENCE_POSSIBLY_INTACT
else
    verdict=VOLATILE_EVIDENCE_ALREADY_LOST
fi
echo "VERDICT=$verdict"
echo
case "$verdict" in
  HEALTHY_NO_WEDGE)
    echo "  The MEM-AP examined successfully — this card is not wedged. Nothing to investigate."
    echo "  The values above are a healthy-baseline capture, useful as a reference to diff a real"
    echo "  wedge against."
    ;;
  RPAP_UNREADABLE)
    echo "  The RP-AP itself did not answer. That is worse than a stalled MEM-AP — the rescue port"
    echo "  is the surface that is supposed to survive everything. Check the probe and the wiring"
    echo "  before concluding anything about the chip."
    ;;
  RESET_ONLY_WAITING_TIMCK)
    echo "  SWCORE is stuck waiting for the AON-timer clock transition. The datasheet states that in"
    echo "  this state the only recourse is to reset the chip, so there is nothing to preserve and"
    echo "  no non-reset recovery to attempt. Capture RP-AP/DP state (done, above), then rescue,"
    echo "  halt in the bootrom, and dump the fs tail before letting the firmware run."
    ;;
  POWER_CLOCK_STALL)
    echo "  SWCORE is waiting for its power-manager clock — a clock transition has stalled. This is"
    echo "  direct causal evidence for the clock/power-transition hypothesis; record it. Whether it"
    echo "  is recoverable depends on the direction of the transition."
    ;;
  MEMAP_STALL_WITH_DOMAINS_HEALTHY)
    echo "  THE MOST INTERESTING CASE. Every power domain reads healthy and the MEM-AP is still dead,"
    echo "  so \"the domain was powered down\" no longer explains it."
    echo
    echo "  MEASURED 2026-08-10 (iter 448, first capture with a WORKING AP probe): the AP register"
    echo "  reads are NOT valid register contents. CSW and BASE both returned 0x4c013477 and IDR was"
    echo "  unreadable, against a healthy baseline of CSW 0x02800052 / BASE 0xe00ff003 / IDR"
    echo "  0x34770008. Two distinct registers cannot hold one value, and 0x4c013477 embeds 3477 — a"
    echo "  fragment of the healthy IDR. That is stale or shifted data on the DP-to-AP path, not the"
    echo "  AP reporting its own state."
    echo
    echo "  So do NOT read TrInProg from such a capture: it decodes a value that is not CSW. The"
    echo "  outstanding-AHB-transaction story is neither supported nor refuted, because the AP state"
    echo "  cannot be read at all. What IS established: the failure is in the DP-to-AP access path"
    echo "  while DP-level reads (CTRL/STAT) still succeed."
    echo
    echo "  Do not rescue yet — SRAM is live, so the dirty sector cache and flash_pages are still"
    echo "  physically present."
    ;;
  VOLATILE_EVIDENCE_POSSIBLY_INTACT)
    echo "  SRAM0/SRAM1 are at the powered baseline: the dirty sector cache and flash_pages are"
    echo "  LIKELY STILL PHYSICALLY PRESENT. A rescue destroys them — measured, SRAM returns with its"
    echo "  power-up fingerprint. If this wedge is being investigated rather than cleared, do NOT"
    echo "  rescue; a non-reset MEM-AP recovery is worth attempting first."
    ;;
  VOLATILE_EVIDENCE_ALREADY_LOST)
    echo "  The SRAM domains are not at the powered baseline, so the volatile evidence is already"
    echo "  gone — destroyed by whatever caused the wedge, not by anything you are about to do."
    echo "  Stop spending risk trying to preserve it. Rescue, halt in the bootrom, dump the fs tail,"
    echo "  and only then let the firmware run."
    ;;
esac
} | { [ -n "$OUT" ] && tee "$OUT" || cat; }

[ -n "$OUT" ] && say "written to $OUT"
exit 0
