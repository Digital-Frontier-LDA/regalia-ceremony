#!/usr/bin/env bash
# hsm-bug6-powerloss.sh — interrupt a write-heavy workload with a real power cut, then ask whether
# a link reached flash before the record it references.
#
#   tools/hsm-bug6-powerloss.sh [cut-delay-seconds] [outdir]
#
# THE QUESTION. Upstream's hypothesis for Bug 6 is that the asynchronous, slot-ordered drain can
# expose a list link before the referenced record sector is durable. `low_flash_task()` programs
# flash_pages[0..5] in SLOT order, which is allocation order, not dependency order. If power is lost
# between a link's sector reaching flash and its referent's sector reaching flash, the chain points
# at bytes that were never written.
#
# WHY A REBOOT SOAK CANNOT ANSWER IT. Measured 2026-08-09: a 56-reboot instrumented run produced 56
# bytes of trace and zero events. The rescue-applet reboot path performs no filesystem writes, so
# allocate_free_addr(), flash_program_block() and the drain never run. Ordering evidence needs a
# WRITE workload, interrupted.
#
# WHAT THIS RUN PRODUCES, three views of the same transactions:
#   * the causal trace, captured externally over UART as it happened;
#   * the physical flash, dumped after the cut;
#   * the analyzer's verdict, joining the two.
#
# HONEST LIMITS, stated up front because they bound what a result means:
#   * a hub cut is COARSE. It lands wherever it lands in the write sequence, so a negative result
#     says very little — it may simply have missed the window. Only a positive result is strong.
#     Targeted, microsecond placement needs the GPIO-trigger + MOSFET rig in
#     doc/BUG6-INSTRUMENTATION-PLAN.md.
#   * this DESTROYS the card's filesystem on purpose. Staging only. It re-provisions afterwards.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CUT_AFTER="${1:-6}"
OUT="${2:-$HOME/.local/share/akash-hsm-staging/bug6-$(date +%Y%m%d-%H%M%S)}"
# DISCOVER THE UART NODE, DO NOT HARDCODE IT. It changes whenever the USB topology changes — adding
# the powered hub moved it from usbmodem1102 to usbmodem113202, and the first run captured 0 records
# because stty failed against the stale name and the failure was only a warning.
DEV="${HSM_FORENSIC_UART:-$(ls -t /dev/cu.usbmodem* 2>/dev/null | head -1)}"
BAUD="${HSM_FORENSIC_BAUD:-115200}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
# 0x103f0000, NOT 0x10f00000. pico-keys-sdk puts its filesystem at the TOP of a 4 MB flash, and the
# traces confirm it: records land at 0x103f7000-0x103f9000. The transposed digit pointed every dump
# at unmapped space above the device, where OpenOCD cheerfully returns 1 MB of 0xFF and reports
# success. Three runs printed "1048576 bytes" for a dump that was 100% erased — the physical half of
# the evidence never existed, and nothing said so.
FLASH_BASE="${HSM_FS_DUMP_BASE:-0x103f0000}"
FLASH_SIZE="${HSM_FS_DUMP_BYTES:-0x10000}"

# AN ALL-ERASED DUMP IS NOT EVIDENCE. Refuse to treat it as one.
assert_dump_is_real(){
    python3 - "$1" <<'EOP'
import sys
d = open(sys.argv[1], "rb").read()
if not d:
    sys.stderr.write("flash dump is EMPTY\n"); sys.exit(1)
if d.count(0xff) == len(d):
    sys.stderr.write(f"flash dump is 100% 0xFF ({len(d)} bytes) — wrong base address or a failed "
                     "read. This is not a picture of the filesystem.\n")
    sys.exit(1)
EOP
}

mkdir -p "$OUT"
say(){ printf '  %s\n' "$*"; }

# EVERY EXIT PATH TIDIES UP. This script refuses at a dozen points (capacity, channel, dump, void
# run) and several of them are reached with an OpenOCD server and a pyserial capture running, or —
# worse — with the DUT's VBUS switched OFF. Leaving either behind means the next run inherits a
# probe that is already held and a card that looks dead, and the operator debugs the wrong thing.
OCD_PID="" ; CAP_PID="" ; POWER_IS_CUT=0
cleanup(){
    local rc=$?
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null
    [ -n "$OCD_PID" ] && kill "$OCD_PID" 2>/dev/null
    if [ "$POWER_IS_CUT" = 1 ]; then
        printf '  restoring VBUS on hub %s port %s before exiting\n' "${LOC:-?}" "${PORT:-?}"
        restore_power 2>/dev/null
    fi
    return $rc
}
# EXIT tidies up; INT and TERM must also STOP. errexit is deliberately off in this script, so a
# handler that only returns leaves bash running the next command — the capture stopped, the power
# restored, and the run carrying on to produce a verdict from a sequence that was interrupted.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 120; exec @ARGV' -- nc localhost 4444 2>&1 | LC_ALL=C tr -d '\000'; }

# ---- 0. PROVE THE INSTRUMENT BEFORE USING IT -----------------------------------------------------
# uhubctl remaps a USB2 location onto its USB3 sibling unless -e is passed, and a hub can report a
# port off while the device stays powered. Neither failure announces itself, and this whole
# experiment is worthless if the "cut" does not cut. So verify against the real device: it must stop
# ANSWERING, and its USB registry id must change when it returns, which is re-enumeration.
LOC="${HSM_UHUBCTL_LOC:-}"; PORT="${HSM_UHUBCTL_PORT:-}"
if [ -z "$LOC" ] || [ -z "$PORT" ]; then
    read -r LOC PORT < <(uhubctl 2>/dev/null | awk -v want="${HSM_PICO_VIDPID:-2e8a:10fd}" '
        /^Current status for hub /{ hub=$5 }
        /^[ \t]*Port [0-9]+:/ && index($0, want) > 0 { gsub(/:/,"",$2); print hub, $2; exit }')
fi
[ -n "${LOC:-}" ] && [ -n "${PORT:-}" ] || { echo "cannot find the Pico's hub port" >&2; exit 2; }
say "power control: hub $LOC port $PORT"

card_answers(){ local o; o="$(perl -e 'alarm 20; exec @ARGV' -- sc-hsm-tool 2>&1)"; grep -qi '^Version' <<< "$o"; }
reg_id(){ local o; o="$(ioreg -p IOUSB -w0 2>/dev/null)"; grep -i 'Pico Key' <<< "$o" | grep -oE 'id 0x[0-9a-f]+' | head -1; }
# NEVER CUT THE DEBUG PROBE'S OWN PORT, and be sure we know which one that is.
#
# The probe and the DUT sit on the same hub. Cutting the probe's port while OpenOCD holds it open
# left it half-enumerated on 2026-08-09 — the hub reported `power connect []` with no ENABLE bit,
# macOS listed no device, and OpenOCD said "unable to find a matching CMSIS-DAP device". Three
# power cycles did not clear it; it took a physical replug. That costs a human, which is the one
# thing this bench exists to avoid.
PROBE_PORT="$(uhubctl -e -l "$LOC" 2>/dev/null | awk '/Debug Probe/ && !seen { gsub(/:/,"",$2); print $2; seen = 1 }')"
if [ -n "${PROBE_PORT:-}" ] && [ "$PROBE_PORT" = "$PORT" ]; then
    echo "REFUSING TO RUN: the DUT and the Debug Probe are on the same hub port ($PORT)." >&2
    echo "  Cutting it would take the debugger down with the card, and recovering that has" >&2
    echo "  needed a physical replug. Move one of them to another port." >&2
    exit 2
fi
[ -n "${PROBE_PORT:-}" ] && say "debug probe is on port $PROBE_PORT — will not be cut"

# A CUT THAT DID NOT HAPPEN MUST NOT BE SCORED AS ONE. POWER_IS_CUT was set before uhubctl ran and
# the status was discarded, so a failed switch produced an ordinary interrupted workload analysed as
# a power-loss experiment — the one thing this bench exists to measure, faked.
cut_power(){
    uhubctl -e -l "$LOC" -p "$PORT" -a off -r 2 >/dev/null 2>&1 || return 1
    POWER_IS_CUT=1
}
restore_power(){ uhubctl -e -l "$LOC" -p "$PORT" -a on >/dev/null 2>&1; POWER_IS_CUT=0; }

# THE VERIFICATION CUT IS OPT-IN, BECAUSE IT DESTROYS THE INSTRUMENT IT PRECEDES.
#
# MEASURED 2026-08-09: a SINGLE DUT power cut is enough to kill the Debug Probe's UART bridge. This
# run used to verify the cut was real, then self-test the trace channel — and the self-test failed
# every time, because the verification cut had just taken the channel down. The experiment was
# spending its instrument during setup and then discovering it was gone.
#
# The cut has been verified on this bench (card stops answering, USB registry id changes on return)
# and that property does not need re-establishing every run. So the ONLY cut in a normal run is the
# experimental one, at the end — the UART then stays alive for the whole workload and dies at the
# cut, which costs nothing, since everything before the cut is the evidence.
#
# HSM_BUG6_VERIFY_CUT=1 re-enables it, for a bench where the cut is not yet trusted. Expect the
# trace channel to be dead afterwards.
# `= 1`, not `-n`: with a -n test, HSM_BUG6_VERIFY_CUT=0 — the natural way to write "no" — ENABLED
# the verification cut and killed the UART bridge this run depends on.
if [ "${HSM_BUG6_VERIFY_CUT:-0}" = "1" ]; then
say "verifying the cut is real before relying on it (this will disturb the probe)"
_id0="$(reg_id)"
cut_power || { echo "REFUSING TO RUN: uhubctl could not switch hub $LOC port $PORT off for the" >&2
               echo "  verification cut, so the instrument cannot be verified at all." >&2
               exit 2; }
sleep 4
if card_answers; then
    restore_power
    echo "REFUSING TO RUN: the card still answers with its port powered off." >&2
    echo "  The cut is not cutting. Check the -e flag and the hub, and do not trust any" >&2
    echo "  power-loss result from this bench until a cut is demonstrably real." >&2
    exit 2
fi
restore_power; sleep 8
_id1="$(reg_id)"
if [ -z "$_id1" ] || [ "$_id0" = "$_id1" ]; then
    echo "REFUSING TO RUN: the device did not re-enumerate ($_id0 -> ${_id1:-absent})." >&2
    exit 2
fi
say "cut verified: card went silent and re-enumerated ($_id0 -> $_id1)"
for _ in $(seq 1 30); do card_answers && break; sleep 2; done
card_answers || say "WARNING: the card is not answering after the verification cut"
else
    say "skipping the verification cut (HSM_BUG6_VERIFY_CUT=1 to force it)"
    say "  a single cut kills the probe's UART bridge, and the channel self-test below is the"
    say "  check that actually matters for this run"
fi

# ---- 0. CAPACITY ---------------------------------------------------------------------------------
# A FULL CARD FAILS WRITES WITH THE SAME SYMPTOM AS A BROKEN BUILD.
#
# CKR_GENERAL_ERROR from an exhausted card is indistinguishable by message from a genuine fault. On
# 2026-08-10 that produced two consecutive wrong diagnoses: a candidate ordering fix was blamed for
# breaking keygen, then the stock build was blamed too. The card simply held 128 objects. Freeing 60
# restored 2/2 keygens on the same binary that had just "failed".
#
# So check before the run, not after the confusion.
if ! "$REPO/tools/hsm-capacity-check.sh" >/dev/null 2>&1; then
    echo "REFUSING TO RUN: the card is at or near its object limit." >&2
    "$REPO/tools/hsm-capacity-check.sh" 2>&1 | sed 's/^/  /' >&2
    echo "  Any write failure in this run would be capacity, not firmware, and the verdict would" >&2
    echo "  be meaningless. Free space first:  ./tools/hsm-capacity-check.sh --free 40" >&2
    exit 2
fi
say "capacity: $("$REPO/tools/hsm-capacity-check.sh" 2>/dev/null | head -1)"

# ---- 1. BASELINE ---------------------------------------------------------------------------------
say "capturing the pre-run flash baseline"
pkill -f "$(basename "$OCD_BIN")" 2>/dev/null; sleep 2
"$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c "adapter speed 5000" > "$OUT/ocd-pre.log" 2>&1 &
OCD_PID=$!
sleep 9
ocd "halt
dump_image $OUT/flash-before.bin $FLASH_BASE $FLASH_SIZE" >/dev/null 2>&1
ocd "resume" >/dev/null 2>&1
if assert_dump_is_real "$OUT/flash-before.bin"; then
    say "  $(wc -c < "$OUT/flash-before.bin") bytes of real filesystem"
else
    echo "REFUSING TO RUN: the pre-run flash baseline is not real flash (see above)." >&2
    echo "  Set HSM_FS_DUMP_BASE to where this build actually keeps its filesystem." >&2
    exit 2
fi
pkill -f "$(basename "$OCD_BIN")" 2>/dev/null; sleep 2

# ---- 2. TRACE + WORKLOAD -------------------------------------------------------------------------
# CAPTURE WITH pyserial, NEVER stty+cat. stty does not reliably apply CDC line coding to the Debug
# Probe's UART bridge: the port opens, bytes arrive, and they are a mis-clocked read of a real
# signal. Measured on the same firmware and wiring — stty+cat gave ~2800 bytes and 0 records at
# EVERY baud from 19200 to 230400; pyserial gave 35074 bytes, 947 records, 0 rejected.
CAPTURE="$REPO/tools/hsm-forensic-capture.py"
PYBIN="${HSM_PYSERIAL_PYTHON:-$HOME/.local/share/akash-hsm-venv/bin/python3}"
[ -x "$PYBIN" ] || PYBIN=python3
if ! "$PYBIN" -c "import serial" 2>/dev/null; then
    echo "REFUSING TO RUN: pyserial is unavailable to $PYBIN." >&2
    echo "  stty+cat is NOT an acceptable fallback here — it mis-clocks this bridge and yields" >&2
    echo "  a confident verdict from an unreadable trace." >&2
    exit 2
fi
capture_bg(){ "$PYBIN" "$CAPTURE" "$1" "$2" "$DEV" "$BAUD" 2>/dev/null & CAP_PID=$!; }
say "trace channel: $DEV @ $BAUD (pyserial)"
# ---- 2a. PROVE THE CHANNEL DELIVERS FRAMES BEFORE SPENDING A RUN ---------------------------------
#
# Opening the port is not the same as receiving from it. Two runs completed the whole destructive
# sequence — verified cut, both flash dumps, analyzer verdict — on ZERO decoded records, and each
# printed an authoritative-looking INCOMPLETE. The port opened; nothing came through. A run that
# cannot deliver evidence should be abandoned before it wipes the card, not after.
#
# So: do one small write and require real frames. Cheap, and it fails in seconds rather than after
# a full provisioning cycle.
say "self-testing the trace channel with a single write"
# ONE CONTINUOUS CAPTURE for the self-test AND the workload. Two separate captures leave a real
# discontinuity in the middle of the evidence: measured, a run decoded 765 records cleanly and was
# still condemned UNUSABLE for a gap 621 -> 1540, because the self-test's own keygen consumed
# sequence numbers while the trace capture was not running. The analyzer was right — a gap can hide
# the deciding program — so remove the gap rather than teach it to ignore one.
capture_bg 620 "$OUT/trace.bin"
sleep 2
perl -e 'alarm 30; exec @ARGV' -- pkcs11-tool --module "${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}" \
    --login --pin "${HSM_USER_PIN:-648219}" --keypairgen --key-type EC:prime256v1 \
    --id 7f --label forensic-selftest >/dev/null 2>&1
sleep 2
# Peek at the live capture WITHOUT stopping it: copy what has arrived so far and decode that.
cp "$OUT/trace.bin" "$OUT/selftest.bin" 2>/dev/null || true
_st="$(python3 "$REPO/tools/hsm-forensic-decode.py" "$OUT/selftest.bin" 2>&1 >/dev/null | grep -oE '^decoded [0-9]+' | awk '{print $2}')"
if [ "${_st:-0}" -lt 5 ]; then
    echo "REFUSING TO RUN: the trace channel delivered ${_st:-0} records for a known write." >&2
    echo "  The firmware emits (check g_seq over SWD) but the bytes are not arriving intact." >&2
    echo "  Fix the channel before spending a destructive run on it — an empty trace still" >&2
    echo "  produces a confident-looking verdict." >&2
    exit 2
fi
say "  channel verified: $_st records from a single keygen (capture continues)"

# WORKLOAD: REPEATED KEYGENS, NOT A FULL PROVISIONING.
#
# hsm-staging-restore.sh begins with --initialize, which erases the whole filesystem and emits a
# burst far larger than the 256-slot ring. The recorder then discards by design, and the trace shows
# a structural gap — measured at exactly 621 -> 1540 on three consecutive runs, which the analyzer
# correctly condemns as UNUSABLE. That is the recorder behaving as specified, not a fault.
#
# A keygen produces a few hundred events: enough to exercise allocate_free_addr(), the four
# structural link writes and the slot-ordered drain, without overflowing the ring. A single keygen
# already yielded 947 records with lost_total 0 and an ORDERING_VIOLATION, so this is the workload
# that actually answers the question.
# UNIQUE IDs PER RUN, OR THE SECOND RUN DOES NOTHING.
#
# These IDs were fixed at 0xc1..0xc8. The first run created them; every later run collided with the
# existing objects, wrote nothing, and produced ~54 records instead of ~3000 — while still printing
# a verdict. MEASURED: a 12-attempt hunt in which only attempts 1 and 2 did real work (3335 and 1936
# records); attempts 3-12 decoded 54 each. "12 attempts found nothing" was a false statement about
# an experiment that had effectively run twice.
RUN_TAG="$(( $(date +%s) % 4096 ))"
say "starting the write-heavy workload (repeated keygens, run tag $RUN_TAG)"
# COUNT WHAT SUCCEEDED. Every keygen failure was swallowed with `|| true`, and the record
# threshold below counts the ONE CONTINUOUS CAPTURE — which already contains the self-test keygen.
# A run where every workload keygen failed (a full card, colliding ids, a card no longer accepting
# writes) could therefore clear the threshold on the self-test alone and be scored as a power-loss
# experiment that never exercised the drain.
: > "$OUT/workload.ok"
(
  for i in 1 2 3 4 5 6 7 8; do
      if perl -e 'alarm 25; exec @ARGV' -- pkcs11-tool \
          --module "${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}" \
          --login --pin "${HSM_USER_PIN:-648219}" --keypairgen --key-type EC:prime256v1 \
          --id "$(printf '%04x' $(( (RUN_TAG * 16 + i) % 65536 )))" --label "bug6-$RUN_TAG-$i" \
          >/dev/null 2>&1; then
          echo "$i" >> "$OUT/workload.ok"
      fi
  done
) > "$OUT/workload.log" 2>&1 &
WORKLOAD_START="$(date +%s)"

say "cutting VBUS ${CUT_AFTER}s into the workload"
sleep "$CUT_AFTER"
cut_power || { echo "ABANDONING THE RUN: uhubctl could not switch hub $LOC port $PORT off." >&2
               echo "  Without a real cut this is an interrupted workload, not a power-loss run." >&2
               exit 2; }
CUT_AT="$(( $(date +%s) - WORKLOAD_START ))"
say "  cut at t+${CUT_AT}s"
sleep 4
pkill -f "pkcs11-tool" 2>/dev/null
kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null
restore_power

# ---- 3. POST-CUT PHYSICAL STATE ------------------------------------------------------------------
# Dump BEFORE letting the firmware settle into whatever it does with a damaged filesystem. The
# window is narrow: flash is non-volatile, but only until the firmware writes to it again.
say "waiting for the device to reappear, then dumping flash"
perl -e 'alarm 90; exec @ARGV' -- bash -c 'until _o="$(ioreg -p IOUSB -w0 2>/dev/null)"; grep -qi "Pico Key" <<< "$_o"; do sleep 2; done' || say "  device did not reappear on its own"
pkill -f "$(basename "$OCD_BIN")" 2>/dev/null; sleep 2
"$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c "adapter speed 5000" > "$OUT/ocd-post.log" 2>&1 &
OCD_PID=$!
sleep 9
ocd "halt
dump_image $OUT/flash-after.bin $FLASH_BASE $FLASH_SIZE" >/dev/null 2>&1
ocd "resume" >/dev/null 2>&1
POST_FLASH=""
if assert_dump_is_real "$OUT/flash-after.bin"; then
    POST_FLASH="$OUT/flash-after.bin"
    say "  $(wc -c < "$OUT/flash-after.bin") bytes of real filesystem"
else
    # DO NOT HAND THE ANALYZER A DUMP WE JUST REJECTED. It was still passed as --post-flash, so the
    # physical cross-check ran against 1 MiB of 0xFF: every record "missing from flash", which reads
    # as evidence of loss when it is evidence of a bad base address or a failed dump. The run is
    # still worth analysing on the trace alone — it just must not claim a physical finding.
    say "  WARNING: post-cut dump is all-0xFF — physical evidence UNAVAILABLE for this run"
    say "  the trace verdict below rests on the trace ALONE (--post-flash withheld)"
fi

# ---- 4. ANALYSE ----------------------------------------------------------------------------------
# A RUN THAT WROTE NOTHING IS NOT A MISS. Refuse to score it as one.
#
# INCOMPLETE from a near-empty trace is correct but reads like "tested and found clean" when it
# really means "never tested". The hunt counts attempts, so a void run silently inflates the
# denominator and makes a negative look stronger than the evidence supports.
_rec="$(python3 "$REPO/tools/hsm-forensic-decode.py" "$OUT/trace.bin" 2>&1 >/dev/null \
        | grep -oE '^decoded [0-9]+' | awk '{print $2}')"
_ok="$(wc -l < "$OUT/workload.ok" 2>/dev/null | tr -d ' ')"
if [ "${_ok:-0}" -eq 0 ]; then
    say "VOID RUN: not one workload keygen succeeded (${_rec:-0} records, self-test included)"
    say "  (duplicate key IDs, a full filesystem, or a card no longer accepting writes)"
    say "  NOT scored as a miss"
    echo "RESULT=VOID_WORKLOAD" > "$OUT/verdict.txt"
    echo "RESULT=VOID_WORKLOAD"
    exit 3
fi
# The self-test's own records are already in this capture — one keygen yielded ~947 on this bench —
# so the floor has to be counted BEYOND them, not from zero.
if [ $(( ${_rec:-0} - ${_st:-0} )) -lt 300 ]; then
    say "VOID RUN: only $(( ${_rec:-0} - ${_st:-0} )) records beyond the self-test's ${_st:-0} — the workload did not exercise the drain"
    say "  (duplicate key IDs, a full filesystem, or a card no longer accepting writes)"
    say "  NOT scored as a miss"
    echo "RESULT=VOID_WORKLOAD" > "$OUT/verdict.txt"
    echo "RESULT=VOID_WORKLOAD"
    exit 3
fi
say "decoding the trace"
python3 "$REPO/tools/hsm-forensic-decode.py" "$OUT/trace.bin" > "$OUT/trace.jsonl" 2>"$OUT/decode.log"
cat "$OUT/decode.log" | sed 's/^/    /'

say "running the analyzer against the post-cut flash"
if [ -n "$POST_FLASH" ]; then
    python3 "$REPO/tools/hsm-drain-analyzer.py" "$OUT/trace.jsonl" \
        --post-flash "$POST_FLASH" --flash-base "$FLASH_BASE" \
        > "$OUT/verdict.txt" 2>&1
else
    python3 "$REPO/tools/hsm-drain-analyzer.py" "$OUT/trace.jsonl" > "$OUT/verdict.txt" 2>&1
    echo "PHYSICAL_EVIDENCE=UNAVAILABLE (post-cut flash dump was not real flash)" >> "$OUT/verdict.txt"
fi
sed 's/^/    /' "$OUT/verdict.txt"

{
    echo "cut_after_s=$CUT_AFTER"
    echo "cut_at_s=$CUT_AT"
    echo "hub=$LOC port=$PORT"
    echo "tooling=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
} > "$OUT/run.meta"
say "artifacts in $OUT"
grep -aoE '^RESULT=[A-Z_]+' "$OUT/verdict.txt" | head -1
