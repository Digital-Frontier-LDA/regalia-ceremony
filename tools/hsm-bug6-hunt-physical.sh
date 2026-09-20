#!/usr/bin/env bash
# hsm-bug6-hunt-physical.sh — repeat the coarse power cut until one lands in the ordering window.
#
#   ./tools/hsm-bug6-hunt-physical.sh [attempts] [outdir]
#
# WHY THIS EXISTS.
#
# The trace shows an ordering inversion: the predecessor's next_addr is programmed before the record
# it points at. That is a property of the drain, and it reproduces. What it is NOT is proof of
# corruption — FLASH_PROGRAM_RETURNED records that the call returned, not that bytes reached the
# medium. Two independent reviewers landed on the same objection:
#
#   "You proved call-return order in an instrumented trace, not that power loss can leave flash
#    with a durable link to a non-durable referent."
#
# The analyzer already knows the difference. hsm-drain-analyzer.py emits evidence="trace" for an
# ordering claim derived from the event stream, and evidence="physical" only when the post-cut dump
# shows _phys_u32(link_addr) == new_base AND _phys_is_erased(new_base) — the link present, the
# referent still 0xFF. That is the dangling reference itself, and it is the whole claim.
#
# The physical path had never fired, and could not have: FLASH_BASE was 0x10f00000 while the
# filesystem is at 0x103f0000, so every dump read unmapped space and came back 1 MB of 0xFF. With
# the base corrected the check can finally succeed, which makes repetition worth spending.
#
# A hub cut is coarse — hundreds of milliseconds of jitter against a window that a single run showed
# to be ~3000 events wide. One attempt landing in it is luck; the cheapest way to buy the luck is to
# take the shot repeatedly before building the GPIO-trigger + MOSFET rig. This stops at the first
# physical violation, so a lucky early hit costs one run.
#
# Every attempt is kept, hit or miss. A run that produced only trace evidence is still a data point
# about how wide the window is, and discarding misses would turn this into a machine for
# manufacturing the answer it was pointed at.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTEMPTS="${1:-20}"
OUT="${2:-$HOME/.local/share/akash-hsm-staging/bug6-hunt-$(date +%Y%m%d-%H%M%S)}"
CUT_AT="${HSM_BUG6_CUT_AT:-}"
mkdir -p "$OUT"

say(){ printf '%s\n' "$*"; }

say "hunting for a PHYSICAL dangling reference"
say "  attempts:  $ATTEMPTS"
say "  artifacts: $OUT"
say "  stopping at the first evidence=physical violation; misses are kept"
say ""

hits=0; real=0; void=0
for i in $(seq 1 "$ATTEMPTS"); do
    # Vary the cut point across attempts. A fixed offset samples one phase of the workload over and
    # over; the window sits at a different place each run because keygen timing is not constant.
    if [ -n "$CUT_AT" ]; then
        at="$CUT_AT"
    else
        at=$(( 14 + (i * 7) % 26 ))
    fi
    d="$OUT/attempt-$(printf '%03d' "$i")-cut${at}s"
    printf '  attempt %2d/%s  cut at t+%ss ... ' "$i" "$ATTEMPTS" "$at"

    perl -e 'alarm 900; exec @ARGV' -- "$REPO/tools/hsm-bug6-powerloss.sh" "$at" "$d" \
        > "$d.log" 2>&1
    rc=$?

    verdict="$(grep -aoE '^RESULT=[A-Z_]+' "$d.log" 2>/dev/null | tail -1)"

    # Ask the analyzer directly whether ANY violation this run rests on physical evidence. The
    # console summary does not distinguish the two, and the distinction is the entire point.
    # THE ANALYZER PATH IS PASSED IN, NOT COMPUTED. Under `python3 -`, `__file__` is "<stdin>", so
    # `os.path.abspath(__file__)` resolved against the SHELL'S CURRENT DIRECTORY: run from the
    # repository root — the documented invocation — it pointed one level above the repository, the
    # subprocess produced no JSON, the except printed "0", and the hunt recorded "no physical
    # evidence" for every attempt. A negative result from a command that never ran.
    phys="$(python3 - "$d/trace.jsonl" "$d/flash-after.bin" "$REPO/tools/hsm-drain-analyzer.py" <<'EOP' 2>/dev/null
import json, subprocess, sys, os
trace, flash, analyzer = sys.argv[1], sys.argv[2], sys.argv[3]
if not (os.path.exists(trace) and os.path.exists(flash) and os.path.exists(analyzer)):
    print("0"); raise SystemExit
cmd = [sys.executable, analyzer, trace, "--post-flash", flash,
       "--flash-base", os.environ.get("HSM_FS_DUMP_BASE", "0x103f0000"), "--json"]
try:
    d = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout)
except Exception:
    print("0"); raise SystemExit
print(sum(1 for v in d.get("violations", [])
          if v.get("evidence") == "physical" and v.get("verdict") == "ORDERING_VIOLATION"))
EOP
)"
    phys="${phys:-0}"

    printf '%s  physical=%s (rc=%s)\n' "${verdict:-RESULT=NONE}" "$phys" "$rc"

    # A void run is not a miss. Counting it as one inflates the denominator of a negative result.
    if [ "$rc" = "3" ] || [ "$verdict" = "RESULT=VOID_WORKLOAD" ]; then
        say "      ^ VOID (workload did nothing) — not counted; retrying does not help until fixed"
        void=$((void + 1))
        continue
    fi
    real=$((real + 1))

    if [ "$phys" -gt 0 ] 2>/dev/null; then
        hits=$((hits + 1))
        say ""
        say "PHYSICAL DANGLING REFERENCE CAPTURED on attempt $i (cut at t+${at}s)"
        say "  the post-cut dump shows the link present against an ERASED referent"
        say "  artifacts: $d"
        say ""
        say "This is the evidence the trace could not supply. Bug 6's mechanism moves from"
        say "OBSERVED to demonstrated: interrupting the drain in this window leaves the chain"
        say "referencing bytes that were never written."
        echo "PHYSICAL_EVIDENCE=$d" > "$OUT/RESULT"
        exit 0
    fi
done

say ""
say "no physical dangling reference in $real REAL attempts ($void void, $ATTEMPTS launched)"
say ""
say "This does NOT refute the mechanism and must not be reported as if it did. A coarse hub cut has"
say "hundreds of milliseconds of jitter; the window it must land in is a fraction of one keygen."
say "Missing it $ATTEMPTS times is the expected outcome of a blunt instrument, not evidence of"
say "safety. The verdict stays OBSERVED, and the next instrument is the GPIO-trigger + MOSFET rig"
say "that can place a cut deliberately instead of hoping."
echo "PHYSICAL_EVIDENCE=none real_attempts=$real void=$void launched=$ATTEMPTS" > "$OUT/RESULT"
exit 1
