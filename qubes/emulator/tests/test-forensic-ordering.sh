#!/usr/bin/env bash
# test-forensic-ordering.sh — guard the one invariant that makes hsm-wedge-snapshot.sh a forensic
# instrument rather than a state-destroying one. NO HARDWARE REQUIRED; pure source assertions.
#
# THE INVARIANT: observe everything pristine FIRST, perform the potentially destructive diagnostic
# LAST.
#
# Why it is fragile enough to need a test. The tool reads DP CTRL/STAT and the RP-AP power state
# under `configure -defer-examine`, specifically so OpenOCD never runs its examination path. That
# matters because OpenOCD's response to a stalled AP is not a bare DAPABORT — it writes
# DAPABORT|STKCMPCLR|STKERRCLR|WDERRCLR|ORUNERRCLR in one operation, clearing every sticky bit we
# came to read. Only after those values are captured does the tool run `arp_examine`, which is what
# distinguishes a wedged card from a healthy one and which may itself provoke that abort.
#
# Both halves are individually reasonable and the ordering between them is what carries the value.
# A later reader tidying this up — hoisting the examine to "fail fast", or moving the register reads
# after the target is known-good — would leave a script that still runs, still prints plausible hex,
# and silently reports the state OpenOCD left behind instead of the state the chip wedged in. That
# is precisely the failure class this bench spent a day removing: checks that cannot observe what
# they claim to.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SNAP="$REPO/tools/hsm-wedge-snapshot.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

printf '\n\033[1m### forensic snapshot ordering — pristine reads must precede the destructive probe\033[0m\n'

if [ ! -f "$SNAP" ]; then
    F "tools/hsm-wedge-snapshot.sh is missing — the forensic instrument is gone"
    printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"; exit 1
fi

line_of(){ grep -nE "$1" "$SNAP" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 | cut -d: -f1; }

l_defer="$(line_of 'configure -defer-examine')"
l_dp="$(line_of 'dap dpreg')"
l_ap="$(line_of 'dap apreg .* 0x08')"
l_exam="$(line_of 'arp_examine')"

[ -n "$l_defer" ] && P "attaches with -defer-examine, so OpenOCD never runs its abort path" \
                  || F "the -defer-examine attach is GONE — the sticky bits will be wiped before they are read"

[ -n "$l_dp" ] && P "reads DP CTRL/STAT" || F "the DP CTRL/STAT read is gone"
[ -n "$l_ap" ] && P "reads the RP-AP power state" || F "the RP-AP power-state read is gone"

if [ -n "$l_exam" ] && [ -n "$l_dp" ] && [ -n "$l_ap" ]; then
    if [ "$l_exam" -gt "$l_dp" ] && [ "$l_exam" -gt "$l_ap" ]; then
        P "arp_examine runs AFTER both pristine reads (line $l_exam > $l_dp, $l_ap)"
    else
        F "arp_examine has been moved BEFORE a pristine read (line $l_exam vs DP $l_dp / RP-AP $l_ap) — it can provoke the abort that clears the sticky bits, so the capture is worthless"
    fi
elif [ -z "$l_exam" ]; then
    F "the arp_examine liveness probe is gone — a healthy card is now indistinguishable from a wedged one"
fi

# The tool must not halt, reset or rescue: it exists to be run before those decisions are made.
for forbidden in 'ocd "halt' 'reset run' 'RESCUE_RESTART' 'apreg .* 0 0x80000000'; do
    if grep -nE "$forbidden" "$SNAP" 2>/dev/null | grep -qvE '^[0-9]+:[[:space:]]*#'; then
        F "hsm-wedge-snapshot.sh now performs a state-changing operation ($forbidden) — it must stay read-only"
    fi
done
[ "$fail" -eq 0 ] && P "stays read-only: no halt, reset or rescue"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || {
    echo
    echo "  This is not a style check. The ordering is what makes the capture meaningful:"
    echo "  OpenOCD clears STKCMP/STKERR/WDERR/ORUNERR when it aborts a stalled AP, so any"
    echo "  read taken after an examination reports OpenOCD's cleanup, not the wedge."
    exit 1
}
