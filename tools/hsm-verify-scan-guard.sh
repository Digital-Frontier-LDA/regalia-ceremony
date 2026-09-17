#!/usr/bin/env bash
# hsm-verify-scan-guard.sh — does the scan guard actually SAVE a card carrying a dangling link?
#
#   ./tools/hsm-verify-scan-guard.sh [outdir]
#
# The guard is known to be harmless: patched firmware boots, keygens, and still sees every file.
# Harmless is not the same as working. Proving it works needs a card whose flash actually contains a
# link pointing at a record that was never written — and waiting for a power cut to land inside a
# window a fraction of a keygen wide is hoping, not testing.
#
# So construct the condition instead of hunting it. The corruption is one 32-bit field: a record's
# next_addr, pointed at an erased sector. Build that image offline, then boot BOTH firmwares against
# THE SAME BYTES:
#
#     unpatched  -> expected: the scan follows the link, reads fid 0xffff, publishes it, then
#                   dereferences 0xffffffff and faults. A dead card.
#     patched    -> expected: the scan stops at the erased record and the card comes up.
#
# Same image both times is what makes this an experiment rather than two anecdotes. If the unpatched
# firmware survives, the mechanism is wrong and the guard is solving nothing — that outcome is a
# real result and this script reports it as one.
#
# DESTRUCTIVE. It rewrites the staging card's filesystem. Recoverable by reprovisioning.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# IDENTITY + ROLE FLAGS (mandatory — see the gate below). --probe <serial> names WHICH debug
# probe, --expect-board <otp-id> is verified against the RP2350 OTP id before anything is sent.
PROBE=""; EXPECT_BOARD=""
_pos=()
while [ $# -gt 0 ]; do
    case "$1" in
        --probe)        PROBE="$2"; shift 2;;
        --expect-board) EXPECT_BOARD="$2"; shift 2;;
        -h|--help)      sed -n '2,32p' "$0"; exit 0;;
        *)              _pos+=("$1"); shift;;
    esac
done
# bash 3.2 (macOS) treats "set -- "${_pos[@]}"" on an EMPTY array as an unbound variable under
# set -u, so guard the expansion instead of relying on the caller's bash version.
if [ "${#_pos[@]}" -gt 0 ]; then set -- "${_pos[@]}"; else set --; fi
OUT="${1:-$HOME/.local/share/akash-hsm-staging/guard-verify-$(date +%Y%m%d-%H%M%S)}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
FS_BASE="${HSM_FS_DUMP_BASE:-0x103f0000}"
FS_SIZE="${HSM_FS_DUMP_BYTES:-0x10000}"
PATCHED="${HSM_ELF_PATCHED:-$HOME/code/pico-hsm/build_forensic/pico_hsm.elf}"
UNPATCHED="${HSM_ELF_UNPATCHED:-$HOME/code/pico-hsm/build_forensic_off/pico_hsm.elf}"
mkdir -p "$OUT"
say(){ printf '%s\n' "$*"; }

# IDENTITY + ROLE INTERLOCK — the hsm-quiesce.sh pattern, now mandatory for every flash tool.
# This script captures and then REWRITES the card's filesystem. Before this gate it flashed
# whatever board the DEFAULT probe found — no probe serial, no OTP check, no role check. Now:
# --probe names the probe, the board it reaches is proven by its OTP id, and that board must be
# registered staging through HSM_BOARD_MAP and the committed role registry. Required, not advised.
# shellcheck source=/dev/null
. "$REPO/tools/hsm-reader-select.sh"
hsm_verify_board_over_probe "$PROBE" "$EXPECT_BOARD" || exit 2
hsm_assert_staging_board "$EXPECT_BOARD" || exit 2

ocd_run(){ perl -e 'alarm 200; exec @ARGV' -- "$OCD_BIN" -f interface/cmsis-dap.cfg \
    -f target/rp2350.cfg -c "adapter speed 5000" -c "$1" 2>&1; }

card_answers(){ local o; o="$(perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool 2>&1)"; \
    grep -qi '^Version' <<< "$o"; }

for e in "$PATCHED" "$UNPATCHED"; do
    [ -f "$e" ] || { echo "missing firmware: $e" >&2; exit 2; }
done

# ---- 1. capture the real filesystem ---------------------------------------------------------
say "capturing the current filesystem"
ocd_run "init; halt; dump_image $OUT/fs-orig.bin $FS_BASE $FS_SIZE; reset run; shutdown" \
    > "$OUT/dump.log" 2>&1
python3 - "$OUT/fs-orig.bin" <<'EOP' || exit 2
import sys
d = open(sys.argv[1], "rb").read()
if not d or d.count(0xff) == len(d):
    sys.stderr.write("the dump is empty or entirely erased — wrong base, or an unprovisioned card. "
                     "There is no chain to corrupt.\n")
    sys.exit(1)
EOP
say "  $(wc -c < "$OUT/fs-orig.bin") bytes of real filesystem"

# ---- 2. build the corrupted image ------------------------------------------------------------
say "constructing a dangling link"
python3 - "$OUT/fs-orig.bin" "$OUT/fs-dangling.bin" "$FS_BASE" "$FS_SIZE" <<'EOP' || exit 2
import sys
src, dst, base_s, size_s = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
BASE, SIZE = int(base_s, 16), int(size_s, 16)
d = bytearray(open(src, "rb").read())
END_POOL = BASE + SIZE - 0x1000          # the chain head lives near the top of the region

def u32(a):
    o = a - BASE
    return int.from_bytes(d[o:o+4], "little")

def w32(a, v):
    o = a - BASE
    d[o:o+4] = v.to_bytes(4, "little")

# Find the head of the chain by scanning for a pointer that lands inside the region.
# CORRUPT THE TAIL, NOT THE HEAD.
#
# An earlier version aimed the chain HEAD's next_addr at an erased sector. That is not the shape the
# ordering inversion leaves, and it is catastrophic in a way the real bug is not: severing the head
# makes EVERY record unreachable, so the card lost its PIN state, could not be re-initialised, and
# needed SWD to recover. It also destroys the very inventory a corruption test needs.
#
# The real inversion appends a NEW record and programs the link to it before the record itself. So
# the durable-but-dangling link is at the TAIL: everything already stored stays reachable, and only
# the newest entry points into erased space. Find the record whose next is 0x0 -- scan_region()'s
# clean-termination marker -- and aim that at an erased address inside the live pool.
ptrs = [(BASE + o, int.from_bytes(d[o:o+4], "little")) for o in range(0, SIZE - 4, 4)]
inrange = [(a, v) for a, v in ptrs if BASE <= v < BASE + SIZE and v != 0xffffffff]
if not inrange:
    sys.stderr.write("no chain pointers found -- nothing to corrupt\n"); sys.exit(1)
lo = min(v for _, v in inrange)

# Walk from the head to find the tail, rather than guessing which record it is.
head_at, head = inrange[-1][0], inrange[-1][1]
seen_addrs, cur, tail = set(), head, None
while cur and cur not in seen_addrs and BASE <= cur < BASE + SIZE:
    seen_addrs.add(cur)
    nxt = u32(cur)
    if nxt == 0x0:
        tail = cur
        break
    cur = nxt
if tail is None:
    sys.stderr.write("could not find the chain tail (no record with next == 0x0)\n"); sys.exit(1)

target = None
for a in range(lo + 0x1000, BASE + SIZE, 0x100):
    o = a - BASE
    if all(b == 0xff for b in d[o:o+64]):
        target = a
        break
if target is None:
    sys.stderr.write("no erased address inside the live pool to point at\n"); sys.exit(1)
head = tail          # corrupt the tail's next_addr
head_at = tail
print(f"    pool floor   {lo:#010x}  chain walked: {len(seen_addrs)} record(s)")

# Point the head record's next_addr at it. This is exactly the shape the measured ordering
# inversion leaves behind: the link is durable, the record it names is not.
w32(head, target)
open(dst, "wb").write(bytes(d))
print(f"    chain TAIL   {head:#010x} (next was 0x0 -- clean end of chain)")
print(f"    next_addr -> {target:#010x}  (erased sector: the dangling referent)")
EOP

# ---- 3. A/B the two firmwares against the same bytes ------------------------------------------
verdict_for(){   # $1 = elf, $2 = label
    say ""
    say "booting $2 firmware against the corrupted image"
    ocd_run "init; halt; program $1 verify; \
             flash write_image erase $OUT/fs-dangling.bin $FS_BASE bin; reset run; shutdown" \
        > "$OUT/flash-$2.log" 2>&1
    if grep -qa 'Verified OK' "$OUT/flash-$2.log"; then
        say "  flashed and filesystem restored"
    else
        say "  FLASH FAILED — see $OUT/flash-$2.log"
        echo "FLASH_FAILED"; return
    fi
    sleep 14
    if card_answers; then say "  card ANSWERS"; echo "ALIVE"; else say "  card SILENT"; echo "DEAD"; fi
}

r_unpatched="$(verdict_for "$UNPATCHED" unpatched | tail -1)"
r_patched="$(verdict_for "$PATCHED" patched | tail -1)"

# ---- 4. verdict ------------------------------------------------------------------------------
say ""
say "  unpatched: $r_unpatched"
say "  patched:   $r_patched"
say ""
if [ "$r_unpatched" = "DEAD" ] && [ "$r_patched" = "ALIVE" ]; then
    say "RESULT=GUARD_WORKS"
    say "  The same bytes kill the unpatched firmware and are survived by the patched one."
    say "  The dangling link is sufficient to brick a card, and the guard is sufficient to stop it."
    echo "RESULT=GUARD_WORKS" > "$OUT/verdict.txt"; exit 0
elif [ "$r_unpatched" = "ALIVE" ] && [ "$r_patched" = "ALIVE" ]; then
    say "RESULT=NO_HARM_OBSERVED"
    say "  The unpatched firmware SURVIVED a dangling link. The scan-walk mechanism does not"
    say "  reproduce as predicted on this build, and the guard is not demonstrated to be load-"
    say "  bearing. This weakens the Bug 6 story and must be reported, not buried."
    echo "RESULT=NO_HARM_OBSERVED" > "$OUT/verdict.txt"; exit 1
else
    say "RESULT=INCONCLUSIVE (unpatched=$r_unpatched patched=$r_patched)"
    say "  A patched firmware that dies, or a flash step that failed, proves nothing either way."
    echo "RESULT=INCONCLUSIVE" > "$OUT/verdict.txt"; exit 1
fi
