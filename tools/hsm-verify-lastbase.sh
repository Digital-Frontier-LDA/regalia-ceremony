#!/usr/bin/env bash
# hsm-verify-lastbase.sh — does a dangling link corrupt the NEXT write?
#
#   ./tools/hsm-verify-lastbase.sh [outdir]
#
# A dangling link does not brick the card — that was tested and the earlier claim retracted. The card
# boots and answers. So if the ordering inversion causes Bug 6 at all, the damage must land somewhere
# other than boot, and there is a specific candidate in scan_region():
#
#     if (flash_read_uintptr(base) == 0x0) {
#         if (base < last_base) {
#             last_base = base;
#         }
#         break;
#     }
#
# last_base is the allocation watermark, and it is updated ONLY on the clean-termination path, when a
# record's next is exactly 0x0. A dangling link makes the loop exit the OTHER way — the walk follows
# an erased record, reads 0xffffffff as the next link, and falls out when that fails `base >= startp`
# (or unwinds through the address wrap). On that path last_base is never lowered and keeps its
# initial value, end_data_pool.
#
# If the allocator then trusts a watermark that says "everything below here is free", the next write
# can be placed on top of live records. That is not a crash. It is silent corruption on the next
# write, which is Bug 6's actual shape, and it explains why a card carrying a dangling link boots up
# looking perfectly healthy.
#
# The test: inventory the objects, write ONE new key, inventory again. Anything that vanishes or
# stops reading was overwritten.
#
# DESTRUCTIVE. Rewrites the staging card's filesystem.
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
OUT="${1:-$HOME/.local/share/akash-hsm-staging/lastbase-$(date +%Y%m%d-%H%M%S)}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
MOD="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"
PIN="${HSM_USER_PIN:-648219}"
FS_BASE="${HSM_FS_DUMP_BASE:-0x103f0000}"
UNPATCHED="${HSM_ELF_UNPATCHED:-$HOME/code/pico-hsm/build_forensic_off/pico_hsm.elf}"
PATCHED="${HSM_ELF_PATCHED:-$HOME/code/pico-hsm/build_forensic/pico_hsm.elf}"
IMG="${HSM_DANGLING_IMAGE:-$HOME/.local/share/akash-hsm-staging/guard-verify3/fs-dangling.bin}"
mkdir -p "$OUT"
say(){ printf '%s\n' "$*"; }

# IDENTITY + ROLE INTERLOCK — the hsm-quiesce.sh pattern, now mandatory for every flash tool.
# This script rewrites the card's FILESYSTEM IMAGE. Before this gate it flashed whatever board
# the DEFAULT probe found — no probe serial, no OTP check, no role check. Now: --probe names the
# probe, the board it reaches is proven by its OTP id, and that board must be registered staging
# through HSM_BOARD_MAP and the committed role registry. All of it is required; absence refuses.
# shellcheck source=/dev/null
. "$REPO/tools/hsm-reader-select.sh"
hsm_verify_board_over_probe "$PROBE" "$EXPECT_BOARD" || exit 2
hsm_assert_staging_board "$EXPECT_BOARD" || exit 2

[ -f "$IMG" ] || { echo "no dangling image at $IMG — run hsm-verify-scan-guard.sh first" >&2; exit 2; }

# ADDRESS THE BOARD'S OWN CARD. Neither call below had a slot selector, so on the two-board bench
# they listed the first token — and the before/after difference they produce IS the result of this
# experiment. It could inventory the other card and report "pre-existing objects LOST: 0" for a
# board that lost records. The token is resolved from the board just verified over SWD.
# Resolved at FIRST USE: the card only exists to be asked once firmware has been flashed, and a
# load-time resolution would refuse runs that fail their own prerequisites first.
SLOTID=""
swept_slot(){
    [ -n "$SLOTID" ] && { printf '%s' "$SLOTID"; return 0; }
    local tok
    tok="$(hsm_token_for_board "$EXPECT_BOARD")" || return 1
    SLOTID="$(hsm_slot_id_for "$tok")" || return 1
    printf '%s' "$SLOTID"
}
require_slot(){
    local s
    s="$(swept_slot)"
    [ -n "$s" ] || { echo "REFUSING: board $EXPECT_BOARD does not resolve to exactly one PKCS#11 slot;" >&2
                     echo "  this experiment IS a before/after diff of one card and must not read another." >&2
                     exit 2; }
    printf '%s' "$s"
}

inventory(){   # -> sorted "id label" lines, one per key object
    perl -e 'alarm 90; exec @ARGV' -- pkcs11-tool --module "$MOD" --slot "$(require_slot)" --login --pin "$PIN" \
        --list-objects 2>/dev/null \
        | awk '/^(Private|Public) Key Object/{t=$1} /^  label:/{l=$2} /^  ID:/{print t" "$2" "l}' \
        | sort
}

run_arm(){   # $1 = elf, $2 = label, $3 = HEX id for the new key
    say ""
    say "=== $2 firmware ==="
    perl -e 'alarm 200; exec @ARGV' -- "$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
        -c "adapter speed 5000" \
        -c "init; halt; program $1 verify; flash write_image erase $IMG $FS_BASE bin; reset run; shutdown" \
        > "$OUT/flash-$2.log" 2>&1
    grep -qa 'Verified OK' "$OUT/flash-$2.log" || { say "  FLASH FAILED"; return 1; }
    sleep 14

    inventory > "$OUT/$2-before.txt"
    local n_before; n_before="$(wc -l < "$OUT/$2-before.txt" | tr -d ' ')"
    say "  objects before the write: $n_before"
    if [ "$n_before" = "0" ]; then
        say "  card lists nothing — cannot test a write against an empty inventory"
        return 1
    fi

    # ONE write. The hypothesis is about the next allocation, so do not obscure it with a burst.
    say "  creating one key"
    if perl -e 'alarm 90; exec @ARGV' -- pkcs11-tool --module "$MOD" --slot "$(require_slot)" --login --pin "$PIN" \
        --keypairgen --key-type EC:prime256v1 --id "$3" --label "lastbase-$2" \
        > "$OUT/keygen-$2.log" 2>&1; then
        say "  key created"
    else
        # A WRITE THAT DID NOT HAPPEN IS NOT EVIDENCE OF NO CORRUPTION. The whole hypothesis is
        # about what the NEXT allocation does; if the allocation never ran, "0 objects lost" is a
        # clean-looking result from an experiment that did not take place. Refuse it.
        say "  KEYGEN FAILED — this arm cannot answer the question"
        say "    $(grep -aiE 'error|failed' "$OUT/keygen-$2.log" | head -1)"
        echo "-1" > "$OUT/$2-lost.txt"
        return 1
    fi
    sleep 3

    inventory > "$OUT/$2-after.txt"
    local n_after; n_after="$(wc -l < "$OUT/$2-after.txt" | tr -d ' ')"
    say "  objects after the write:  $n_after"

    # Survivors, not counts: a count can stay level while an old object is replaced by the new one.
    local lost
    lost="$(comm -23 "$OUT/$2-before.txt" "$OUT/$2-after.txt" | wc -l | tr -d ' ')"
    say "  pre-existing objects LOST: $lost"
    comm -23 "$OUT/$2-before.txt" "$OUT/$2-after.txt" | head -5 | sed 's/^/    gone: /'
    echo "$lost" > "$OUT/$2-lost.txt"
    return 0
}

say "does a dangling link corrupt the next write?"
say "  image: $IMG"

run_arm "$UNPATCHED" unpatched 51 || say "  (unpatched arm did not complete)"
run_arm "$PATCHED"   patched   52 || say "  (patched arm did not complete)"

lu="$(cat "$OUT/unpatched-lost.txt" 2>/dev/null || echo -1)"
lp="$(cat "$OUT/patched-lost.txt" 2>/dev/null || echo -1)"
say ""
say "  unpatched lost: $lu"
say "  patched lost:   $lp"
say ""
if [ "$lu" -gt 0 ] 2>/dev/null && [ "$lp" = "0" ]; then
    say "RESULT=CORRUPTION_CONFIRMED_AND_FIXED"
    say "  A dangling link makes the next write destroy $lu pre-existing object(s), and the guard"
    say "  prevents it. This connects the ordering inversion to real data loss."
    echo "RESULT=CORRUPTION_CONFIRMED_AND_FIXED" > "$OUT/verdict.txt"; exit 0
elif [ "$lu" -gt 0 ] 2>/dev/null && [ "$lp" -gt 0 ] 2>/dev/null; then
    say "RESULT=CORRUPTION_CONFIRMED_GUARD_INSUFFICIENT"
    say "  The next write destroys data on BOTH builds. The corruption is real and the guard does"
    say "  not stop it — the fix is wrong, or incomplete, and must not be proposed as-is."
    echo "RESULT=CORRUPTION_CONFIRMED_GUARD_INSUFFICIENT" > "$OUT/verdict.txt"; exit 1
elif [ "$lu" = "0" ]; then
    say "RESULT=NO_CORRUPTION"
    say "  A dangling link neither bricks the card nor damages the next write. On this evidence the"
    say "  ordering inversion is real but benign, and should be reported as an observation about the"
    say "  drain — NOT as the cause of Bug 6."
    echo "RESULT=NO_CORRUPTION" > "$OUT/verdict.txt"; exit 1
else
    say "RESULT=INCONCLUSIVE (unpatched=$lu patched=$lp)"
    echo "RESULT=INCONCLUSIVE" > "$OUT/verdict.txt"; exit 1
fi
