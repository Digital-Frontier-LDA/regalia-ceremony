#!/usr/bin/env bash
# hsm-usb-delay-sweep.sh — measure how long the USB presentation delay actually needs to be.
#
#   ./tools/hsm-usb-delay-sweep.sh [reboots-per-arm] [outdir]
#
# WHY A SWEEP AND NOT A GUESS.
#
# The wedge is a USB re-enumeration race. It was identified by varying boot time indirectly, through
# file count:
#
#     66 objects   boot 6.30s   wedge rate  4.0%   (14/347)
#      0 objects   boot 3.98s   wedge rate 13.0%   (7/54)      z = 2.74, p < 0.01
#
# From that I picked a 250 ms hold before tusb_init(). That was a guess dressed as a fix, and it was
# roughly 11% of the 2.32-SECOND boot difference the effect was actually derived from. The A/B that
# followed was also confounded — the two arms ran at different file counts, which is the very
# variable driving the rate — so it measured nothing.
#
# This sweeps the delay itself at a FIXED file count, which is the only way to see where the rate
# turns over. Then the shipped value is that knee plus a buffer, rather than a number someone liked.
#
# DESIGN NOTES THAT MATTER
#
#   * File count is held constant and RECORDED per arm. It is the known confounder; an arm that
#     drifts is not comparable and says so in the output rather than being averaged in.
#   * Arms are run in a fixed order but the ZERO-DELAY arm is repeated at the END. If the two
#     zero-delay arms disagree, something drifted over the run — bench temperature, flash wear, host
#     USB state — and the whole sweep is suspect. Without that control a monotonic trend could be
#     drift rather than the delay.
#   * Each arm is a separate BUILD, because the delay is a compile-time constant. The build is
#     verified to contain the value it claims before the arm runs; flashing the wrong binary and
#     attributing its rate to a delay would be the same class of error as the confounded A/B.
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
N="${1:-200}"
OUT="${2:-$HOME/.local/share/akash-hsm-staging/delay-sweep-$(date +%Y%m%d-%H%M%S)}"
PICO="${HSM_PICO_DIR:-$HOME/code/pico-hsm}"
BUILD="${HSM_BUILD_DIR:-build_pz}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
mkdir -p "$OUT"

# IDENTITY + ROLE INTERLOCK — the hsm-quiesce.sh pattern, now mandatory for every flash tool.
# This script PROGRAMS FLASH on every arm. Before this gate it flashed whatever board the DEFAULT
# probe found — no probe serial, no OTP check, no role check — so a second board on the bench, or
# a card that matters, got rewritten by accident of OpenOCD's probe order. Now: --probe names the
# probe, the board it reaches is proven by its OTP id, and that board must be registered staging
# through HSM_BOARD_MAP and the committed role registry. All of it is required; absence refuses.
# shellcheck source=/dev/null
. "$REPO/tools/hsm-reader-select.sh"
hsm_verify_board_over_probe "$PROBE" "$EXPECT_BOARD" || exit 2
hsm_assert_staging_board "$EXPECT_BOARD" || exit 2

# 0 first as the baseline, then increasing, then 0 AGAIN as the drift control.
DELAYS="${HSM_DELAY_SWEEP:-0 500 1000 2000 3000 0}"

say(){ printf '%s\n' "$*"; }
say "USB presentation delay sweep"
say "  $N reboots per arm, delays: $DELAYS"
say "  artifacts: $OUT"
say ""

objcount(){
    perl -e 'alarm 90; exec @ARGV' -- pkcs11-tool \
        --module "${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}" \
        --login --pin "${HSM_USER_PIN:-648219}" --list-objects 2>/dev/null \
        | grep -c 'Key Object'
}

arm=0
for d in $DELAYS; do
    arm=$((arm + 1))
    tag="$(printf 'arm%02d-delay%sms' "$arm" "$d")"
    say "=== $tag ==="

    # BUILD WITH THIS DELAY, AND PROVE THE BINARY CARRIES IT.
    # Reconfigure with the board set explicitly. A bare `cmake -S . -B` against a build dir whose
    # cache has been disturbed fails with "could not find CMAKE_PROJECT_NAME in Cache", which is how
    # the first attempt at this sweep lost all six arms.
    # PIN THE TOOLCHAIN. Homebrew's arm-none-eabi-gcc 16.1.0 is installed and CANNOT build this
    # tree — it ships without newlib, so every compile dies on "stdint.h: No such file". The working
    # toolchain is arm-gnu-15.2, and the only reason builds succeeded before was that an old cache
    # remembered it. Deleting that cache during debugging cost a full rebuild to rediscover.
    ( cd "$PICO" \
      && PICO_SDK_PATH="${PICO_SDK_PATH:-$HOME/pico-sdk}" \
         PICO_TOOLCHAIN_PATH="${HSM_TOOLCHAIN:-$HOME/toolchains/arm-gnu-15.2}" \
         cmake -S . -B "$BUILD" \
              -DPICO_BOARD="${HSM_PICO_BOARD:-waveshare_rp2350_pizero}" \
              -DPICO_TOOLCHAIN_PATH="${HSM_TOOLCHAIN:-$HOME/toolchains/arm-gnu-15.2}" \
              -DPICOKEY_USB_PRESENT_DELAY_MS="$d" \
      && cmake --build "$BUILD" -j8 ) > "$OUT/$tag.build.log" 2>&1
    if ! grep -qa 'Built target pico_hsm' "$OUT/$tag.build.log"; then
        say "  BUILD FAILED — skipping this arm (see $tag.build.log)"
        continue
    fi

    # PROVE THIS ARM'S BINARY DIFFERS FROM THE OTHERS, BY CHECKSUM.
    #
    # The first version grepped the disassembly for "#<delay>" and rejected every non-zero arm.
    # busy_wait_ms(500) does not put 500 in the instruction stream — the constant is converted, so
    # the literal never appears. That check produced false NEGATIVES for four arms and a false
    # POSITIVE for one (an unrelated #2000 happened to match), which is worse than no check.
    #
    # A checksum answers the question that actually matters: did this arm flash a DIFFERENT binary
    # than the others? Verified by hand — delays 0/500/2000 give three distinct md5s. If two arms
    # share a checksum they are the same firmware and their rates cannot be compared.
    bin_md5="$(md5 -q "$PICO/$BUILD/pico_hsm.elf" 2>/dev/null \
               || md5sum "$PICO/$BUILD/pico_hsm.elf" | cut -d' ' -f1)"
    if grep -q "md5=$bin_md5" "$OUT/RESULTS" 2>/dev/null; then
        say "  DUPLICATE BINARY (md5 $bin_md5) — this arm is the same firmware as an earlier one"
        say "  Refusing to record it as a distinct delay."
        continue
    fi
    say "  binary md5: $bin_md5"

    pkill -f "$(basename "$OCD_BIN")" 2>/dev/null; sleep 2
    perl -e 'alarm 240; exec @ARGV' -- "$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
        -c "adapter speed 5000" \
        -c "program $PICO/$BUILD/pico_hsm.elf verify reset exit" > "$OUT/$tag.flash.log" 2>&1
    if ! grep -qa 'Verified OK' "$OUT/$tag.flash.log"; then
        say "  FLASH FAILED — skipping this arm"
        continue
    fi
    sleep 14

    n_obj="$(objcount)"
    say "  file count: ${n_obj:-unknown} objects"

    HSM_REPO="$REPO" HSM_WEDGE_SNAPSHOT='' HSM_RECOVER_CMD="$REPO/tools/hsm-swd-powman-recover.sh" \
        perl -e "alarm $((N * 40 + 600)); exec @ARGV" -- "$REPO/tools/hsm-reboot-soak.sh" "$N" 90 \
        > "$OUT/$tag.soak.log" 2>&1

    c="$(grep -acE 'BACK in' "$OUT/$tag.soak.log")"
    w="$(grep -acE 'DID NOT COME BACK' "$OUT/$tag.soak.log")"
    tot=$((c + w))
    rate="$(python3 -c "print(f'{100*$w/$tot:.1f}' if $tot else 'n/a')")"
    boot="$(python3 -c "
import re,statistics
v=[int(m) for m in re.findall(r'BACK in\s+(\d+)s', open('$OUT/$tag.soak.log',errors='ignore').read())]
print(f'{statistics.mean(v):.2f}' if v else 'n/a')")"

    printf '%s delay=%sms objects=%s reboots=%s wedges=%s rate=%s%% meanboot=%ss md5=%s\n' \
        "$tag" "$d" "${n_obj:-?}" "$tot" "$w" "$rate" "$boot" "$bin_md5" >> "$OUT/RESULTS"
    say "  -> $w/$tot wedges = ${rate}%   mean boot ${boot}s"
    say ""
done

say "=== SWEEP COMPLETE ==="
cat "$OUT/RESULTS" 2>/dev/null
say ""
say "READ THE TWO ZERO-DELAY ARMS FIRST. If they disagree, the bench drifted during the sweep and"
say "the trend between them is not attributable to the delay. Check the objects= column too: file"
say "count is the known confounder, and an arm that drifted is not comparable."
