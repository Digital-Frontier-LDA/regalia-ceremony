#!/usr/bin/env bash
# hsm-identify-firmware.sh — answer "WHICH BUILD IS ACTUALLY ON THE CARD?" by comparing the flash
# contents against every candidate ELF on disk. Requires SWD (OpenOCD + Debug Probe).
#
#   tools/hsm-identify-firmware.sh                       # check every build_*/pico_hsm.elf
#   tools/hsm-identify-firmware.sh path/to/pico_hsm.elf  # check specific ones
#   SIZE=0x40000 tools/hsm-identify-firmware.sh          # compare more/less of the image
#
# WHY THIS EXISTS.
#
# Every reliability number on this bench — reboot soaks, wedge hunts, the staging battery — is a
# statement about A BINARY. The firmware invariants script asserts the fixes exist in SOURCE, and
# the submodule pin says what a clean clone would build, but neither says a word about what is
# programmed into the device that produced the measurements.
#
# That gap is not hypothetical. On 2026-08-08 this tree held two builds:
#
#   build_pz/pico_hsm.elf    2026-08-06 19:38   predates ALL FIVE reliability fixes
#   build_rtt/pico_hsm.elf   2026-08-08 08:50   contains them
#
# and nothing recorded which one the card was running. A soak against build_pz would have measured
# unfixed firmware while every artefact around it — green invariants, a correct submodule pin, a
# careful attestation doc — said "hardened". Reproducibility paperwork that stops at the build
# directory proves nothing about the device.
#
# HOW IT DECIDES. It dumps the head of flash over SWD and compares it byte-for-byte against each
# candidate's binary image. An exact match is identity; anything else is reported as a mismatch
# rather than guessed at. A device that matches NOTHING on disk is the important answer, not an
# error — it means the running firmware came from a tree that no longer exists.
set -u

OCD_PORT="${OCD_PORT:-4444}"
FLASH_BASE="${FLASH_BASE:-0x10000000}"
SIZE="${SIZE:-0x20000}"                      # 128 KiB: well past where these builds diverge
OBJCOPY="${OBJCOPY:-$(command -v arm-none-eabi-objcopy || echo "$HOME/toolchains/arm-gnu-15.2/bin/arm-none-eabi-objcopy")}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# STRIP NULs: OpenOCD's telnet stream carries IAC negotiation bytes and a NUL after each response,
# and grep treats input containing a NUL as BINARY — so a pattern that is plainly present never
# matches. Measured 2026-08-08: a probe reading "0x40100030: 00000000" reported "cannot read the
# chip" on a healthy card every time. A check that fails constantly carries no information while
# reading exactly like a diagnosis.
ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 120; exec @ARGV' -- nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000'; }

[ -x "$OBJCOPY" ] || { echo "no arm-none-eabi-objcopy (set OBJCOPY=)" >&2; exit 2; }

# CHECK THE INSTRUMENT FIRST. A stale OpenOCD answers commands about a chip it can no longer read,
# and `dump_image` against one produces a file of zeros — which would then "identify" the firmware
# as whichever candidate happens to be mostly padding. Same failure class as the soak's dead-socket
# probe: silent, and confidently wrong.
if ! ocd "mdw 0x40100030" | LC_ALL=C grep -qaEi '40100030: *[0-9a-f]{8}'; then
    echo "REFUSING TO RUN: the debug server on port $OCD_PORT cannot read the chip." >&2
    echo "  A dump taken through a stale server is zeros, and would identify the wrong build." >&2
    exit 2
fi

# Collect candidates: explicit arguments, or every build in the firmware tree.
if [ "$#" -gt 0 ]; then
    CANDIDATES=("$@")
else
    HSM_TREE="${HSM_TREE:-$HOME/code/pico-hsm}"
    CANDIDATES=()
    for e in "$HSM_TREE"/build_*/pico_hsm.elf; do [ -f "$e" ] && CANDIDATES+=("$e"); done
fi
[ "${#CANDIDATES[@]}" -gt 0 ] || { echo "no candidate ELFs found" >&2; exit 2; }

echo "reading ${SIZE} bytes from ${FLASH_BASE} over SWD"
# Halt first: dump_image on a running core can race flash access by the firmware itself and return
# a torn image. Leaving it halted is fine here — the caller decides when to resume, and identifying
# firmware is a deliberate diagnostic act, not something that runs during a measurement.
ocd "halt
dump_image $WORK/device.bin $FLASH_BASE $SIZE" >/dev/null 2>&1

if [ ! -s "$WORK/device.bin" ]; then
    echo "FAILED: no image came back from the device" >&2
    ocd "resume" >/dev/null 2>&1
    exit 1
fi
dev_sha="$(shasum -a 256 "$WORK/device.bin" | awk '{print $1}')"
dev_size="$(wc -c < "$WORK/device.bin" | tr -d ' ')"

# An all-zero or all-0xFF dump means the read failed or the flash is blank; either way it must not
# be matched against anything.
if [ "$(LC_ALL=C tr -d '\377\000' < "$WORK/device.bin" | wc -c | tr -d ' ')" = "0" ]; then
    echo "FAILED: the dump is entirely 0x00/0xFF — the read did not reach flash" >&2
    ocd "resume" >/dev/null 2>&1
    exit 1
fi

echo "device image: $dev_size bytes, sha256 ${dev_sha:0:16}…"
echo

match=""
for elf in "${CANDIDATES[@]}"; do
    "$OBJCOPY" -O binary "$elf" "$WORK/cand.full" 2>/dev/null || { printf '  %-46s (objcopy failed)\n' "$(basename "$(dirname "$elf")")"; continue; }
    head -c "$dev_size" "$WORK/cand.full" > "$WORK/cand.bin"
    c_sha="$(shasum -a 256 "$WORK/cand.bin" | awk '{print $1}')"
    label="$(basename "$(dirname "$elf")")"
    stamp="$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$elf" 2>/dev/null)"
    if [ "$c_sha" = "$dev_sha" ]; then
        printf '  \033[32mMATCH\033[0m  %-22s %s\n' "$label" "$stamp"
        match="$elf"
    else
        printf '  ----   %-22s %s\n' "$label" "$stamp"
    fi
done

ocd "resume" >/dev/null 2>&1
echo

if [ -n "$match" ]; then
    echo "the card is running: $match"
    exit 0
fi

echo "NO CANDIDATE MATCHES the firmware on the card."
echo "  The running firmware was built from a tree that is no longer on disk, so no measurement"
echo "  taken against it can be tied to source. Reflash from a known build before measuring."
exit 1
