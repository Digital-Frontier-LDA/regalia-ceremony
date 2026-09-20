#!/usr/bin/env bash
# hsm-devaut-read.sh — print a SmartCard-HSM's device identity (C.DevAut, EF 2F02) using ONLY the
# OpenSC tools: no Java, no Smart Card Shell. Read-only — it selects the SC-HSM application and
# issues READ BINARY, so it touches no PIN and spends no retry counter.
#
# WHY IT EXISTS. Commissioning pins the device by the SHA-256 of C.DevAut (hsm-host-role/files/
# commission-card.sh, REQUIREMENTS B7): a serial is self-reported, a CHR is only a name, and the
# digest covers the device public key. Until now the only reader was hsm-devaut-id.js, which needs
# a Smart Card Shell (Java) install. That is reasonable at a ceremony and unreasonable at a rack in
# someone else's building — and a gate that cannot be evaluated where it must run is not a gate.
#
#   hsm-devaut-read.sh [--reader N] [--expect-serial DENK0404144]
#
# Output is the shape hsm-devaut-id.js emits, so either can feed commission-card.sh:
#   DEVAUT_CHR=…   DEVAUT_CAR=…   DEVAUT_SHA256=…   DEVAUT_BYTES=…   DEVAUT_HEX=…
#
# Verified byte-identical to the scsh reader on a Nitrokey HSM 2 (DENK0404144, fw 4.1, 2026-09-18);
# the emulator suite pins that blob. CHR/CAR are the same convenience tag-substring extraction the
# JS does and carry the same KNOWN LIMIT — the authoritative TR-03110 parse and chain verification
# is cvc-devaut-verify.py over DEVAUT_HEX.
set -uo pipefail

READER="" ; EXPECT_SERIAL=""
AID="E82B0601040181C31F0201"      # SmartCard-HSM application identifier
CHUNK=255                         # Le=FF

die() { printf 'hsm-devaut-read: %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --reader)        READER="${2:-}"; shift 2;;
    --expect-serial) EXPECT_SERIAL="${2:-}"; shift 2;;
    -h|--help)       sed -n '2,24p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

command -v opensc-tool >/dev/null || die "opensc-tool not found (install opensc)"
RARGS=()
[ -n "$READER" ] && RARGS=(-r "$READER")

# NAME THE CARD, DO NOT GUESS IT. With two SmartCard-HSMs attached, reading whichever reader comes
# first reports the OTHER card's identity and the check still passes, because a well-formed
# certificate from the wrong device parses perfectly (measured 2026-09-03, hsm-devaut-id.js).
if [ -n "$EXPECT_SERIAL" ]; then
  command -v pkcs15-tool >/dev/null || die "pkcs15-tool not found; cannot confirm --expect-serial"
  dump="$(pkcs15-tool ${RARGS[@]+"${RARGS[@]}"} --dump 2>/dev/null)"
  got="$(awk -F': *' '/Serial number/{print $2; exit}' <<< "$dump")"
  [ "$got" = "$EXPECT_SERIAL" ] \
    || die "this reader holds serial '${got:-<unreadable>}', not '$EXPECT_SERIAL' — refusing to report another card's identity"
fi

# Hex to bytes without xxd: xxd ships in vim-common and is NOT installed on a minimal Debian host.
# A missing xxd once produced a silently EMPTY DKEK password (qubes/scripts/hsm-auto-import.sh), so
# this path uses nothing outside bash and coreutils.
hex_to_bin() {
  local h="$1" i
  for (( i = 0; i < ${#h}; i += 2 )); do printf "%b" "\\x${h:i:2}"; done
}

# Send one APDU and print its response data as hex. A SmartCard-HSM answers a read that runs past
# the end of the file with SW 6282 ("end of file reached") AND the bytes it did have — treating
# that as an error truncated EF 2F02 at 255 bytes and produced a digest of a PREFIX, which would
# have matched nothing and failed commissioning on a genuine card. Both 9000 and 6282 carry data.
LAST_SW=""
apdu_data() {
  local out
  out="$(opensc-tool ${RARGS[@]+"${RARGS[@]}"} -s "$1" 2>&1)" || { printf '%s\n' "$out" >&2; return 1; }
  LAST_SW="$(sed -n 's/.*SW1=0x\([0-9A-Fa-f]*\), SW2=0x\([0-9A-Fa-f]*\).*/\1\2/p' <<< "$out" | tail -1)"
  case "${LAST_SW^^}" in
    9000|6282) ;;
    *) printf '%s\n' "$out" >&2; return 1;;
  esac
  awk '/^Received/ {buf=""; want=1; next}
       want && /^[0-9A-F][0-9A-F] / { s=substr($0,1,48); gsub(/[^0-9A-F]/,"",s); buf = buf s }
       END { printf "%s", buf }' <<< "$out"
}

# SELECT the application. Two encodings, because they are not interchangeable across devices: a
# Nitrokey HSM 2 answers P2=0C ("no response data"), while a Pico HSM rejects it with 6A86 and wants
# P2=00 with an Le byte. Trying only one silently limits this reader to one vendor.
apdu_data "00A4040C0B${AID}" >/dev/null \
  || apdu_data "00A404000B${AID}00" >/dev/null \
  || die "could not select the SmartCard-HSM application (is a card inserted? is pcscd running? is this a SmartCard-HSM?)"

hex=""
off=0
while :; do
  # READ BINARY, odd instruction B1, with an offset data object: 54 02 <offset, big-endian>.
  chunk="$(apdu_data "$(printf '00B12F0204540%s%02X%02X%02X' 2 $(( (off >> 8) & 0xFF )) $(( off & 0xFF )) "$CHUNK")")" || break
  [ -n "$chunk" ] || break
  hex="$hex$chunk"
  n=$(( ${#chunk} / 2 ))
  [ "${LAST_SW^^}" = "6282" ] && break     # the card said that was the end of the file
  [ "$n" -lt "$CHUNK" ] && break
  off=$(( off + n ))
  [ "$off" -gt 8192 ] && die "EF 2F02 exceeds 8 KiB — refusing to keep reading"
done

[ -n "$hex" ] || die "EF 2F02 read back empty — this card exposes no C.DevAut"

# Convenience TLV extraction, mirroring hsm-devaut-id.js: 5F20 = Certificate Holder Reference,
# 42 = Certificate Authority Reference. First occurrence only — EF 2F02 holds the device
# certificate followed by its issuer's, and the device's own references come first.
tlv_ascii() {
  local tag="$1" rest len
  case "$hex" in *"$tag"*) rest="${hex#*"$tag"}";; *) return 0;; esac
  len=$(( 16#${rest:0:2} ))
  { [ "$len" -gt 0 ] && [ "$len" -le 64 ]; } || return 0
  hex_to_bin "${rest:2:$(( len * 2 ))}" | tr -cd '[:print:]'
}

printf 'DEVAUT_CHR=%s\n' "$(tlv_ascii 5F20)"
printf 'DEVAUT_CAR=%s\n' "$(tlv_ascii 42)"
printf 'DEVAUT_SHA256=%s\n' "$(hex_to_bin "$hex" | sha256sum | awk '{print $1}')"
printf 'DEVAUT_BYTES=%s\n' "$(( ${#hex} / 2 ))"
printf 'DEVAUT_HEX=%s\n' "$hex"
