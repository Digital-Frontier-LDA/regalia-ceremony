#!/usr/bin/env bash
# hsm-key-attestation-read.sh — print a SmartCard-HSM KEY ATTESTATION (EF CE<keyref>) using ONLY
# the OpenSC tools: no Java, no Smart Card Shell. Read-only — it selects the SC-HSM application and
# issues READ BINARY, so it touches no PIN and spends no retry counter.
#
# WHY IT EXISTS. regalia-kms identifies a custody key by device serial plus the SHA-256 of the key's
# SubjectPublicKeyInfo (ADR-0002 D1, regalia-kms#26). The daemon speaks PKCS#11 only, and PKCS#11
# cannot reach the two files that prove WHERE that key came from: the device certificate (EF 2F02)
# and the authenticated request GENERATE ASYMMETRIC KEY PAIR left in EF CE<keyref>, signed by the
# device key PrK.DevAut. CKA_LOCAL cannot stand in for them on an SC-HSM (#447). So provenance —
# "this key was generated on THIS genuine card" — is proven ONCE, at commissioning, from these two
# files, and the public-key pin is what carries that result into the daemon. This reads the second
# file; hsm-devaut-read.sh reads the first; hsm-key-attestation-verify.py checks one against the
# other.
#
#   hsm-key-attestation-read.sh --key-ref N [--reader N] [--expect-serial DENK0404144]
#
# --key-ref is the SC-HSM KEY REFERENCE (1..255), NOT the PKCS#11 CKA_ID. They are different
# numbers: on DENK0404144 the key with CKA_ID 0a lives at key reference 1, so its attestation is
# EF CE01. `pkcs15-tool --list-keys` prints both ("Key ref" and "ID") for the private key. Reading
# the wrong EF is not dangerous — the verifier's --expect-point refuses an attestation for another
# key — but it is the first thing to check when that refusal appears.
#
# Output:
#   ATTEST_KEY_REF=1   ATTEST_FID=CE01   ATTEST_SHA256=…   ATTEST_BYTES=…   ATTEST_HEX=…
#
# FAILS CLOSED. Exit 2 with a named reason on: a missing EF (SW 6A82 — no key at that reference, or
# a key that was IMPORTED rather than generated, which leaves no attestation), a failed read at any
# offset, an empty file, or a card that is not the one named by --expect-serial. It never prints a
# partial file as if it were the whole one. Parsing and signature checking are deliberately NOT done
# here: that is hsm-key-attestation-verify.py's job, and a second parser is a second place to be
# wrong.
set -uo pipefail

READER="" ; EXPECT_SERIAL="" ; KEY_REF=""
AID="E82B0601040181C31F0201"      # SmartCard-HSM application identifier
CHUNK=255                         # Le=FF
MAX_BYTES=8192

die() { printf 'hsm-key-attestation-read: %s\n' "$*" >&2; exit 2; }
need_val() { [ "$#" -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --reader)        need_val "$1" "${2-}"; READER="$2"; shift 2;;
    --expect-serial) need_val "$1" "${2-}"; EXPECT_SERIAL="$2"; shift 2;;
    --key-ref)       need_val "$1" "${2-}"; KEY_REF="$2"; shift 2;;
    -h|--help)       sed -n '2,32p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

# A KEY REFERENCE IS ONE BYTE, AND 0 IS NOT ONE. Decimal only: "10" meaning ten and "10" meaning
# sixteen is exactly the confusion between a key reference and a hex CKA_ID this flag has to avoid,
# so the flag accepts one notation and refuses the rest rather than guessing.
[ -n "$KEY_REF" ] || die "--key-ref is required (the SC-HSM key reference, 1..255; see pkcs15-tool --list-keys)"
case "$KEY_REF" in
  *[!0-9]*|0*) die "--key-ref '$KEY_REF' is not a decimal key reference 1..255 (no leading zeros, no hex)";;
esac
[ "$KEY_REF" -ge 1 ] && [ "$KEY_REF" -le 255 ] \
  || die "--key-ref '$KEY_REF' is out of range — an SC-HSM key reference is 1..255"
FID="$(printf 'CE%02X' "$KEY_REF")"

command -v opensc-tool >/dev/null || die "opensc-tool not found (install opensc)"
RARGS=()
[ -n "$READER" ] && RARGS=(-r "$READER")

# NAME THE CARD, DO NOT GUESS IT. Same reason as hsm-devaut-read.sh: with two SmartCard-HSMs
# attached, a well-formed attestation from the WRONG device verifies perfectly against that device's
# own certificate, and the only thing that then catches it is a pin nobody has recorded yet —
# because this is the step that records it.
if [ -n "$EXPECT_SERIAL" ]; then
  command -v pkcs15-tool >/dev/null || die "pkcs15-tool not found; cannot confirm --expect-serial"
  dump="$(pkcs15-tool ${RARGS[@]+"${RARGS[@]}"} --dump 2>/dev/null)"
  got="$(awk -F': *' '/Serial number/ && !seen {print $2; seen = 1}' <<< "$dump")"
  [ "$got" = "$EXPECT_SERIAL" ] \
    || die "this reader holds serial '${got:-<unreadable>}', not '$EXPECT_SERIAL' — refusing to read another card's attestation"
fi

hex_to_bin() {
  local h="$1" i
  for (( i = 0; i < ${#h}; i += 2 )); do printf "%b" "\\x${h:i:2}"; done
}

# Send one APDU and print "<SW> <response data as hex>" — the status word travels WITH the data,
# for the reason hsm-devaut-read.sh gives (a global set inside a command substitution never reaches
# the parent, and "end of file" becomes indistinguishable from "read failed").
#
# ONLY SELECT AND READ BINARY LEAVE THIS FUNCTION. This script is run against cards that already
# hold production keys, at a rack, by someone following a runbook. The allow-list makes "it never
# presents a PIN and never writes" a property of the code rather than of whoever edits it next: a
# VERIFY (0020), UPDATE BINARY (00D6/00D7) or anything else is refused before opensc-tool sees it.
apdu_data() {
  local out sw data
  case "${1^^}" in
    00A40400*|00B1*) ;;
    *) printf 'hsm-key-attestation-read: REFUSING to send APDU %s — only SELECT and READ BINARY are allowed here\n' "$1" >&2
       return 1;;
  esac
  out="$(opensc-tool ${RARGS[@]+"${RARGS[@]}"} -s "$1" 2>&1)" || { printf '%s\n' "$out" >&2; return 1; }
  sw="$(sed -n 's/.*SW1=0x\([0-9A-Fa-f]*\), SW2=0x\([0-9A-Fa-f]*\).*/\1\2/p' <<< "$out" | tail -1)"
  sw="${sw^^}"
  data="$(awk '/^Received/ {buf=""; want=1; row=0; next}
               want && /^[0-9A-F][0-9A-F] / {
                 row++
                 n = (row == 1) ? int(length($0) / 4) : int((length($0) - 16) / 3)
                 s=substr($0,1,3*n); gsub(/[^0-9A-F]/,"",s); buf = buf s
               }
               END { printf "%s", buf }' <<< "$out")"
  printf '%s %s' "${sw:-????}" "$data"
  case "$sw" in
    9000|6282) return 0;;
    *) printf '%s\n' "$out" >&2; return 1;;
  esac
}

# SELECT with P2=00 and an Le byte. hsm-devaut-read.sh tries P2=0C first because it predates the
# measurement; P2=00 + Le is accepted by BOTH a Nitrokey HSM 2 (DENK0404144, 2026-09-23) and a Pico
# HSM (which rejects P2=0C with 6A86), so one encoding serves both and there is no fallback path to
# get wrong.
apdu_data "00A404000B${AID}00" >/dev/null 2>&1 \
  || die "could not select the SmartCard-HSM application (is a card inserted? is pcscd running? is this a SmartCard-HSM?)"

hex=""
off=0
while :; do
  # READ BINARY, odd instruction B1, file id in P1/P2, offset data object 54 02 <offset, big-endian>.
  resp="$(apdu_data "$(printf '00B1%s04540%s%02X%02X%02X' "$FID" 2 $(( (off >> 8) & 0xFF )) $(( off & 0xFF )) "$CHUNK")")" || {
    sw="${resp%% *}"
    # A MISSING FILE HAS ITS OWN NAME. 6A82 at offset 0 means there is no attestation at this key
    # reference: no key there, the wrong reference, or a key that was IMPORTED (UNWRAP KEY writes no
    # CExx). The last one is exactly what commissioning exists to refuse, so it is named, not
    # reported as a generic I/O error an operator would retry.
    if [ "$off" -eq 0 ] && [ "$sw" = "6A82" ]; then
      die "EF $FID does not exist (SW 6A82) — no attestation at key reference $KEY_REF: wrong --key-ref, no key there, or an IMPORTED key (only on-card generation leaves one)"
    fi
    # A FAILED READ IS NOT THE END OF THE FILE. Hashing what arrived is the one outcome this reader
    # must never produce.
    die "READ BINARY of EF $FID at offset $off answered SW ${sw:-????} — refusing to report a partial attestation"
  }
  sw="${resp%% *}"
  chunk="${resp#* }"
  [ -n "$chunk" ] || break
  hex="$hex$chunk"
  n=$(( ${#chunk} / 2 ))
  [ "$sw" = "6282" ] && break               # the card said that was the end of the file
  [ "$n" -lt "$CHUNK" ] && break
  off=$(( off + n ))
  [ "$off" -gt "$MAX_BYTES" ] && die "EF $FID exceeds 8 KiB — refusing to keep reading"
done

[ -n "$hex" ] || die "EF $FID read back empty — no attestation at key reference $KEY_REF"

printf 'ATTEST_KEY_REF=%s\n' "$KEY_REF"
printf 'ATTEST_FID=%s\n' "$FID"
printf 'ATTEST_SHA256=%s\n' "$(hex_to_bin "$hex" | sha256sum | awk '{print $1}')"
printf 'ATTEST_BYTES=%s\n' "$(( ${#hex} / 2 ))"
printf 'ATTEST_HEX=%s\n' "$hex"
