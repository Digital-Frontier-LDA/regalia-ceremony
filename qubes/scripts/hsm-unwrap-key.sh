#!/usr/bin/env bash
# hsm-unwrap-key.sh — import a DKEK-wrapped key onto a SmartCard-HSM with OpenSC alone, and write
# the PKCS#15 description without which no PKCS#11 consumer can see it. regalia#486 step 2.
#
# WHAT IT REPLACES. hsm-auto-import.js did three things with a Java Smart Card Shell: build the key
# blob, UNWRAP it, and write the PrKD. The blob is now built by hsm-dkek-encode-key.py; this sends
#
#     80 74 <key id> 93 <blob>      UNWRAP KEY
#     00 D7 C4 <key id> 54 02 0000 53 <len> <PrKD>
#
# UNWRAP KEY STORES THE KEY AND NOTHING ELSE. OpenSC's sc-hsm emulation enumerates private keys
# from their PKCS#15 description in EF C4xx, so a bare unwrap is invisible to every PKCS#11
# consumer, logged in or not — measured on DENK0404144 2026-09-17: after the unwrap the card held
# only CC01 and `pkcs11-tool --login --list-objects` listed no private key at all. The description
# is not decoration; it is the half that makes the key usable.
#
#   HSM_USER_PIN=… hsm-unwrap-key.sh --reader 0 --key-id 2 --blob funding-wrapped.bin \
#                                    --label akash-funding [--key-size 256]
#
# THE PIN NEVER REACHES argv, for the reason hsm-init-hardened.sh gives: the APDUs go to
# opensc-explorer on stdin, and the child runs without the PIN in its environment.
set -uo pipefail

READER="" ; KEY_ID="" ; BLOB="" ; LABEL="" ; KEY_SIZE="256"
AID="E82B0601040181C31F0201"

die(){ printf 'hsm-unwrap-key: %s\n' "$*" >&2; exit 2; }
say(){ printf '  %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --reader)   READER="${2:-}"; shift 2;;
    --key-id)   KEY_ID="${2:-}"; shift 2;;
    --blob)     BLOB="${2:-}"; shift 2;;
    --label)    LABEL="${2:-}"; shift 2;;
    --key-size) KEY_SIZE="${2:-}"; shift 2;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

command -v opensc-explorer >/dev/null || die "opensc-explorer not found (install opensc)"
[ -n "$READER" ] || die "--reader is required"
[ -n "$BLOB" ] && [ -r "$BLOB" ] || die "--blob must name a readable key blob"
[ -n "$LABEL" ] || die "--label is required: it is what PKCS#11 consumers match the key by"
[ -n "${HSM_USER_PIN:-}" ] || die "HSM_USER_PIN is required (UNWRAP KEY needs the user PIN verified)"
case "$KEY_ID" in ""|*[!0-9]*) die "--key-id must be a number (1-255)";; esac
[ "$KEY_ID" -ge 1 ] && [ "$KEY_ID" -le 255 ] || die "--key-id must be between 1 and 255"
case "$KEY_SIZE" in *[!0-9]*|"") die "--key-size must be a number of bits";; esac
grep -qE '^[0-9]{6,16}$' <<< "$HSM_USER_PIN" || die "HSM_USER_PIN must be 6-16 digits"
[ "${#LABEL}" -le 100 ] || die "--label is too long for a short APDU"

ascii_hex(){ printf '%s' "$1" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F'; }
tlv(){ printf '%s%02X%s' "$1" "$(( ${#2} / 2 ))" "$2"; }

blob_hex="$(od -An -tx1 "$BLOB" | tr -d ' \n' | tr 'a-f' 'A-F')"
blob_len=$(( ${#blob_hex} / 2 ))
[ "$blob_len" -gt 32 ] || die "$BLOB is only $blob_len bytes — that is not a key blob"

# The PKCS#15 PrivateECCKey description SmartCardHSM.buildPrkDforECC builds:
#   A0 { SEQUENCE { UTF8String label }, SEQUENCE { OCTET STRING keyid, BIT STRING 07 20 80 },
#        A1 { SEQUENCE { SEQUENCE { OCTET STRING "" }, INTEGER keysize } } }
size_hex="$(printf '%04X' "$KEY_SIZE")"
size_hex="${size_hex#"${size_hex%%[!0]*}"}"          # strip leading zeros …
[ $(( ${#size_hex} % 2 )) -eq 0 ] || size_hex="0$size_hex"
case "$size_hex" in [89ABCDEFabcdef]*) size_hex="00$size_hex";; esac   # … and keep INTEGER positive
prkd_label="$(tlv 30 "$(tlv 0C "$(ascii_hex "$LABEL")")")"
prkd_id="$(tlv 30 "$(tlv 04 "$(printf '%02X' "$KEY_ID")")$(tlv 03 "072080")")"
prkd_attr="$(tlv A1 "$(tlv 30 "$(tlv 30 "$(tlv 04 "")")$(tlv 02 "$size_hex")")")"
prkd="$(tlv A0 "$prkd_label$prkd_id$prkd_attr")"

pin_hex="$(ascii_hex "$HSM_USER_PIN")"
verify_apdu="00200081$(printf '%02X' "$(( ${#pin_hex} / 2 ))")$pin_hex"
# Extended Lc (00 hi lo): a 363-byte EC blob does not fit a short APDU.
unwrap_apdu="$(printf '8074%02X9300%04X%s' "$KEY_ID" "$blob_len" "$blob_hex")"
prkd_data="54020000$(tlv 53 "$prkd")"
prkd_apdu="00D7C4$(printf '%02X' "$KEY_ID")$(printf '%02X' "$(( ${#prkd_data} / 2 ))")$prkd_data"

say "unwrapping $blob_len bytes into key id $KEY_ID as '$LABEL'"
out="$(printf 'apdu 00A4040C0B%s\napdu %s\napdu %s\napdu %s\nquit\n' \
        "$AID" "$verify_apdu" "$unwrap_apdu" "$prkd_apdu" \
       | env -u HSM_USER_PIN perl -e 'alarm 120; exec @ARGV' -- opensc-explorer -r "$READER" 2>&1)" || true
mapfile -t SW < <(sed -n 's/.*SW1=0x\([0-9A-Fa-f]*\), SW2=0x\([0-9A-Fa-f]*\).*/\1\2/p' <<< "$out" | tr 'a-f' 'A-F')

# Four answers, in order, and each one is named: a run that reports success while the PIN was
# refused or the description never landed is the failure this whole path keeps producing.
[ "${SW[0]:-}" = "9000" ] || { printf '%s\n' "$out" | tail -4 >&2; die "could not select the SmartCard-HSM application (${SW[0]:-no answer})"; }
case "${SW[1]:-}" in
  9000) say "user PIN verified" ;;
  63C*) die "the user PIN was REFUSED (${SW[1]}) — ${SW[1]#63C} attempt(s) left. Nothing was written." ;;
  *)    die "VERIFY answered ${SW[1]:-no answer}; the key was NOT unwrapped" ;;
esac
[ "${SW[2]:-}" = "9000" ] || die "UNWRAP KEY answered ${SW[2]:-no answer} — the blob was rejected (a KCV mismatch means the card holds a different DKEK)"
say "UNWRAP KEY: 9000 — the card accepted the blob"
[ "${SW[3]:-}" = "9000" ] || die "the key is on the card at id $KEY_ID, but its PKCS#15 description (EF C4$(printf '%02X' "$KEY_ID")) answered ${SW[3]:-no answer}. No PKCS#11 consumer will see it until that is written."
say "PrKD written to EF C4$(printf '%02X' "$KEY_ID") — the key is enumerable"
