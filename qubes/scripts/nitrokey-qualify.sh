#!/usr/bin/env bash
# nitrokey-qualify.sh — qualify a SmartCard-HSM (Nitrokey HSM 2) with the OpenSC tools already in the
# vault-tools TemplateVM, so a Qubes vault AppVM can answer the two D1-gated questions without a Go
# toolchain:
#
#   #448  Does the token expose its device-authentication certificate as a PKCS#11 CKO_CERTIFICATE?
#         The daemon's identity probe hashes exactly one such object; on the staging Pico through
#         OpenSC it found none and the daemon refused the card before login.
#   #447  Does a key GENERATED on the token report CKA_LOCAL true? The wrap guard admits a KEK only
#         when its public half is `local`; on the Pico it was false for every key.
#
# Default is READ-ONLY: it lists objects, counts certificates, and reports CKA_LOCAL per public key.
# It spends no PIN. --provision (destructive) initialises the card and generates a secp256k1 key so
# #447 can be measured on a genuinely card-generated key; it is gated behind an explicit flag because
# it WIPES the device.
#
# The token is chosen by SERIAL, never by slot/reader index: two identical HSMs make index selection
# aim at the wrong card (measured on the bench), so a serial that does not resolve to exactly one
# token is a refusal.
set -uo pipefail

MODULE="${HSM_PKCS11_MODULE:-}"
SERIAL="" ; PROVISION=0 ; CONFIRM_WIPE=0 ; PIN="${HSM_USER_PIN:-}" ; SO_PIN="${HSM_SO_PIN:-}"
OBJ_ID="${HSM_QUAL_OBJECT_ID:-01}"

usage() { sed -n '2,20p' "$0"; }
die()   { printf 'nitrokey-qualify: %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --module)      MODULE="$2"; shift 2;;
    --serial)      SERIAL="$2"; shift 2;;
    --object-id)   OBJ_ID="$2"; shift 2;;
    --pin)         PIN="$2"; shift 2;;
    --so-pin)      SO_PIN="$2"; shift 2;;
    --provision)   PROVISION=1; shift;;
    --i-understand-this-wipes-the-card) CONFIRM_WIPE=1; shift;;
    -h|--help)     usage; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

command -v pkcs11-tool >/dev/null || die "pkcs11-tool not found (install opensc)"
[ -n "$MODULE" ] || for c in /usr/lib/*/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so /opt/homebrew/lib/opensc-pkcs11.so; do [ -f "$c" ] && { MODULE="$c"; break; }; done
[ -n "$MODULE" ] && [ -f "$MODULE" ] || die "PKCS#11 module not found; pass --module PATH"
[ -n "$SERIAL" ] || die "REFUSING: no --serial. This qualifies a specific token and never guesses which."

# Resolve the token's PKCS#11 slot by matching the serial in `-L`, so selection cannot drift to the
# other HSM. Exactly one match is required.
mapfile -t SLOTS < <(pkcs11-tool --module "$MODULE" -L 2>/dev/null | awk -v want="$SERIAL" '
  /^Slot [0-9]/ { slot=$2; sub(/[()]/,"",slot) }
  /serial num/  { s=$0; sub(/.*serial num[^:]*: */,"",s); gsub(/[ \t]+$/,"",s); if (s==want) print slot }')
[ "${#SLOTS[@]}" -eq 1 ] || die "serial '$SERIAL' resolves to ${#SLOTS[@]} tokens on $MODULE, want exactly 1 (is the card connected? another HSM sharing the serial?)"
SLOT="${SLOTS[0]}"
P11=(pkcs11-tool --module "$MODULE" --slot-index "$SLOT")

printf '### nitrokey-qualify — token serial %s, slot %s, module %s\n' "$SERIAL" "$SLOT" "$MODULE"

# ---- #448: device certificate as a PKCS#11 CKO_CERTIFICATE ------------------------------------
cert_count="$("${P11[@]}" --list-objects --type cert 2>/dev/null | grep -c 'Certificate Object' || true)"
if [ "${cert_count:-0}" -ge 1 ]; then
  printf '#448 device certificate: %s CKO_CERTIFICATE object(s) present -- the daemon identity probe CAN read it here\n' "$cert_count"
else
  printf '#448 device certificate: none exposed as a PKCS#11 CKO_CERTIFICATE -- the daemon identity probe would refuse (same as the Pico); it needs the EF 2F02 APDU fallback\n'
fi

# ---- #447: CKA_LOCAL per public key ----------------------------------------------------------
# pkcs11-tool prints "Access: local" for a public key whose CKA_LOCAL is true. Count pubkeys and the
# ones marked local; a card-generated key must be local, an imported one must not be.
pubkeys="$("${P11[@]}" --list-objects --type pubkey 2>/dev/null)"
total="$(grep -c 'Public Key Object' <<< "$pubkeys" || true)"
local_yes="$(grep -c 'Access:[[:space:]]*local' <<< "$pubkeys" || true)"
printf '#447 public keys: %s total, %s report CKA_LOCAL=true\n' "${total:-0}" "${local_yes:-0}"
if [ "${total:-0}" -eq 0 ]; then
  printf '     (no keys on the card yet; run with --provision to generate one and measure #447 on it)\n'
fi

if [ "$PROVISION" != 1 ]; then
  printf '### read-only qualification complete (no PIN spent, card unchanged)\n'
  exit 0
fi

# ---- destructive provisioning (authorized) ---------------------------------------------------
[ "$CONFIRM_WIPE" = 1 ] || die "--provision WIPES the card; pass --i-understand-this-wipes-the-card to proceed"
command -v sc-hsm-tool >/dev/null || die "sc-hsm-tool not found (install opensc)"
[ -n "$PIN" ]    || die "--pin (or HSM_USER_PIN) required for --provision"
[ -n "$SO_PIN" ] || die "--so-pin (or HSM_SO_PIN) required for --provision"

# sc-hsm-tool addresses readers by name/index, not by PKCS#11 slot. Resolve the reader whose card
# carries our serial, so the wipe cannot land on the other HSM.
reader=""
readers_n="$(opensc-tool --list-readers 2>/dev/null | grep -cE '^[0-9]+ ' || true)"
for r in $(seq 0 $(( ${readers_n:-1} - 1 )) 2>/dev/null); do
  atr_serial="$(pkcs15-tool --reader "$r" --dump 2>/dev/null | awk -F': *' '/Serial number/{print $2; exit}')"
  [ "$atr_serial" = "$SERIAL" ] && { reader="$r"; break; }
done
[ -n "$reader" ] || die "could not resolve serial '$SERIAL' to a reader for sc-hsm-tool; refusing to --initialize by index"

printf '### provisioning: WIPING and re-initialising serial %s at reader %s\n' "$SERIAL" "$reader"
sc-hsm-tool --reader "$reader" --initialize --so-pin "$SO_PIN" --pin "$PIN" --dkek-shares 1 --label nitrokey-qual \
  || die "sc-hsm-tool --initialize failed"
# Re-resolve the slot (re-init can renumber) and generate a key ON the card.
mapfile -t SLOTS < <(pkcs11-tool --module "$MODULE" -L 2>/dev/null | awk -v want="$SERIAL" '
  /^Slot [0-9]/ { slot=$2; sub(/[()]/,"",slot) }
  /serial num/  { s=$0; sub(/.*serial num[^:]*: */,"",s); gsub(/[ \t]+$/,"",s); if (s==want) print slot }')
[ "${#SLOTS[@]}" -eq 1 ] || die "after init, serial '$SERIAL' resolves to ${#SLOTS[@]} tokens"
SLOT="${SLOTS[0]}"; P11=(pkcs11-tool --module "$MODULE" --slot-index "$SLOT")
HSM_QUAL_PIN="$PIN" "${P11[@]}" --login --pin env:HSM_QUAL_PIN --keypairgen --key-type EC:secp256k1 --id "$OBJ_ID" --label nitrokey-qual \
  || die "on-card keypair generation failed"

# Re-measure #447 on the key we just generated ON the card.
gen="$("${P11[@]}" --list-objects --type pubkey 2>/dev/null)"
if grep -q 'Access:[[:space:]]*local' <<< "$gen"; then
  printf '#447 RESULT: a key generated on this token reports CKA_LOCAL=true -- the wrap guard ADMITS it\n'
else
  printf '#447 RESULT: a key generated on this token does NOT report CKA_LOCAL=true -- the wrap guard would REFUSE every KEK here (as on the Pico); provenance must come from attestation\n'
fi
printf '### provisioning qualification complete. Restore staging posture before use.\n'
