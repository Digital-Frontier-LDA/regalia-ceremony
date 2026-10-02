#!/usr/bin/env bash
# hsm-signing-key.sh — a signing key GENERATED ON an offline SmartCard-HSM (Nitrokey HSM 2), with its
# certificate and its DKEK-wrapped backup; and the proof that the backup restores and signs on the spare.
# regalia#554 (regalia-kms#57: the two PCR keys and the Secure Boot key of the KMS hosts' boot image).
#
#   hsm-signing-key.sh generate --serial SERIAL --id HEX --label LABEL --subject "COMMON NAME" --out DIR
#                               [--days N] [--pin-fd N]
#   hsm-signing-key.sh restore  --serial SPARE_SERIAL --blob LABEL.wrapped.bin --certificate LABEL.crt.pem
#                               [--pin-fd N]
#
# CUSTODY, ADR-0002 D19: "a new HSM key: generated on the token; its DKEK-wrapped blob is its backup."
# The key is never outside a card. The signing HSM and its spare share a DKEK of their own, used by
# nothing else (regalia#554): a card holding the KMS hosts' DKEK cannot unwrap these blobs, so an
# image-signing key can never be restored onto an online host. That DKEK's share is a software secret
# under the break-glass key; this script does not handle it (the card must already hold the DKEK).
#
# generate, on the signing HSM, with ONLY that card attached:
#   1. the token is found BY SERIAL, and it must be the only token present: sc-hsm-tool addresses the
#      card without a reader index, so a second card would be a card it might wrap from by mistake;
#   2. the PIN once (echo off, or --pin-fd), checked before anything probes the card: key-reference
#      probing spends a PIN verification per attempt, and on a wrong PIN that walks the retry counter
#      to zero (measured 2026-08-06, hsm-recovery-drill.sh);
#   3. the object id must be free; the key references that wrap BEFORE are recorded;
#   4. pkcs11-tool --keypairgen --key-type rsa:2048 --id ID --label LABEL — on the card;
#   5. the new key reference is the one that wraps AFTER and did not before (the card assigns
#      references itself and ignores the PKCS#11 id, measured 2026-08-06); exactly one, or refused;
#   6. a self-signed certificate: hsm-signing-cert.py writes the bytes to be signed, the CARD signs
#      them (SHA256-RSA-PKCS), and the certificate must verify under the card's public key — so the
#      certificate is also the proof that this object signs;
#   7. sc-hsm-tool --wrap-key: the DKEK-wrapped blob, the backup;
#   8. the record (hsm-signing-cert.py evidence): serial, id, reference, public key, certificate, the
#      blob's SHA-256. Written last: a refusal at any step leaves no record.
#   Out: DIR/LABEL.crt.pem, DIR/LABEL.pub.der, DIR/LABEL.wrapped.bin, DIR/LABEL.evidence.json.
#
# restore, on the spare, with ONLY the spare attached: the blob is unwrapped into the first free key
# reference; the restored key is found by its public key (an unwrapped key may come back with no label
# and another id, measured on the drill); it signs a fresh challenge, which must verify under the
# certificate's key and must NOT verify for other data (a verifier that accepts anything proves nothing).
# A card whose DKEK is not the blob's refuses the unwrap: that is the refusal the separate domain is for.
#
# THE PIN is never on a command line: pkcs11-tool and sc-hsm-tool get the literal `--pin env:REGALIA_PIN`
# and the value only in the environment of that one process. One attempt; a wrong PIN spends a retry.
#
# NOT RUN ON A CARD. Written against the emulator's model and the quirks the drills measured; it must be
# run once on a bench Nitrokey HSM 2 before the ceremony relies on it.
set -uo pipefail
umask 077
# ASCII RANGES. A check here that says [0-9] means ten digits, and [a-z] twenty-six letters. In a
# UTF-8 locale bash matches a bracket range by the locale's collation instead: [0-9] also takes
# full-width and Arabic-Indic digits, [a-z0-9] takes accented letters, and a negated range such as
# *[!0-9]* no longer catches them (measured: bash 5.2, glibc 2.41, en_US.UTF-8). Only the collation is
# pinned, so text stays UTF-8 and lengths are still counted in characters. LC_ALL overrides
# LC_COLLATE, so it is moved away first, into every other category it was deciding.
if [ -n "${LC_ALL:-}" ]; then
  for _lc in LANG LC_CTYPE LC_NUMERIC LC_TIME LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS \
             LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION; do export "$_lc=$LC_ALL"; done
  unset LC_ALL _lc
fi
export LC_COLLATE=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_TOOL="$HERE/hsm-signing-cert.py"
MAX_REF=12

die(){ printf 'hsm-signing-key: REFUSED: %s\n' "$*" >&2; exit 1; }
need(){ [ -n "${2-}" ] || die "$1 needs a value"; }
ok(){ printf '  ok  %s\n' "$*"; }

COMMAND="${1-}"; [ $# -gt 0 ] && shift
SERIAL="" ID="" LABEL="" SUBJECT="" OUT="" DAYS=3650 PIN_FD="" BLOB="" CERT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --serial)      need "$1" "${2-}"; SERIAL="$2"; shift 2;;
    --id)          need "$1" "${2-}"; ID="$(printf '%s' "$2" | tr 'A-F' 'a-f')"; shift 2;;
    --label)       need "$1" "${2-}"; LABEL="$2"; shift 2;;
    --subject)     need "$1" "${2-}"; SUBJECT="$2"; shift 2;;
    --out)         need "$1" "${2-}"; OUT="$2"; shift 2;;
    --days)        need "$1" "${2-}"; DAYS="$2"; shift 2;;
    --pin-fd)      need "$1" "${2-}"; PIN_FD="$2"; shift 2;;
    --blob)        need "$1" "${2-}"; BLOB="$2"; shift 2;;
    --certificate) need "$1" "${2-}"; CERT="$2"; shift 2;;
    --pin|-p|--pin=*|--so-pin|--so-pin=*)
      die "a PIN is never taken on the command line — it is asked for with echo off, or read from --pin-fd";;
    -h|--help) sed -n '2,8p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done
case "$COMMAND" in generate|restore) ;; *) die "the first argument is generate or restore";; esac
[ -n "$SERIAL" ] || die "--serial is required"
case "$SERIAL" in *[!A-Za-z0-9]*) die "--serial '$SERIAL' is not a serial";; esac
case "$PIN_FD" in ''|[0-9]|[1-9][0-9]) ;; *) die "--pin-fd takes a file-descriptor number";; esac
if [ "$COMMAND" = generate ]; then
  [ -n "$ID" ] && [ -n "$LABEL" ] && [ -n "$SUBJECT" ] && [ -n "$OUT" ] || die "generate needs --id, --label, --subject and --out"
  case "$ID" in [0-9a-f][0-9a-f]) ;; *) die "--id must be one byte in hex (two digits)";; esac
  case "$LABEL" in ''|*[!a-z0-9-]*) die "--label is lowercase letters, digits and dashes";; esac
  case "$DAYS" in ''|*[!0-9]*) die "--days is a number";; esac
  [ -d "$OUT" ] || die "--out $OUT is not a directory"
  for f in crt.pem pub.der wrapped.bin evidence.json; do
    [ ! -e "$OUT/$LABEL.$f" ] || die "$OUT/$LABEL.$f already exists: nothing is overwritten"
  done
else
  [ -s "$BLOB" ] && [ -s "$CERT" ] || die "restore needs --blob and --certificate, both non-empty files"
fi

first_file(){ local c; for c in "$@"; do [ -f "$c" ] && { printf '%s' "$c"; return 0; }; done; return 1; }
MODULE="${CEREMONY_PKCS11_MODULE:-${HSM_PKCS11_MODULE:-}}"
[ -n "$MODULE" ] || MODULE="$(first_file /usr/lib/*/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so /usr/local/lib/opensc-pkcs11.so)" \
  || die "no opensc-pkcs11 module found (set CEREMONY_PKCS11_MODULE)"
[ -f "$MODULE" ] || die "PKCS#11 module $MODULE does not exist"
for t in pkcs11-tool sc-hsm-tool openssl python3; do command -v "$t" >/dev/null 2>&1 || die "$t is not installed"; done

W="$(mktemp -d "${CEREMONY_SIGNING_TMP:-${TMPDIR:-/dev/shm}}/signing-key.XXXXXX" 2>/dev/null || mktemp -d)" || die "cannot create a work directory"
# A key generated on the card and then refused (no certificate, no backup, no record) must not stay on
# an offline SIGNING card: a key nobody recorded and nobody can restore is one that can still sign. It
# is deleted, and if that fails the operator is told to delete it before the card leaves the table.
KEY_MADE="" DONE=""
on_exit(){
  if [ -n "$KEY_MADE" ] && [ -z "$DONE" ] && [ -n "${PIN:-}" ]; then
    if p11_pin --delete-object --type privkey --id "$ID" >/dev/null 2>&1 && p11_pin --delete-object --type pubkey --id "$ID" >/dev/null 2>&1; then
      printf 'hsm-signing-key: the key generated at id %s was DELETED from card %s (nothing was recorded for it)
' "$ID" "$SERIAL" >&2
    else
      printf 'hsm-signing-key: THE KEY GENERATED AT id %s IS STILL ON CARD %s and nothing recorded it: delete it (pkcs11-tool --delete-object --type privkey --id %s, then pubkey) before the card leaves the table
' "$ID" "$SERIAL" "$ID" >&2
    fi
  fi
  rm -rf "$W"; unset PIN REGALIA_PIN
}
trap on_exit EXIT

# Every card command is bounded: a wedged reader must end the step, not hang it with a PIN in memory.
p11(){ perl -e 'alarm shift; exec @ARGV' 60 pkcs11-tool --module "$MODULE" "$@"; }
p11_pin(){ REGALIA_PIN="$PIN" perl -e 'alarm shift; exec @ARGV' 60 pkcs11-tool --module "$MODULE" --slot "$SLOT_ID" --login --pin env:REGALIA_PIN "$@"; }
schsm_pin(){ REGALIA_PIN="$PIN" perl -e 'alarm shift; exec @ARGV' 60 sc-hsm-tool "$@" --pin env:REGALIA_PIN; }
cert_tool(){ python3 -I "$CERT_TOOL" "$@"; }

# ---- 1. the one token, by serial --------------------------------------------------------------------
slots="$(p11 --list-token-slots 2>/dev/null)" || die "cannot list the PKCS#11 token slots of $MODULE"
SLOT_ID="" n=0 total=0 cur=""
while IFS= read -r line; do
  case "$line" in
    "Slot "*"(0x"*")"*) cur="${line#*(}"; cur="${cur%%)*}";;
    *"serial num"*:*)
      total=$((total + 1))
      s="${line#*:}"; s="$(printf '%s' "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [ -n "$cur" ] && [ "$s" = "$SERIAL" ]; then SLOT_ID="$cur"; n=$((n + 1)); fi
      cur="";;
  esac
done <<< "$slots"
[ "$n" -eq 1 ] || die "serial $SERIAL matches $n tokens — attach exactly that card"
[ "$total" -eq 1 ] || die "$total tokens are attached; attach ONLY card $SERIAL (sc-hsm-tool addresses the card without a reader index)"
ok "card $SERIAL is the only token attached (slot $SLOT_ID)"

# ---- 2. the PIN, once, verified before any probe ----------------------------------------------------
if [ -n "$PIN_FD" ]; then
  IFS= read -r PIN <&"$PIN_FD" || die "no PIN on file descriptor $PIN_FD"
else
  printf '   card %s — enter its user PIN (not shown; ONE attempt, a wrong PIN spends a retry): ' "$SERIAL" >&2
  IFS= read -rs PIN || die "no PIN entered"
  printf '\n' >&2
fi
[ -n "$PIN" ] || die "an empty PIN was entered — nothing was sent to the card"
objects="$(p11_pin --list-objects 2>&1)"; rc=$?
if [ "$rc" -ne 0 ]; then
  case "$(grep -aoE 'CKR_[A-Z_]+' <<< "$objects" | head -1)" in
    CKR_PIN_INCORRECT) die "the card refused the PIN (CKR_PIN_INCORRECT) — ONE RETRY WAS SPENT";;
    CKR_PIN_LOCKED)    die "the card's PIN is LOCKED (CKR_PIN_LOCKED)";;
    *)                 die "the card did not list its objects with the PIN (pkcs11-tool exit $rc)";;
  esac
fi
ok "the PIN verifies"

wrappable_refs(){ # the key references that wrap now; --wrap-key does not modify the key
  local r t out=""
  for r in $(seq 1 "$MAX_REF"); do
    t="$W/probe-$r"
    if schsm_pin --wrap-key "$t" --key-reference "$r" >/dev/null 2>&1 && [ -s "$t" ]; then out="$out $r"; fi
    rm -f "$t"
  done
  printf '%s' "$out"
}
pubkey_ids(){ # the ids of the public-key objects on the card
  p11_pin --list-objects --type pubkey 2>/dev/null | sed -n 's/^[[:space:]]*ID:[[:space:]]*\([0-9a-fA-F]*\)[[:space:]]*$/\1/p' | tr 'A-F' 'a-f'
}
sign_check(){ # $1 = id, $2 = public key DER: a fresh challenge signed on the card, with a wrong-data control
  head -c 32 /dev/urandom > "$W/challenge"; head -c 32 /dev/urandom > "$W/other"
  openssl pkey -pubin -inform DER -in "$2" -out "$W/check.pem" 2>/dev/null || return 1
  p11_pin --id "$1" --sign --mechanism SHA256-RSA-PKCS --input-file "$W/challenge" --output-file "$W/challenge.sig" >/dev/null 2>&1 || return 1
  openssl dgst -sha256 -verify "$W/check.pem" -signature "$W/challenge.sig" "$W/challenge" >/dev/null 2>&1 || return 1
  if openssl dgst -sha256 -verify "$W/check.pem" -signature "$W/challenge.sig" "$W/other" >/dev/null 2>&1; then return 2; fi
  return 0
}

if [ "$COMMAND" = generate ]; then
  # ---- 3. the id is free; what wraps before ---------------------------------------------------------
  grep -qx "$ID" <<< "$(pubkey_ids)" && die "object id $ID is already in use on card $SERIAL"
  before="$(wrappable_refs)"
  # ---- 4. the key, on the card ----------------------------------------------------------------------
  gen="$(p11_pin --keypairgen --key-type rsa:2048 --id "$ID" --label "$LABEL" 2>&1)" \
    || die "the card did not generate the key: $(grep -aoE 'CKR_[A-Z_]+' <<< "$gen" | head -1)"
  KEY_MADE=1
  ok "RSA-2048 key $LABEL generated on card $SERIAL at id $ID"
  # ---- 5. its key reference -------------------------------------------------------------------------
  after="$(wrappable_refs)"
  REF=""; count=0
  for r in $after; do case " $before " in *" $r "*) ;; *) REF="$r"; count=$((count + 1));; esac; done
  [ "$count" -eq 1 ] || die "expected exactly one new key reference after generating, found $count (before:${before:- none}, after:${after:- none})"
  ok "its key reference is $REF"
  # ---- 6. the certificate, signed by the card ---------------------------------------------------------
  p11 --slot "$SLOT_ID" --read-object --type pubkey --id "$ID" --output-file "$W/pub.der" >/dev/null 2>&1 && [ -s "$W/pub.der" ] \
    || die "cannot read the public key of id $ID"
  serial_hex="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"; serial_hex="1${serial_hex:1}"   # 128 bits, positive
  cert_tool tbs --public-key "$W/pub.der" --subject "$SUBJECT" --days "$DAYS" --serial-hex "$serial_hex" --out "$W/tbs.der" || exit 1
  p11_pin --id "$ID" --sign --mechanism SHA256-RSA-PKCS --input-file "$W/tbs.der" --output-file "$W/tbs.sig" >/dev/null 2>&1 \
    || die "the card did not sign the certificate"
  cert_tool assemble --tbs "$W/tbs.der" --signature "$W/tbs.sig" --out "$W/crt.pem" || exit 1
  cert_tool check --certificate "$W/crt.pem" --public-key "$W/pub.der" >/dev/null || die "the certificate the card signed does not verify"
  ok "certificate signed by the card, and it verifies under the card's key"
  # ---- 7. the backup ----------------------------------------------------------------------------------
  schsm_pin --wrap-key "$W/wrapped.bin" --key-reference "$REF" >/dev/null 2>&1 && [ -s "$W/wrapped.bin" ] \
    || die "sc-hsm-tool --wrap-key failed for key reference $REF (does the card hold its DKEK?)"
  ok "DKEK-wrapped blob written"
  # ---- 8. the record, last ----------------------------------------------------------------------------
  cert_tool evidence --device-serial "$SERIAL" --object-id "$ID" --key-reference "$REF" --label "$LABEL" --public-key "$W/pub.der" \
    --certificate "$W/crt.pem" --blob "$W/wrapped.bin" --out "$W/evidence.json" || exit 1
  for f in crt.pem pub.der wrapped.bin evidence.json; do cp "$W/$f" "$OUT/$LABEL.$f" || die "cannot write $OUT/$LABEL.$f"; done
  DONE=1; unset PIN
  printf 'SIGNING-KEY %s card %s id %s ref %s public key %s\n' "$LABEL" "$SERIAL" "$ID" "$REF" \
    "$(sha256sum "$OUT/$LABEL.pub.der" | cut -d' ' -f1)"
  exit 0
fi

# ---- restore, on the spare ----------------------------------------------------------------------------
openssl x509 -in "$CERT" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER -out "$W/want.der" 2>/dev/null && [ -s "$W/want.der" ] \
  || die "$CERT is not a certificate"
cert_tool check --certificate "$CERT" --public-key "$W/want.der" >/dev/null || die "$CERT does not verify under its own key"
# The proof is that THIS blob restores the key. A card that already holds it would pass with any blob.
for id in $(pubkey_ids); do
  p11 --slot "$SLOT_ID" --read-object --type pubkey --id "$id" --output-file "$W/have.der" >/dev/null 2>&1 || continue
  cmp -s "$W/have.der" "$W/want.der" && die "card $SERIAL already holds this key (id $id): a restore onto it would prove nothing about the blob"
done
used="$(wrappable_refs)"
DEST=""
for r in $(seq 1 "$MAX_REF"); do case " $used " in *" $r "*) ;; *) DEST="$r"; break;; esac; done
[ -n "$DEST" ] || die "no free key reference on card $SERIAL"
# sc-hsm-tool --unwrap-key EXITS 1 EVEN ON SUCCESS (measured 2026-08-06, hsm-recovery-drill.sh): judged by its output.
out="$(schsm_pin --unwrap-key "$BLOB" --key-reference "$DEST" 2>&1)"
grep -qi 'successfully imported' <<< "$out" \
  || die "card $SERIAL did not unwrap the blob (a card whose DKEK is not the blob's refuses it): $(tail -1 <<< "$out")"
found=""
for id in $(pubkey_ids); do
  p11 --slot "$SLOT_ID" --read-object --type pubkey --id "$id" --output-file "$W/have.der" >/dev/null 2>&1 || continue
  cmp -s "$W/have.der" "$W/want.der" && { found="$id"; break; }
done
[ -n "$found" ] || die "after the unwrap no key on card $SERIAL has the certificate's public key"
sign_check "$found" "$W/want.der"; rc=$?
unset PIN
case "$rc" in
  0) ;;
  2) die "the signature check accepted other data: the check proves nothing";;
  *) die "the restored key at id $found did not sign a challenge that verifies under the certificate's key";;
esac
printf 'RESTORED %s on card %s at id %s ref %s: it signs for the certificate key\n' \
  "$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | sed 's/^subject=//')" "$SERIAL" "$found" "$DEST"
