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
# WHAT IS LEFT BEHIND WHEN IT STOPS. generate ends in one of two states: the four files in --out and the
# key on the card, or no file and no key. A refusal, a failed card command or a signal (INT, TERM, HUP)
# after the key was asked for removes whatever reached --out and deletes the key, then says which: DELETED,
# or STILL ON CARD with what to do, judged by listing the card again and not by the delete's exit status.
# Those messages go to the terminal the script was started on even while a card command's output is
# discarded. restore, refused after the unwrap, deletes the key it just put on the spare and says so.
#
# THE BLOB IS TIED TO THE KEY ONLY BY restore. On the card that made it, nothing can open a wrapped blob,
# so generate knows the blob only as "what key reference R wrapped", and R as "the reference that wraps
# now and did not before" (probed twice each time; one new reference, or refused). Until restore has run
# on the spare, the backup is a claim.
#
# NOT RUN ON A CARD. Written against a stubbed card model and the quirks the drills measured; it must be
# run once on a bench Nitrokey HSM 2 before the ceremony relies on it. To settle there:
#   * whether deleting the private key also removes the public-key object (the result is judged by
#     listing the card again, so either answer works, but the message may differ);
#   * whether an unwrapped key has a public-key object at all (the id-in-use and already-holds checks,
#     and restore's search, read public-key objects);
#   * sc-hsm-tool is called without --reader (one token attached is required first); with a card of
#     another kind in a second reader it may pick that reader and stop the step.
set -uo pipefail
umask 077
# The PIN lives in a shell variable that is NOT exported. A caller's environment that already has PIN or
# REGALIA_PIN would make `read` keep the export attribute, and every child would carry the PIN; a caller's
# OPENSSL_CONF could hand openssl an engine. None of them is inherited.
unset PIN REGALIA_PIN OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
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
  [ -w "$OUT" ] || die "--out $OUT is not writable (found before anything is generated)"
  for f in crt.pem pub.der wrapped.bin evidence.json; do
    # -L too: a dangling link is "not there" to -e and would be written through, or refused at the end
    { [ ! -e "$OUT/$LABEL.$f" ] && [ ! -L "$OUT/$LABEL.$f" ]; } || die "$OUT/$LABEL.$f already exists: nothing is overwritten"
  done
else
  [ -s "$BLOB" ] && [ -s "$CERT" ] || die "restore needs --blob and --certificate, both non-empty files"
fi

first_file(){ local c; for c in "$@"; do [ -f "$c" ] && { printf '%s' "$c"; return 0; }; done; return 1; }
MODULE="${CEREMONY_PKCS11_MODULE:-${HSM_PKCS11_MODULE:-}}"
[ -n "$MODULE" ] || MODULE="$(first_file /usr/lib/*/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so /usr/local/lib/opensc-pkcs11.so)" \
  || die "no opensc-pkcs11 module found (set CEREMONY_PKCS11_MODULE)"
[ -f "$MODULE" ] || die "PKCS#11 module $MODULE does not exist"
for t in pkcs11-tool sc-hsm-tool openssl python3 timeout; do command -v "$t" >/dev/null 2>&1 || die "$t is not installed"; done

W="$(mktemp -d "${CEREMONY_SIGNING_TMP:-${TMPDIR:-/dev/shm}}/signing-key.XXXXXX" 2>/dev/null || mktemp -d)" || die "cannot create a work directory"

# Every card command is bounded: a wedged reader must end the step, not hang it with a PIN in memory.
# (timeout, not a perl one-liner: perl would carry the PIN and honour PERL5OPT.)
p11(){ timeout 60 pkcs11-tool --module "$MODULE" "$@"; }
p11_pin(){ REGALIA_PIN="$PIN" timeout 60 pkcs11-tool --module "$MODULE" --slot "$SLOT_ID" --login --pin env:REGALIA_PIN "$@"; }
schsm_pin(){ REGALIA_PIN="$PIN" timeout 60 sc-hsm-tool "$@" --pin env:REGALIA_PIN; }
cert_tool(){ python3 -I "$CERT_TOOL" "$@"; }

# The ids of the public-key objects on the card, one per line. FAILS when the card does not answer: a
# listing that failed is not an empty card, and every check built on it would pass for the wrong reason.
object_ids(){ # $1 = pubkey | privkey
  local listing
  listing="$(p11_pin --list-objects --type "$1" 2>/dev/null)" || return 1
  sed -n 's/^[[:space:]]*ID:[[:space:]]*\([0-9a-fA-F]*\)[[:space:]]*$/\1/p' <<< "$listing" | tr 'A-F' 'a-f'
}
pubkey_ids(){ object_ids pubkey; }

# ---- what is left behind ---------------------------------------------------------------------------------
# fd 9 is the stderr the script was started with. The trap can run while a card command's output is being
# discarded (a signal during `… >/dev/null 2>&1`), and its messages must still reach the operator.
exec 9>&2
KEY_ASKED="" UNWRAPPED="" DONE="" WRITTEN=() IDS_BEFORE=""
say9(){ printf 'hsm-signing-key: %s\n' "$*" >&9 2>/dev/null || true; }
remove_key(){ # $1 = id: delete both objects, then LIST BOTH KINDS AGAIN: the listings decide, not the deletes' status
  local pub priv
  p11_pin --delete-object --type privkey --id "$1" >/dev/null 2>&1
  p11_pin --delete-object --type pubkey --id "$1" >/dev/null 2>&1
  pub="$(object_ids pubkey)" && priv="$(object_ids privkey)" || return 2
  ! grep -qx "$1" <<< "$pub" && ! grep -qx "$1" <<< "$priv"
}
on_exit(){
  trap '' PIPE INT TERM HUP                 # nothing interrupts the cleanup, and a closed terminal does not end it
  local f ids id left=""
  if [ -z "$DONE" ]; then
    for f in ${WRITTEN[@]+"${WRITTEN[@]}"}; do rm -f "$f"; done
    if [ -n "$KEY_ASKED" ] && [ -n "${PIN:-}" ]; then
      # the key may or may not be there: the card was asked, and the answer may have been lost
      if ! ids="$(pubkey_ids)"; then
        left="COULD NOT ASK card $SERIAL whether a key is at id $ID. Nothing recorded it. List the card and delete it (pkcs11-tool --delete-object --type privkey --id $ID, then pubkey) before the card leaves the table"
      elif grep -qx "$ID" <<< "$ids"; then
        if remove_key "$ID"; then left="the key generated at id $ID was DELETED from card $SERIAL (nothing was recorded for it, and no file of it was kept)"
        else left="THE KEY GENERATED AT id $ID IS STILL ON CARD $SERIAL and nothing recorded it: delete it (pkcs11-tool --delete-object --type privkey --id $ID, then pubkey) before the card leaves the table"; fi
      fi
    fi
    if [ -n "$UNWRAPPED" ] && [ -n "${PIN:-}" ]; then
      # restore was refused after the unwrap: the spare holds a key nothing vouched for
      if ! ids="$(pubkey_ids)"; then
        left="a key WAS UNWRAPPED at key reference $DEST on card $SERIAL and the restore was refused. COULD NOT LIST the card: delete that key before the card is used"
      else
        left="the refused restore left no key on card $SERIAL"
        for id in $ids; do
          grep -qx "$id" <<< "$IDS_BEFORE" && continue
          if remove_key "$id"; then left="the key the refused restore had unwrapped (id $id, key reference $DEST) was DELETED from card $SERIAL"
          else left="THE KEY UNWRAPPED AT id $id (key reference $DEST) IS STILL ON CARD $SERIAL after a refused restore: delete it before the card is used"; break; fi
        done
      fi
    fi
  fi
  rm -rf "$W"; unset PIN REGALIA_PIN
  [ -z "$left" ] || say9 "$left"
}
trap on_exit EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

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

probe_refs(){ # the key references that wrap now; --wrap-key does not modify the key
  local r t out=""
  for r in $(seq 1 "$MAX_REF"); do
    t="$W/probe-$r"
    if schsm_pin --wrap-key "$t" --key-reference "$r" >/dev/null 2>&1 && [ -s "$t" ]; then out="$out $r"; fi
    rm -f "$t"
  done
  printf '%s' "$out"
}
# Probed TWICE, and the two answers must agree: a probe that failed once for another reason would make an
# existing key look new, and its blob would be recorded as the new key's.
wrappable_refs(){
  local a b
  a="$(probe_refs)"; b="$(probe_refs)"
  [ "$a" = "$b" ] || return 1
  printf '%s' "$a"
}
read_pubkey(){ # $1 = id, $2 = output file
  rm -f "$2"
  p11 --slot "$SLOT_ID" --read-object --type pubkey --id "$1" --output-file "$2" >/dev/null 2>&1 && [ -s "$2" ]
}
sign_check(){ # $1 = id, $2 = public key DER: a fresh challenge signed on the card, with a wrong-data control
  head -c 32 /dev/urandom > "$W/challenge"; head -c 32 /dev/urandom > "$W/other"
  cmp -s "$W/challenge" "$W/other" && return 1
  openssl pkey -pubin -inform DER -in "$2" -out "$W/check.pem" 2>/dev/null || return 1
  p11_pin --id "$1" --sign --mechanism SHA256-RSA-PKCS --input-file "$W/challenge" --output-file "$W/challenge.sig" >/dev/null 2>&1 || return 1
  openssl dgst -sha256 -verify "$W/check.pem" -signature "$W/challenge.sig" "$W/challenge" >/dev/null 2>&1 || return 1
  if openssl dgst -sha256 -verify "$W/check.pem" -signature "$W/challenge.sig" "$W/other" >/dev/null 2>&1; then return 2; fi
  return 0
}

if [ "$COMMAND" = generate ]; then
  # ---- 3. the id is free; what wraps before ---------------------------------------------------------
  ids="$(pubkey_ids)" || die "the card did not list its public keys: whether id $ID is free is not known"
  grep -qx "$ID" <<< "$ids" && die "object id $ID is already in use on card $SERIAL"
  before="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap: nothing was generated"
  # ---- 4. the key, on the card ----------------------------------------------------------------------
  # From here the card may hold a key at $ID whatever this script learns of it (a lost answer, a signal):
  # the exit trap looks.
  KEY_ASKED=1
  gen="$(p11_pin --keypairgen --key-type rsa:2048 --id "$ID" --label "$LABEL" 2>&1)" \
    || die "the card did not report a generated key (${gen:+$(grep -aoE 'CKR_[A-Z_]+' <<< "$gen" | head -1)}; pkcs11-tool failed)"
  ok "RSA-2048 key $LABEL generated on card $SERIAL at id $ID"
  # ---- 5. its key reference -------------------------------------------------------------------------
  after="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap after generating"
  REF=""; count=0
  for r in $after; do case " $before " in *" $r "*) ;; *) REF="$r"; count=$((count + 1));; esac; done
  [ "$count" -eq 1 ] || die "expected exactly one new key reference after generating, found $count (before:${before:- none}, after:${after:- none})"
  for r in $before; do case " $after " in *" $r "*) ;; *) die "key reference $r wrapped before generating and does not now: the card's answers are not stable";; esac; done
  ok "its key reference is $REF"
  # ---- 6. the certificate, signed by the card ---------------------------------------------------------
  read_pubkey "$ID" "$W/pub.der" || die "cannot read the public key of id $ID"
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
  # ---- 8. the record, last; then all four files, or none ----------------------------------------------
  cert_tool evidence --device-serial "$SERIAL" --object-id "$ID" --key-reference "$REF" --label "$LABEL" --public-key "$W/pub.der" \
    --certificate "$W/crt.pem" --blob "$W/wrapped.bin" --out "$W/evidence.json" || exit 1
  # Staged under temporary names in --out, then renamed, the record last. Until DONE the exit trap removes
  # every name listed in WRITTEN and deletes the key: a blob that restores must not outlive a refusal.
  for f in crt.pem pub.der wrapped.bin evidence.json; do
    WRITTEN+=("$OUT/.$LABEL.$f.tmp" "$OUT/$LABEL.$f")
    cp "$W/$f" "$OUT/.$LABEL.$f.tmp" || die "cannot write into $OUT"
  done
  for f in crt.pem pub.der wrapped.bin evidence.json; do
    mv -n "$OUT/.$LABEL.$f.tmp" "$OUT/$LABEL.$f" && [ ! -e "$OUT/.$LABEL.$f.tmp" ] || die "cannot put $OUT/$LABEL.$f in place"
  done
  DONE=1; unset PIN
  printf 'SIGNING-KEY %s card %s id %s ref %s public key %s\n' "$LABEL" "$SERIAL" "$ID" "$REF" \
    "$(sha256sum "$OUT/$LABEL.pub.der" | cut -d' ' -f1)"
  exit 0
fi

# ---- restore, on the spare ----------------------------------------------------------------------------
openssl x509 -in "$CERT" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER -out "$W/want.der" 2>/dev/null && [ -s "$W/want.der" ] \
  || die "$CERT is not a certificate"
cert_tool check --certificate "$CERT" --public-key "$W/want.der" >/dev/null || die "$CERT does not verify under its own key"
# The proof is that THIS blob restores the key. A card that already holds it would pass with any blob, so
# every key on the card is read first, and a listing or a read that fails is a refusal, not "no such key".
IDS_BEFORE="$(pubkey_ids)" || die "card $SERIAL did not list its public keys: whether it already holds this key is not known"
for id in $IDS_BEFORE; do
  read_pubkey "$id" "$W/have.der" || die "cannot read the public key at id $id on card $SERIAL: whether it already holds this key is not known"
  cmp -s "$W/have.der" "$W/want.der" && die "card $SERIAL already holds this key (id $id): a restore onto it would prove nothing about the blob"
done
used="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap: nothing was unwrapped"
DEST=""
for r in $(seq 1 "$MAX_REF"); do case " $used " in *" $r "*) ;; *) DEST="$r"; break;; esac; done
[ -n "$DEST" ] || die "no free key reference on card $SERIAL"
# From here the spare may hold a key nothing vouched for: the exit trap removes it unless DONE.
UNWRAPPED=1
# sc-hsm-tool --unwrap-key EXITS 1 EVEN ON SUCCESS (measured 2026-08-06, hsm-recovery-drill.sh): judged by its output.
out="$(schsm_pin --unwrap-key "$BLOB" --key-reference "$DEST" 2>&1)"
grep -qi 'successfully imported' <<< "$out" \
  || die "card $SERIAL did not unwrap the blob (a card whose DKEK is not the blob's refuses it): $(tail -1 <<< "$out")"
now="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap after the unwrap"
case " $now " in *" $DEST "*) ;; *) die "after the unwrap key reference $DEST does not wrap: the blob did not put a key there";; esac
ids="$(pubkey_ids)" || die "card $SERIAL did not list its public keys after the unwrap"
found=""
for id in $ids; do
  grep -qx "$id" <<< "$IDS_BEFORE" && continue              # only a key that was NOT there before can be the blob's
  read_pubkey "$id" "$W/have.der" || die "cannot read the public key at id $id after the unwrap"
  cmp -s "$W/have.der" "$W/want.der" && { found="$id"; break; }
done
[ -n "$found" ] || die "after the unwrap no NEW key on card $SERIAL has the certificate's public key: the blob is not that key's"
sign_check "$found" "$W/want.der"; rc=$?
case "$rc" in
  0) ;;
  2) die "the signature check accepted other data: the check proves nothing";;
  *) die "the restored key at id $found did not sign a challenge that verifies under the certificate's key";;
esac
DONE=1; unset PIN
printf 'RESTORED %s on card %s at id %s ref %s: it signs for the certificate key\n' \
  "$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | sed 's/^subject=//')" "$SERIAL" "$found" "$DEST"
