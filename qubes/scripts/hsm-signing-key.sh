#!/usr/bin/env bash
# hsm-signing-key.sh — a signing key GENERATED ON an offline SmartCard-HSM (Nitrokey HSM 2), with its
# certificate and its DKEK-wrapped backup; and the proof that the backup restores and signs on the spare.
# regalia#554 (regalia-kms#57: the two PCR keys and the Secure Boot key of the KMS hosts' boot image).
#
#   hsm-signing-key.sh generate --serial SERIAL --expect-kcv KCV --id HEX --label LABEL --subject "COMMON NAME"
#                               --out DIR [--key-type rsa:2048|ec:prime256v1] [--days N] [--pin-fd N]
#   hsm-signing-key.sh restore  --serial SPARE_SERIAL --expect-kcv KCV --blob LABEL.wrapped.bin
#                               --certificate LABEL.crt.pem [--pin-fd N]
#   hsm-signing-key.sh refuse   --serial OTHER_SERIAL --expect-kcv OTHER_KCV --blob LABEL.wrapped.bin
#                               --certificate LABEL.crt.pem [--pin-fd N]
#
# THE DOMAIN, BY ITS KEY CHECK VALUE. --expect-kcv is the DKEK key check value the ceremony record gives
# for the card's own domain (sixteen hex digits, as sc-hsm-tool prints "DKEK key check value"). Before the
# PIN, the card's status must show a complete DKEK with exactly that value; an import still pending, no
# DKEK, or another value is refused. A wrapped blob names the DKEK it was made under in its first eight
# bytes (SEQUENCE { OCTET STRING { KCV || … } }, measured 2026-10-03 on DENK0404380), so: generate checks
# the blob it wrote names the card's KCV and records it (dkek_kcv); restore needs the blob's KCV to be the
# card's; refuse needs them to DIFFER, and is never tried on a card of the blob's own domain.
#
# KEY TYPES. rsa:2048 (the default) for the boot image's keys (regalia#554); ec:prime256v1 for the membership
# root (regalia-kms#156, option C), which lives on its OWN HSM and spare under a DKEK used by nothing else.
# The card signs with SHA256-RSA-PKCS or ECDSA-SHA256 accordingly; restore and refuse read the type from the
# certificate's key.
#
# THE CARD'S OWN EVIDENCE (both types). After generating, the device certificate C.DevAut (EF 2F02) and the
# authenticated request the generation left in EF CE<key reference> are read with opensc-tool alone
# (hsm-devaut-read.sh, hsm-key-attestation-read.sh: no PIN), and hsm-key-attestation-verify.py checks that
# C.DevAut chains to CardContact's root in qubes/trust-anchors/smartcard-hsm, that the device signed the
# request, and that the attested key IS the public key the card exposes. Refused otherwise: a key imported
# from software has no attestation, and that is the difference this step is for. (A key restored from a
# DKEK blob does have one: the blob carries the generating card's EF CE<ref>, measured 2026-10-03.) Both files go
# into the evidence; the verifier needs pycvc and runs under the interpreter tools/ceremony-python.sh finds.
#
# refuse, on a card of ANOTHER DKEK domain (the KMS hosts', the image-signing pair's), with ONLY that card
# attached: the blob must NOT unwrap there. It passes only when the card gives the answer a card of another
# DKEK gives ("SC_CARDCTL_SC_HSM_UNWRAP_KEY … failed with Data object not found": it looks the DKEK up by the
# blob's KCV and has none, measured 2026-10-03) and no new key reference appeared. Any other failure proves
# nothing about the domain and is refused. An unwrap that succeeded is the failure this proves cannot
# happen, and the key it put there is deleted before the script stops.
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
# reference, one with neither a key nor an EF CE<ref>: deleting a key leaves its EF CE<ref> behind, and the
# unwrap refuses a reference that still has one (measured 2026-10-03). The blob carries the key's EF CE<ref>
# along, so the restored key's attestation is the generating card's. The restored key is found by its public key (an unwrapped key may come back with no label
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
# RUN ON A CARD 2026-10-03 (DENK0404380, firmware 4.1, OpenSC with every other reader ignored): one RSA-2048
# and one P-256 key generated, attested and wrapped; the P-256 blob restored onto a free reference and signed;
# a card of another DKEK refused it. Measured there: deleting the private key also removes the public-key
# object; an unwrapped key comes back with its label, its id and a public-key object; the unwrap exited 0.
# Still: sc-hsm-tool is called without --reader (one token attached is required first); with a card of
# another kind in a second reader it may pick that reader and stop the step.
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
SERIAL="" ID="" LABEL="" SUBJECT="" OUT="" DAYS=3650 PIN_FD="" BLOB="" CERT="" KEY_TYPE="rsa:2048" KCV=""
while [ $# -gt 0 ]; do
  case "$1" in
    --expect-kcv)  need "$1" "${2-}"; KCV="$(printf '%s' "$2" | tr 'a-f' 'A-F')"; shift 2;;
    --serial)      need "$1" "${2-}"; SERIAL="$2"; shift 2;;
    --id)          need "$1" "${2-}"; ID="$(printf '%s' "$2" | tr 'A-F' 'a-f')"; shift 2;;
    --label)       need "$1" "${2-}"; LABEL="$2"; shift 2;;
    --subject)     need "$1" "${2-}"; SUBJECT="$2"; shift 2;;
    --out)         need "$1" "${2-}"; OUT="$2"; shift 2;;
    --days)        need "$1" "${2-}"; DAYS="$2"; shift 2;;
    --pin-fd)      need "$1" "${2-}"; PIN_FD="$2"; shift 2;;
    --blob)        need "$1" "${2-}"; BLOB="$2"; shift 2;;
    --certificate) need "$1" "${2-}"; CERT="$2"; shift 2;;
    --key-type)    need "$1" "${2-}"; KEY_TYPE="$2"; shift 2;;
    --pin|-p|--pin=*|--so-pin|--so-pin=*)
      die "a PIN is never taken on the command line — it is asked for with echo off, or read from --pin-fd";;
    -h|--help) sed -n '2,8p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done
case "$COMMAND" in generate|restore|refuse) ;; *) die "the first argument is generate, restore or refuse";; esac
case "$KEY_TYPE" in rsa:2048|ec:prime256v1) ;; *) die "--key-type is rsa:2048 or ec:prime256v1";; esac
[ -n "$SERIAL" ] || die "--serial is required"
case "$SERIAL" in *[!A-Za-z0-9]*) die "--serial '$SERIAL' is not a serial";; esac
case "$PIN_FD" in ''|[0-9]|[1-9][0-9]) ;; *) die "--pin-fd takes a file-descriptor number";; esac
[ -n "$KCV" ] || die "--expect-kcv is required: the DKEK key check value the ceremony record gives for THIS card's domain"
case "$KCV" in [0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]) ;;
  *) die "--expect-kcv is sixteen hex digits, as sc-hsm-tool prints the DKEK key check value";; esac
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
  [ -s "$BLOB" ] && [ -s "$CERT" ] || die "$COMMAND needs --blob and --certificate, both non-empty files"
fi

first_file(){ local c; for c in "$@"; do [ -f "$c" ] && { printf '%s' "$c"; return 0; }; done; return 1; }
MODULE="${CEREMONY_PKCS11_MODULE:-${HSM_PKCS11_MODULE:-}}"
[ -n "$MODULE" ] || MODULE="$(first_file /usr/lib/*/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so /usr/local/lib/opensc-pkcs11.so)" \
  || die "no opensc-pkcs11 module found (set CEREMONY_PKCS11_MODULE)"
[ -f "$MODULE" ] || die "PKCS#11 module $MODULE does not exist"
for t in pkcs11-tool sc-hsm-tool opensc-tool openssl python3 timeout; do command -v "$t" >/dev/null 2>&1 || die "$t is not installed"; done

W="$(mktemp -d "${CEREMONY_SIGNING_TMP:-${TMPDIR:-/dev/shm}}/signing-key.XXXXXX" 2>/dev/null || mktemp -d)" || die "cannot create a work directory"

# Every card command is bounded: a wedged reader must end the step, not hang it with a PIN in memory.
# (timeout, not a perl one-liner: perl would carry the PIN and honour PERL5OPT.)
p11(){ timeout 60 pkcs11-tool --module "$MODULE" "$@"; }
p11_pin(){ REGALIA_PIN="$PIN" timeout 60 pkcs11-tool --module "$MODULE" --slot "$SLOT_ID" --login --pin env:REGALIA_PIN "$@"; }
schsm_pin(){ REGALIA_PIN="$PIN" timeout 60 sc-hsm-tool "$@" --pin env:REGALIA_PIN; }
cert_tool(){ python3 -I "$CERT_TOOL" "$@"; }

# The card's own evidence: readers (opensc-tool only, no PIN) and the verifier (pycvc).
DEVAUT_SH="${HSM_DEVAUT_READ_SH:-$HERE/hsm-devaut-read.sh}"
ATTEST_SH="${HSM_KEY_ATTEST_READ_SH:-$HERE/hsm-key-attestation-read.sh}"
ATTEST_PY="${HSM_KEY_ATTEST_VERIFY_PY:-$HERE/hsm-key-attestation-verify.py}"
TRUST_DIR="${HSM_TRUST_DIR:-$HERE/../trust-anchors/smartcard-hsm}"
CEREMONY_PY_SH="${HSM_CEREMONY_PYTHON_SH:-$HERE/../../tools/ceremony-python.sh}"
# The mechanism and the signature format follow from the key type: the card signs, openssl verifies DER.
mechanism_for(){ # $1 = key type
  case "$1" in rsa:2048) printf '%s' "--mechanism SHA256-RSA-PKCS";; ec:prime256v1) printf '%s' "--mechanism ECDSA-SHA256 --signature-format openssl";; esac
}

# The ids of the public-key objects on the card, one per line. FAILS when the card does not answer: a
# listing that failed is not an empty card, and every check built on it would pass for the wrong reason.
object_ids(){ # $1 = pubkey | privkey
  local listing
  listing="$(p11_pin --list-objects --type "$1" 2>/dev/null)" || return 1
  sed -n 's/^[[:space:]]*ID:[[:space:]]*\([0-9a-fA-F]*\)[[:space:]]*$/\1/p' <<< "$listing" | tr 'A-F' 'a-f'
}
pubkey_ids(){ object_ids pubkey; }

# The reader that holds THIS card: the readers in order, the first whose card reports serial $SERIAL
# (opensc-tool numbers readers, and a laptop's own empty reader may be number 0). Sets READER and DEVOUT.
find_reader(){
  local r out
  READER="" DEVOUT=""
  for r in $(timeout 30 opensc-tool --list-readers 2>/dev/null | sed -n 's/^[[:space:]]*\([0-9][0-9]*\)[[:space:]].*/\1/p'); do
    if out="$(timeout 60 bash "$DEVAUT_SH" --reader "$r" --expect-serial "$SERIAL" 2>/dev/null)" && grep -q '^DEVAUT_HEX=' <<< "$out"; then
      READER="$r"; DEVOUT="$out"; return 0
    fi
  done
  die "no reader holds card $SERIAL with a readable device certificate (EF 2F02)"
}
# Whether EF CE<ref> exists: "present", "absent", or a failure. DELETING A KEY LEAVES ITS EF CE<ref> BEHIND
# (measured 2026-10-03, DENK0404380), and sc-hsm-tool --unwrap-key refuses a reference that still has one
# ("Found existing certificate in EF with fid ce01"): a reference whose key was deleted is not free.
ce_file(){ # $1 = key reference
  local out
  if out="$(timeout 60 bash "$ATTEST_SH" --reader "$READER" --expect-serial "$SERIAL" --key-ref "$1" 2>&1)"; then
    printf 'present'
  elif grep -q '(SW 6A82)' <<< "$out"; then
    printf 'absent'
  else
    return 1
  fi
}

# ---- what is left behind ---------------------------------------------------------------------------------
# fd 9 is the stderr the script was started with. The trap can run while a card command's output is being
# discarded (a signal during `… >/dev/null 2>&1`), and its messages must still reach the operator.
exec 9>&2
KEY_ASKED="" UNWRAPPED="" DONE="" WRITTEN=() IDS_BEFORE="" PRIV_BEFORE=""
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
      # restore was refused after the unwrap: the spare may hold a key nothing vouched for, at key reference
      # $DEST. It is looked for among the private keys too (an unwrapped key may have no public object), only
      # what is NEW is deleted (a private key at an id whose public object was there before loses only the
      # private key), and the key REFERENCE decides the message: "no key" only when $DEST no longer wraps.
      local priv pub gone=""
      if priv="$(object_ids privkey)" && pub="$(object_ids pubkey)"; then
        for id in $(printf '%s\n%s\n' "$priv" "$pub" | sort -u); do
          grep -qx "$id" <<< "$PRIV_BEFORE" && continue        # a private key that was there before is not the blob's
          p11_pin --delete-object --type privkey --id "$id" >/dev/null 2>&1
          grep -qx "$id" <<< "$IDS_BEFORE" || p11_pin --delete-object --type pubkey --id "$id" >/dev/null 2>&1
          gone="$gone $id"
        done
      fi
      # probed twice: a probe that failed for another reason must not read as "no key there"
      local refs_now
      if ! refs_now="$(wrappable_refs)"; then
        left="COULD NOT DETERMINE whether the refused restore left a key at key reference $DEST on card $SERIAL${gone:+ (id$gone was deleted)}: list the card and delete that key before the card is used"
      elif ! grep -qw "$DEST" <<< "$refs_now"; then
        if [ -n "$gone" ]; then left="the key the refused restore had unwrapped (key reference $DEST, id$gone) was DELETED from card $SERIAL"
        else left="the refused restore left no key on card $SERIAL (key reference $DEST does not wrap)"; fi
      else
        left="A KEY IS STILL AT KEY REFERENCE $DEST ON CARD $SERIAL after a refused restore${gone:+ (deleting id$gone did not remove it)}: delete it before the card is used"
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

# ---- 1b. the card's DKEK domain, by its key check value ---------------------------------------------
# sc-hsm-tool prints "DKEK key check value : <16 hex>" only once every share is in; while an import is
# pending it prints the shares still missing instead, and a card without a DKEK prints neither. No PIN.
status="$(timeout 60 sc-hsm-tool </dev/null 2>&1)" || die "sc-hsm-tool could not read card $SERIAL's status"
CARD_KCV="$(sed -n 's/^DKEK key check value[[:space:]]*:[[:space:]]*\([0-9A-Fa-f]\{16\}\)[[:space:]]*$/\1/p' <<< "$status" | tr 'a-f' 'A-F')"
[ "$(grep -c '^DKEK key check value' <<< "$status")" -eq 1 ] && [ -n "$CARD_KCV" ] \
  || die "card $SERIAL holds no complete DKEK (no key check value; an import may be pending): $(grep -i dkek <<< "$status" | tr '\n' ' ')"
[ "$CARD_KCV" = "$KCV" ] || die "card $SERIAL holds DKEK $CARD_KCV, not $KCV, the domain --expect-kcv names: wrong card, or wrong share imported"
ok "card $SERIAL holds DKEK $CARD_KCV"
if [ "$COMMAND" != generate ]; then
  BLOB_KCV="$(cert_tool blob-kcv --blob "$BLOB")" || die "$BLOB is not a sc-hsm-tool wrapped key"
  if [ "$COMMAND" = restore ]; then
    [ "$BLOB_KCV" = "$CARD_KCV" ] || die "the blob was wrapped under DKEK $BLOB_KCV and card $SERIAL holds $CARD_KCV: it cannot restore here"
  else
    [ "$BLOB_KCV" != "$CARD_KCV" ] || die "card $SERIAL holds DKEK $CARD_KCV, the blob's own: it is the key's domain, not another one, and nothing is tried"
  fi
fi

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
  local kt mech; kt="$(cert_tool key-type --public-key "$2")" || return 1
  read -ra mech <<< "$(mechanism_for "$kt")"
  p11_pin --id "$1" --sign "${mech[@]}" --input-file "$W/challenge" --output-file "$W/challenge.sig" >/dev/null 2>&1 || return 1
  openssl dgst -sha256 -verify "$W/check.pem" -signature "$W/challenge.sig" "$W/challenge" >/dev/null 2>&1 || return 1
  if openssl dgst -sha256 -verify "$W/check.pem" -signature "$W/challenge.sig" "$W/other" >/dev/null 2>&1; then return 2; fi
  return 0
}

if [ "$COMMAND" = generate ]; then
  # ---- 3. the id is free; what wraps before ---------------------------------------------------------
  ids="$(pubkey_ids)" || die "the card did not list its public keys: whether id $ID is free is not known"
  grep -qx "$ID" <<< "$ids" && die "object id $ID is already in use on card $SERIAL"
  before="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap: nothing was generated"
  # ... and as many as the card's private keys: a reference that failed to wrap in BOTH probes would
  # otherwise look new after generating, and another key's blob would be recorded as this one's
  privs="$(object_ids privkey)" || die "the card did not list its private keys"
  [ "$(wc -w <<< "$before")" = "$(grep -c . <<< "$privs")" ] \
    || die "$(wc -w <<< "$before") key references wrap but the card lists $(grep -c . <<< "$privs") private keys: the probes did not see every key; nothing was generated"
  # ---- 4. the key, on the card ----------------------------------------------------------------------
  # From here the card may hold a key at $ID whatever this script learns of it (a lost answer, a signal):
  # the exit trap looks.
  KEY_ASKED=1
  case "$KEY_TYPE" in rsa:2048) p11_type=rsa:2048;; ec:prime256v1) p11_type=EC:prime256v1;; esac
  gen="$(p11_pin --keypairgen --key-type "$p11_type" --id "$ID" --label "$LABEL" 2>&1)" \
    || die "the card did not report a generated key ($(grep -aoE 'CKR_[A-Z_]+' <<< "$gen" | head -1 | sed 's/$/, /')pkcs11-tool failed)"
  ok "$KEY_TYPE key $LABEL generated on card $SERIAL at id $ID"
  # ---- 5. its key reference -------------------------------------------------------------------------
  after="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap after generating"
  REF=""; count=0
  for r in $after; do case " $before " in *" $r "*) ;; *) REF="$r"; count=$((count + 1));; esac; done
  [ "$count" -eq 1 ] || die "expected exactly one new key reference after generating, found $count (before:${before:- none}, after:${after:- none})"
  for r in $before; do case " $after " in *" $r "*) ;; *) die "key reference $r wrapped before generating and does not now: the card's answers are not stable";; esac; done
  privs="$(object_ids privkey)" || die "the card did not list its private keys after generating"
  [ "$(wc -w <<< "$after")" = "$(grep -c . <<< "$privs")" ] \
    || die "$(wc -w <<< "$after") key references wrap but the card lists $(grep -c . <<< "$privs") private keys after generating: which reference is the new key's is not known"
  ok "its key reference is $REF"
  # ---- 6. the certificate, signed by the card ---------------------------------------------------------
  read_pubkey "$ID" "$W/pub.der" || die "cannot read the public key of id $ID"
  got="$(cert_tool key-type --public-key "$W/pub.der")" || die "the public key at id $ID is of no type this tool certifies"
  [ "$got" = "$KEY_TYPE" ] || die "the card generated a $got key at id $ID, not the $KEY_TYPE asked for"
  serial_hex="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"; serial_hex="1${serial_hex:1}"   # 128 bits, positive
  cert_tool tbs --public-key "$W/pub.der" --subject "$SUBJECT" --days "$DAYS" --serial-hex "$serial_hex" --out "$W/tbs.der" || exit 1
  read -ra mech <<< "$(mechanism_for "$KEY_TYPE")"
  p11_pin --id "$ID" --sign "${mech[@]}" --input-file "$W/tbs.der" --output-file "$W/tbs.sig" >/dev/null 2>&1 \
    || die "the card did not sign the certificate"
  cert_tool assemble --tbs "$W/tbs.der" --signature "$W/tbs.sig" --out "$W/crt.pem" || exit 1
  cert_tool check --certificate "$W/crt.pem" --public-key "$W/pub.der" >/dev/null || die "the certificate the card signed does not verify"
  ok "certificate signed by the card, and it verifies under the card's key"
  sign_check "$ID" "$W/pub.der"; rc=$?
  case "$rc" in 0) ;; 2) die "the signature check accepted other data: the check proves nothing";;
    *) die "the key at id $ID did not sign a fresh challenge that verifies under its public key";; esac
  ok "it signs a fresh challenge, and the signature does not verify for other data"
  # ---- 6b. the card's own evidence: C.DevAut, and the attestation of THIS key ------------------------------
  [ -r "$DEVAUT_SH" ] && [ -r "$ATTEST_SH" ] && [ -r "$ATTEST_PY" ] && [ -d "$TRUST_DIR" ] \
    || die "the device-attestation tools or the CardContact trust anchors are missing (hsm-devaut-read.sh, hsm-key-attestation-read.sh, hsm-key-attestation-verify.py, qubes/trust-anchors/smartcard-hsm)"
  find_reader
  devout="$DEVOUT"
  attout="$(timeout 60 bash "$ATTEST_SH" --reader "$READER" --expect-serial "$SERIAL" --key-ref "$REF" 2>&1)" \
    || die "the card has no attestation for key reference $REF (EF CE$(printf '%02X' "$REF")): a generated key always has one. $(tail -1 <<< "$attout")"
  hex_to(){ cert_tool unhex --out "$1"; }
  grep -oE '^DEVAUT_HEX=[0-9A-Fa-f]+' <<< "$devout" | cut -d= -f2 | hex_to "$W/devaut.bin" && [ -s "$W/devaut.bin" ] || die "the device certificate could not be read whole"
  grep -oE '^ATTEST_HEX=[0-9A-Fa-f]+' <<< "$attout" | cut -d= -f2 | hex_to "$W/attest.bin" && [ -s "$W/attest.bin" ] || die "the attestation could not be read whole"
  # shellcheck source=/dev/null
  py_bin="$(. "$CEREMONY_PY_SH" && ceremony_python_find cryptography cvc)" && [ -x "$py_bin/python3" ] \
    || die "no Python interpreter here can import pycvc and cryptography: the card's attestation CANNOT BE EVALUATED"
  ver="$(timeout 60 "$py_bin/python3" -Es "$ATTEST_PY" --devaut "$W/devaut.bin" --attestation "$W/attest.bin" \
           --trust-dir "$TRUST_DIR" --expect-spki "$W/pub.der" 2>&1)"; vrc=$?
  { [ "$vrc" -eq 0 ] && grep -qx 'DEVAUT_CHAIN=verified' <<< "$ver" && grep -qx 'ATTEST_SIGNATURE=verified' <<< "$ver" \
      && grep -qx 'ATTESTED_KEY_MATCHES=yes' <<< "$ver"; } \
    || die "the card's attestation does not prove this key was generated on this genuine card (exit $vrc): $(grep -E '^(DEVAUT_CHAIN|ATTEST_SIGNATURE|ATTESTED_KEY_MATCHES)=' <<< "$ver" | tr '\n' ' ')"
  ok "C.DevAut chains to CardContact's root, and the card attests it generated THIS key (EF CE$(printf '%02X' "$REF"))"
  # ---- 7. the backup ----------------------------------------------------------------------------------
  schsm_pin --wrap-key "$W/wrapped.bin" --key-reference "$REF" >/dev/null 2>&1 && [ -s "$W/wrapped.bin" ] \
    || die "sc-hsm-tool --wrap-key failed for key reference $REF (does the card hold its DKEK?)"
  [ "$(cert_tool blob-kcv --blob "$W/wrapped.bin")" = "$CARD_KCV" ] || die "the blob does not name DKEK $CARD_KCV"
  ok "DKEK-wrapped blob written, under DKEK $CARD_KCV"
  # ---- 8. the record, last; then all four files, or none ----------------------------------------------
  cert_tool evidence --device-serial "$SERIAL" --object-id "$ID" --key-reference "$REF" --label "$LABEL" --public-key "$W/pub.der" \
    --certificate "$W/crt.pem" --blob "$W/wrapped.bin" --dkek-kcv "$CARD_KCV" --devaut "$W/devaut.bin" --attestation "$W/attest.bin" --out "$W/evidence.json" || exit 1
  # Staged under temporary names in --out, then renamed, the record last. Until DONE the exit trap removes
  # every name listed in WRITTEN and deletes the key: a blob that restores must not outlive a refusal.
  for f in crt.pem pub.der wrapped.bin evidence.json; do
    WRITTEN+=("$OUT/.$LABEL.$f.tmp")
    cp "$W/$f" "$OUT/.$LABEL.$f.tmp" || die "cannot write into $OUT"
  done
  for f in crt.pem pub.der wrapped.bin evidence.json; do
    # mv -n returns 0 without moving when the target appeared meanwhile: the .tmp still being there says so,
    # and then the target is someone else's file, which the trap must not remove
    mv -n "$OUT/.$LABEL.$f.tmp" "$OUT/$LABEL.$f" && [ ! -e "$OUT/.$LABEL.$f.tmp" ] || die "cannot put $OUT/$LABEL.$f in place"
    WRITTEN+=("$OUT/$LABEL.$f")
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
PRIV_BEFORE="$(object_ids privkey)" || die "card $SERIAL did not list its private keys"
# One public object per id: with two under one id, a read returns one of them and the other is never compared.
[ -z "$(sort <<< "$IDS_BEFORE" | uniq -d)" ] || die "card $SERIAL lists two public keys under one id: what it holds cannot be read reliably"
for id in $IDS_BEFORE; do
  read_pubkey "$id" "$W/before-$id.der" || die "cannot read the public key at id $id on card $SERIAL: whether it already holds this key is not known"
  cmp -s "$W/before-$id.der" "$W/want.der" && die "card $SERIAL already holds this key (id $id): a restore onto it would prove nothing about the blob"
done
used="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap: nothing was unwrapped"
[ -r "$ATTEST_SH" ] && [ -r "$DEVAUT_SH" ] || die "hsm-key-attestation-read.sh and hsm-devaut-read.sh are needed to find a free key reference"
find_reader
DEST=""
for r in $(seq 1 "$MAX_REF"); do
  case " $used " in *" $r "*) continue;; esac
  ce="$(ce_file "$r")" || die "could not tell whether EF CE$(printf '%02X' "$r") exists on card $SERIAL: nothing was unwrapped"
  [ "$ce" = absent ] && { DEST="$r"; break; }
done
[ -n "$DEST" ] || die "no free key reference on card $SERIAL (none of 1..$MAX_REF has neither a key nor a left-over EF CE<ref>)"
# From here the spare may hold a key nothing vouched for: the exit trap removes it unless DONE.
UNWRAPPED=1
# sc-hsm-tool --unwrap-key exited 1 even on success on 2026-08-06 (hsm-recovery-drill.sh) and 0 on 2026-10-03
# (DENK0404380): judged by its output, never by its status.
out="$(schsm_pin --unwrap-key "$BLOB" --key-reference "$DEST" 2>&1)"
# A card whose DKEK is not the blob's answers this, and only this (measured 2026-10-03, DENK0404380): it
# looks the DKEK up by the blob's check value and has none. Any other failure (a left-over EF CE<ref>, a
# reader error, a wrong PIN) says nothing about the domain.
WRONG_DKEK='SC_CARDCTL_SC_HSM_UNWRAP_KEY, \*) failed with Data object not found'
if [ "$COMMAND" = refuse ]; then
  # The proof that ANOTHER domain's card cannot hold this key. Passes only when the card gave the wrong-DKEK
  # answer AND no new key reference wraps afterwards (probed twice). An unwrap that succeeded leaves the exit
  # trap to delete what it put there, and refuses loudly: the separation this domain exists for did not hold.
  now="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap after the attempt: whether it took the key is not known"
  if ! grep -qi 'successfully imported' <<< "$out" && [ "$now" = "$used" ] && ! grep -q "$WRONG_DKEK" <<< "$out"; then
    UNWRAPPED=""
    die "card $SERIAL did not unwrap the blob, but not with the answer a card of another DKEK gives, so this proves nothing about the domain: $(tail -1 <<< "$out")"
  fi
  if ! grep -qi 'successfully imported' <<< "$out" && [ "$now" = "$used" ]; then
    UNWRAPPED=""; DONE=1; unset PIN
    printf 'REFUSED-AS-REQUIRED card %s would not unwrap %s: its DKEK is not the blob'"'"'s (%s)\n' "$SERIAL" "$(basename "$BLOB")" "$(tail -1 <<< "$out")"
    exit 0
  fi
  die "CARD $SERIAL UNWRAPPED THE BLOB: its DKEK is the blob's, so the key's domain is NOT separate from this card's. The key it put there is being deleted; do not use this blob or this DKEK until that is understood"
fi
grep -qi 'successfully imported' <<< "$out" \
  || die "card $SERIAL did not unwrap the blob: $(tail -1 <<< "$out")"
now="$(wrappable_refs)" || die "the card gave two different answers about which key references wrap after the unwrap"
case " $now " in *" $DEST "*) ;; *) die "after the unwrap key reference $DEST does not wrap: the blob did not put a key there";; esac
ids="$(pubkey_ids)" || die "card $SERIAL did not list its public keys after the unwrap"
found=""
for id in $ids; do
  read_pubkey "$id" "$W/have.der" || die "cannot read the public key at id $id after the unwrap"
  # only a public key that was NOT there before can be the blob's: a new id, or an id whose bytes changed
  [ -f "$W/before-$id.der" ] && cmp -s "$W/have.der" "$W/before-$id.der" && continue
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
