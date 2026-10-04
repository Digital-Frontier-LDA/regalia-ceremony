#!/usr/bin/env bash
# hsm-domain.sh — a DKEK domain of its own for each key of the token ceremony (regalia-ceremony#111): the
# membership root, the boot-image signing key and the revocation key, each on a card and a spare that share a
# DKEK used by nothing else, so no blob of one key can ever be unwrapped on another key's cards or a KMS host's.
#
#   hsm-domain.sh create   --domain root|signing|revocation --serial SERIAL --dir DIR
#   hsm-domain.sh load     --domain D --serial SERIAL --dir DIR --first | --expect-kcv KCV
#   hsm-domain.sh disjoint --kcv NAME=KCV ... [--hosts-not-yet]
#   hsm-domain.sh backup   --domain D --dir DIR --kcv KCV --recipient-file FILE
#
# ONE SHARE, ONE PASSWORD, NO SPLIT. A domain's DKEK is one share under one generated password (sixty-four
# hex digits from /dev/urandom), never an n-of-m password split: ADR-0002 D19 backs up a later software
# secret by encrypting it to the break-glass key, not by splitting it again. `backup` writes the share and its
# password into one age file to the break-glass recipient; that file and the two cards are the domain.
#
# create, on the domain's FIRST card, with ONLY that card attached (sc-hsm-tool makes the share with the
# card's random number generator, so it needs a card, and the card it would take by default is a guess):
#   DIR/D.pbe (the password-encrypted share) and DIR/D.pw (its password), 0600, in DIR, which must be a RAM
#   file system (tmpfs or ramfs; CEREMONY_ALLOW_NONTMPFS=1 for tests). The password reaches sc-hsm-tool only
#   through its environment (--password env:NAME), never argv. Nothing that exists is overwritten.
#
# load, on each card of the domain, with ONLY that card attached, after hsm-init-hardened.sh --dkek-shares 1:
#   the card must be waiting for its one share (DKEK import pending). The share is imported, and the card
#   must then report a complete DKEK; its key check value is printed (DOMAIN D card S KCV K). The first card
#   is loaded with --first; every other with --expect-kcv (the first card's value), which must match: two cards
#   share a DKEK iff their KCVs match, and a second card loaded without it would define its own domain unseen. A card that already holds a complete DKEK is not imported into again: with --expect-kcv equal
#   to its value it is reported as loaded (a re-run), otherwise refused. EXIT STATUS IS NOT INTEGRITY
#   (regalia#460): the state read back from the card decides, never the import's exit status.
#
# disjoint: every key check value given must be sixteen hex digits, not all zero, and different from every
# other. root, signing and revocation are required, and at least one other domain (the hosts' ceremony's
# dkek.kcv, each production host card's KCV read without a PIN) unless --hosts-not-yet, which is printed as
# such. A KCV is a fingerprint of the DKEK: equal values mean the same DKEK, and this refuses them. The
# cryptographic proof is hsm-signing-key.sh refuse, run on a card of every other domain.
#
# backup: DIR/dkek-D.age, to the recipient in FILE (the break-glass key, age1pq1… or age1…). The plaintext
# never touches a file: it goes to age on stdin. The result must be an age file that contains neither the
# password nor the share's bytes in the clear, and only then are DIR/D.pbe and DIR/D.pw shredded, by their
# exact names. Its SHA-256 is printed for the ceremony record. Run it after BOTH cards are loaded: it removes
# the share the second card would need.
set -uo pipefail
if [ -n "${LC_ALL:-}" ]; then
  for _lc in LANG LC_CTYPE LC_NUMERIC LC_TIME LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS \
             LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION; do export "$_lc=$LC_ALL"; done
  unset LC_ALL _lc
fi
export LC_COLLATE=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
die(){ printf 'hsm-domain: REFUSED: %s\n' "$*" >&2; exit 1; }
need(){ [ -n "${2-}" ] || die "$1 needs a value"; }
ok(){ printf '  ok  %s\n' "$*"; }
is_kcv(){ case "$1" in [0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]) [ "$1" != 0000000000000000 ];; *) false;; esac; }
upper(){ printf '%s' "$1" | tr 'a-f' 'A-F'; }

COMMAND="${1-}"; [ $# -gt 0 ] && shift
DOMAIN="" SERIAL="" DIR="" KCV="" RECIPIENT_FILE="" HOSTS_NOT_YET=0 FIRST=0 KCVS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --domain)         need "$1" "${2-}"; DOMAIN="$2"; shift 2;;
    --serial)         need "$1" "${2-}"; SERIAL="$2"; shift 2;;
    --dir)            need "$1" "${2-}"; DIR="$2"; shift 2;;
    --expect-kcv)     need "$1" "${2-}"; KCV="$(upper "$2")"; shift 2;;
    --kcv)            need "$1" "${2-}"; if [ "$COMMAND" = disjoint ]; then KCVS+=("$2"); else KCV="$(upper "$2")"; fi; shift 2;;
    --recipient-file) need "$1" "${2-}"; RECIPIENT_FILE="$2"; shift 2;;
    --hosts-not-yet)  HOSTS_NOT_YET=1; shift;;
    --first)          FIRST=1; shift;;
    --password|--password=*|--pin|--so-pin) die "no secret is taken on the command line";;
    -h|--help) sed -n '2,9p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done
case "$COMMAND" in create|load|disjoint|backup) ;; *) die "the first argument is create, load, disjoint or backup";; esac

# ---- disjoint: no card ----------------------------------------------------------------------------------
if [ "$COMMAND" = disjoint ]; then
  declare -A by_name=() by_value=()
  for pair in ${KCVS[@]+"${KCVS[@]}"}; do
    case "$pair" in *=*) ;; *) die "--kcv takes NAME=KCV, not '$pair'";; esac
    name="${pair%%=*}" value="$(upper "${pair#*=}")"
    case "$name" in ''|*[!a-z0-9-]*) die "--kcv name '$name' is lowercase letters, digits and dashes";; esac
    is_kcv "$value" || die "--kcv $name=${pair#*=}: a key check value is sixteen hex digits and not all zero"
    [ -z "${by_name[$name]+x}" ] || die "--kcv $name is given twice"
    [ -z "${by_value[$value]+x}" ] || die "DOMAINS NOT DISJOINT: $name and ${by_value[$value]} have the same DKEK key check value $value"
    by_name[$name]="$value"; by_value[$value]="$name"
  done
  for d in root signing revocation; do [ -n "${by_name[$d]+x}" ] || die "--kcv $d=… is required"; done
  others=0; for name in "${!by_name[@]}"; do case "$name" in root|signing|revocation) ;; *) others=$((others + 1));; esac; done
  [ "$others" -gt 0 ] || [ "$HOSTS_NOT_YET" = 1 ] \
    || die "no other domain's key check value is given (the hosts' ceremony's dkek.kcv, a host card's): pass them, or --hosts-not-yet, which the record states"
  for name in $(printf '%s\n' "${!by_name[@]}" | sort); do printf 'DISJOINT %s %s\n' "$name" "${by_name[$name]}"; done
  [ "$others" -gt 0 ] || echo "DISJOINT others none (--hosts-not-yet): the token domains were not compared with the KMS hosts'"
  exit 0
fi

case "$DOMAIN" in root|signing|revocation) ;; *) die "--domain is root, signing or revocation";; esac
[ -n "$DIR" ] && [ -d "$DIR" ] || die "--dir must be an existing directory"
SHARE="$DIR/$DOMAIN.pbe" PWFILE="$DIR/$DOMAIN.pw" AGEFILE="$DIR/dkek-$DOMAIN.age"
absent(){ { [ ! -e "$1" ] && [ ! -L "$1" ]; } || die "$1 already exists: nothing is overwritten"; }

# ---- backup: no card --------------------------------------------------------------------------------------
if [ "$COMMAND" = backup ]; then
  is_kcv "$KCV" || die "--kcv is the domain's key check value (sixteen hex digits), as load printed it"
  [ -s "$RECIPIENT_FILE" ] || die "--recipient-file must name the break-glass recipient file"
  recipient="$(head -n 1 "$RECIPIENT_FILE" | tr -d '[:space:]')"
  case "$recipient" in age1pq1*|age1*) ;; *) die "$RECIPIENT_FILE does not hold an age recipient";; esac
  [ -f "$SHARE" ] && [ ! -L "$SHARE" ] && [ -s "$SHARE" ] || die "$SHARE is missing: backup runs after create and both loads, once"
  [ -f "$PWFILE" ] && [ ! -L "$PWFILE" ] && [ -s "$PWFILE" ] || die "$PWFILE is missing"
  absent "$AGEFILE"
  command -v age >/dev/null 2>&1 || die "age is not installed"
  tmp="$DIR/.dkek-$DOMAIN.age.$$"; absent "$tmp"
  pw="$(cat "$PWFILE")"; share_b64="$(base64 -w0 < "$SHARE")"
  ( umask 077
    printf 'regalia.dkek-share/v1\ndomain %s\nkcv %s\npassword %s\nshare %s\n' "$DOMAIN" "$KCV" "$pw" "$share_b64" \
      | age -r "$recipient" -o "$tmp" ) || { rm -f "$tmp"; die "age could not encrypt the share"; }
  [ "$(head -c 21 "$tmp")" = "age-encryption.org/v1" ] || { rm -f "$tmp"; die "age wrote no age file"; }
  # the patterns reach grep on a descriptor (printf is a builtin): never on its argv, where /proc shows them
  if grep -qaF -f <(printf '%s\n%s\n' "$pw" "$share_b64") "$tmp"; then rm -f "$tmp"; die "the age file holds the password or the share in the clear"; fi
  mv -n "$tmp" "$AGEFILE" && [ ! -e "$tmp" ] || { rm -f "$tmp"; die "cannot put $AGEFILE in place"; }
  unset pw share_b64
  shred -u "$SHARE" "$PWFILE" 2>/dev/null || rm -f "$SHARE" "$PWFILE"
  { [ ! -e "$SHARE" ] && [ ! -e "$PWFILE" ]; } || die "the plaintext share or password is still in $DIR: remove $SHARE and $PWFILE"
  printf 'BACKUP %s %s sha256 %s\n' "$DOMAIN" "$AGEFILE" "$(sha256sum "$AGEFILE" | cut -d' ' -f1)"
  exit 0
fi

# ---- create and load: one card, by serial -------------------------------------------------------------------
[ -n "$SERIAL" ] || die "--serial is required"
case "$SERIAL" in *[!A-Za-z0-9]*) die "--serial '$SERIAL' is not a serial";; esac
first_file(){ local c; for c in "$@"; do [ -f "$c" ] && { printf '%s' "$c"; return 0; }; done; return 1; }
MODULE="${CEREMONY_PKCS11_MODULE:-${HSM_PKCS11_MODULE:-}}"
[ -n "$MODULE" ] || MODULE="$(first_file /usr/lib/*/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so /usr/local/lib/opensc-pkcs11.so)" \
  || die "no opensc-pkcs11 module found (set CEREMONY_PKCS11_MODULE)"
for t in pkcs11-tool sc-hsm-tool opensc-tool timeout; do command -v "$t" >/dev/null 2>&1 || die "$t is not installed"; done
DEVAUT_SH="${HSM_DEVAUT_READ_SH:-$HERE/hsm-devaut-read.sh}"
[ -r "$DEVAUT_SH" ] || die "hsm-devaut-read.sh is needed to find the reader that holds card $SERIAL"
# shellcheck source=hsm-card.sh
. "$HERE/hsm-card.sh"
hsm_only_token
find_reader
ok "card $SERIAL is the only token attached (reader $READER)"

if [ "$COMMAND" = create ]; then
  fs="$(stat -f -c %T "$DIR" 2>/dev/null)"
  case "$fs" in tmpfs|ramfs) ;; *) [ "${CEREMONY_ALLOW_NONTMPFS:-}" = 1 ] || die "$DIR is on $fs, not a RAM file system: the share and its password are never written to a disk";; esac
  absent "$SHARE"; absent "$PWFILE"; absent "$AGEFILE"
  pw="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  [ "${#pw}" -eq 64 ] || die "no random password could be read"
  ( umask 077; printf '%s' "$pw" > "$PWFILE" ) || die "cannot write $PWFILE"
  REGALIA_DKEK_PW="$pw" timeout 120 sc-hsm-tool --reader "$READER" --create-dkek-share "$SHARE" --password env:REGALIA_DKEK_PW </dev/null >/dev/null 2>&1
  unset pw
  # the artefact decides, not the exit status: with no card the tool writes nothing and may still exit 0
  [ -f "$SHARE" ] && [ -s "$SHARE" ] || { rm -f "$SHARE" "$PWFILE"; die "sc-hsm-tool wrote no DKEK share for domain $DOMAIN on card $SERIAL"; }
  chmod 600 "$SHARE"
  printf 'CREATED %s share %s on card %s\n' "$DOMAIN" "$SHARE" "$SERIAL"
  exit 0
fi

# load
[ -z "$KCV" ] || is_kcv "$KCV" || die "--expect-kcv is sixteen hex digits, as load prints the key check value"
[ "$FIRST" = 1 ] && [ -n "$KCV" ] && die "--first and --expect-kcv: the first card defines the key check value, every other card is held to it"
[ "$FIRST" = 1 ] || [ -n "$KCV" ] || die "--first (the domain's first card) or --expect-kcv KCV (every other card, with the first card's value)"
hsm_dkek_state
case "$CARD_DKEK" in
  complete)
    [ -n "$KCV" ] && [ "$CARD_KCV" = "$KCV" ] && { printf 'DOMAIN %s card %s KCV %s (already loaded)\n' "$DOMAIN" "$SERIAL" "$CARD_KCV"; exit 0; }
    die "card $SERIAL already holds DKEK $CARD_KCV${KCV:+, not $KCV}: nothing is imported over a complete DKEK (re-initialise it with hsm-init-hardened.sh, or pass --expect-kcv $CARD_KCV if it is already this domain's)";;
  none) die "card $SERIAL has no DKEK share configured: initialise it with hsm-init-hardened.sh --dkek-shares 1 first";;
  pending) ;;
esac
[ -f "$SHARE" ] && [ ! -L "$SHARE" ] && [ -s "$SHARE" ] && [ -f "$PWFILE" ] && [ -s "$PWFILE" ] \
  || die "$SHARE and $PWFILE are needed: create the domain first (this share is gone once backup has run)"
REGALIA_DKEK_PW="$(cat "$PWFILE")" timeout 120 sc-hsm-tool --reader "$READER" --import-dkek-share "$SHARE" --password env:REGALIA_DKEK_PW </dev/null >/dev/null 2>&1
hsm_dkek_state
[ "$CARD_DKEK" = complete ] || die "card $SERIAL did not take the share of domain $DOMAIN (its DKEK is $CARD_DKEK)"
[ -z "$KCV" ] || [ "$CARD_KCV" = "$KCV" ] \
  || die "card $SERIAL now holds DKEK $CARD_KCV, not $KCV: it is NOT in domain $DOMAIN (a wrong share, or a password that decrypted to another key, #460). Re-initialise it"
printf 'DOMAIN %s card %s KCV %s\n' "$DOMAIN" "$SERIAL" "$CARD_KCV"
