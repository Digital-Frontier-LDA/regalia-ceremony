#!/usr/bin/env bash
# pin-escrow.sh — after a PIN change, escrow the current day-to-day PINs encrypted to the breakglass
# recipient and authenticated with the ceremony's escrow MAC key (CEREMONY-PLAN.md, "The PIN card";
# escrow/README.md). Run on the offline machine, from a checkout of this repository, with the PIN
# card open.
#
#   /media/<archive disc>/bin/pin-escrow.sh        # from the checkout's top directory
#
# Run the ARCHIVE DISC's copy (checked with its SHA256SUMS), never this repository's: anyone who can
# write here could change this script to skip a check or send the PINs elsewhere. It refuses to run
# from inside the checkout it writes to.
#
# It refuses, and writes nothing, unless:
#   - escrow/breakglass.recipient's sha256 starts with the 16 hex written on the PIN card (typed here):
#     write access to this repository alone must not redirect the PINs;
#   - the escrow MAC key typed from the PIN card matches escrow/escrow-mac.kcv (from the ceremony's
#     archive disc), so a mistyped key cannot produce a file that recovery would then reject;
#   - every one of the six devices' PINs is typed twice, hidden, and the two agree and have the
#     device's shape (Nitrokey HSM user PIN 10-15 digits; YubiKey PIV PIN 6-8 printable single-byte
#     characters, the credential contract of qubes/CREDENTIAL-SEPARATION.md);
# and it:
#   - keeps the plaintext in tmpfs (/dev/shm) only, removed after encryption, and stops on any write
#     failure (a full tmpfs must not yield a truncated escrow);
#   - names the file by a monotonic sequence, escrow/pins-NNNN.age (one more than the highest escrow
#     anywhere in the history whose MAC verifies),
#     not by a date an offline clock could get wrong, and writes its MAC to escrow/pins-NNNN.age.mac.
#     Recovery uses the highest file whose MAC verifies; repository write access cannot forge one.
#
# Tests only: PIN_ESCROW_TEST_DEVICES="hsm_a yubikey_a" escrows a reduced set, and then names the
# files test-pins-NNNN.age, which recovery never selects.
set -uo pipefail
die(){ printf 'pin-escrow: %s\n' "$*" >&2; exit 1; }
[ $# -eq 0 ] || { sed -n '2,25p' "$0"; [ "$1" = -h ] || [ "$1" = --help ]; exit; }
DEVICES="hsm_a hsm_b hsm_c yubikey_a yubikey_b yubikey_c"; PREFIX=pins
if [ -n "${PIN_ESCROW_TEST_DEVICES:-}" ]; then
  DEVICES="$PIN_ESCROW_TEST_DEVICES"; PREFIX=test-pins
  printf 'pin-escrow: TEST MODE (%s): writes test-pins-NNNN.age, which recovery ignores\n' "$DEVICES" >&2
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
TOP="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run from a checkout of this repository"
cd "$TOP" || exit 1
case "$HERE/" in "$TOP"/*) die "this is the repository's copy of the tool: run the archive disc's bin/pin-escrow.sh (sha256sum -c SHA256SUMS first)";; esac
RCP="escrow/breakglass.recipient"; KCV="escrow/escrow-mac.kcv"
[ -s "$RCP" ] || die "$RCP is missing: it is committed right after the ceremony"
[ -s "$KCV" ] || die "$KCV is missing: it is committed right after the ceremony, from the archive disc"
# The disc's own age, next to this script and under the same SHA256SUMS: never whichever age is first on
# PATH, which would receive the plaintext PINs without having been checked.
AGE="$HERE/age"
[ -x "$AGE" ] || die "no age next to this script ($AGE): run the archive disc's bin/pin-escrow.sh, whose bin/ holds the checked age"
command -v python3 >/dev/null || die "python3 is required (the MAC)"
# RAM only: /dev/shm must be a tmpfs mount, not just a directory (a disk-backed or bind-mounted one
# would keep the PINs). CEREMONY_ALLOW_NONTMPFS=1 is the test-only override, as in ceremony.sh.
if ! grep -qs "[[:space:]]/dev/shm[[:space:]]tmpfs[[:space:]]" /proc/mounts; then
  [ "${CEREMONY_ALLOW_NONTMPFS:-}" = 1 ] && [ -d /dev/shm ] \
    || die "/dev/shm is not a tmpfs mount: refusing to write the PINs where they could reach a disk"
  printf 'pin-escrow: /dev/shm is NOT tmpfs (CEREMONY_ALLOW_NONTMPFS=1: tests only)\n' >&2
fi

# Input: hidden prompts on a terminal; one value per line on stdin otherwise (tests).
ask(){ local v; if [ -t 0 ]; then read -r -s -p "$1" v; echo >&2; else IFS= read -r v || v=""; fi; printf '%s' "$v"; }

fp="$(sha256sum "$RCP" | cut -c1-16)"
typed="$(ask "First 16 hex of the breakglass recipient fingerprint, from the PIN card: ")"
typed="$(tr 'A-F' 'a-f' <<< "${typed//[[:space:]:]/}")"
[ "$typed" = "$fp" ] || die "the recipient in this checkout is NOT the one on the PIN card: STOP, nothing written"

key="$(ask "Escrow MAC key (32 hex), from the PIN card: ")"
kcv="$(python3 "$HERE/pin_escrow_mac.py" kcv <<< "$key")" || die "that is not a 32-hex escrow MAC key; nothing written"
[ "$kcv" = "$(tr -d '[:space:]' < "$KCV")" ] || die "the escrow MAC key does not match $KCV (mistyped?); nothing written"

declare -A pin
for d in $DEVICES; do
  case "$d" in
    hsm_[abc]) re='^[0-9]{10,15}$'; what="10-15 digits";;
    yubikey_[abc]) re='^[[:print:]]{6,8}$'; what="6-8 printable single-byte characters";;
    *) die "unknown device id '$d' (hsm_a..c, yubikey_a..c)";;
  esac
  a="$(ask "$d PIN, from the PIN card: ")"; b="$(ask "$d PIN again: ")"
  [ "$a" = "$b" ] || die "the two entries for $d differ; nothing written"
  LC_ALL=C; [[ "$a" =~ $re ]] || die "the $d PIN must be $what; nothing written"; unset LC_ALL
  pin[$d]="$a"; a=""; b=""
done

# From the whole history, as recovery reads it, and from VERIFIED escrows only: a deleted escrow must not
# let the numbering restart below one recovery would still prefer, and a forged high-numbered file must
# not push the numbering up (or exhaust it).
last="$(python3 "$HERE/pin_escrow_mac.py" highest "$TOP" "$PREFIX" <<< "$key")" || die "cannot read the escrow history"
[ "$last" -lt 9999 ] || die "the escrow sequence is exhausted at 9999 (recovery reads four digits); nothing written"
next="$(printf '%04d' $((last + 1)))"
out="escrow/$PREFIX-$next.age"
# Anything already at the next name cannot verify (it is above the highest verified escrow): it was not
# written with the key. Replace it, and say so; it stays in history, where recovery skips it.
if [ -e "$out" ] || [ -e "$out.mac" ]; then
  printf 'pin-escrow: %s exists but does not verify (not written with the escrow MAC key): replacing it. Record it as an incident.\n' "$out" >&2
  rm -rf -- "$out" "$out.mac"
fi

tmp="$(mktemp /dev/shm/pin-escrow.XXXXXX)" || die "cannot create a file in /dev/shm"
trap 'rm -f "$tmp"' EXIT
( printf '# PIN escrow %s, written %s by tools/pin-escrow.sh; one device=PIN per line\n' "$next" "$(date -u +%FT%TZ)" \
  && for d in $DEVICES; do printf '%s=%s\n' "$d" "${pin[$d]}" || exit 1; done ) > "$tmp" \
  || die "could not write the plaintext to /dev/shm (full?); nothing written"
n="$(grep -cE '^(hsm|yubikey)_[abc]=' "$tmp")"
[ "$n" -eq "$(wc -w <<< "$DEVICES")" ] || die "the plaintext holds $n of $(wc -w <<< "$DEVICES") PINs; nothing written"
"$AGE" -R "$RCP" -o "$out" "$tmp" || { rm -f "$out"; die "encryption failed; nothing written"; }
rm -f "$tmp"
python3 "$HERE/pin_escrow_mac.py" mac "$out" <<< "$key" > "$out.mac" && [ -s "$out.mac" ] \
  || { rm -f "$out" "$out.mac"; die "could not write the MAC; nothing written"; }
key=""
cat <<REC
ESCROWED: $out and $out.mac (sequence $next, $n devices), encrypted to the recipient on the PIN card.
Commit both:
  git add $out $out.mac && git commit -m "escrow: PIN escrow $next"
REC
