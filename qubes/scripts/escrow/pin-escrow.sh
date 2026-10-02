#!/usr/bin/env bash
# pin-escrow.sh — after a PIN change, escrow the current day-to-day PINs encrypted to the breakglass
# recipient and authenticated with the ceremony's escrow MAC key (CEREMONY-PLAN.md, "The PIN card";
# escrow/README.md). Run on the offline machine, from a checkout of this repository, with the PIN
# card open.
#
#   /media/<archive disc>/bin/pin-escrow.sh        # from the checkout's top directory
#   /media/<archive disc>/bin/pin-escrow.sh --new-recovery-key    # print ONE new disk recovery key
#
# --new-recovery-key is for the day a KMS host's disk recovery key has been USED (a real recovery or
# a rehearsal) or its envelope seal is broken. It prints one new key, generated here from the
# system's random source, and writes nothing. A recovery key is never invented by hand: the host
# enrols it on the assumption that it holds 256 random bits. THE ORDER MATTERS:
#   1. write the new key on a new KMS host recovery card;
#   2. at the host: regalia-kms recovery-key.sh --replace (the used key, then the new one), then
#      --check with the key read from the new card;
#   3. ONLY THEN escrow it, with this tool and no argument. An escrow written before step 2 has
#      succeeded would hold, as the newest verified escrow, a key that opens nothing on that host.
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
#   - every one of the three KMS hosts' TPM lockout authorizations is typed twice too, from the KMS
#     HOST CARD (16-32 printable characters, no space). They are asked for at EVERY escrow, changed or
#     not, so that the newest escrow is always whole: recovery reads one file, and a value left out
#     here would send it back to the ceremony's copy, which at the host is a WRONG attempt if the
#     value changed since, and one wrong attempt blocks that TPM's lockout hierarchy for a day;
#   - every one of the three KMS hosts' disk recovery keys is typed twice as well, from the KMS HOST
#     RECOVERY CARD (8 groups of 8 lower-case letters with a dash between groups; the dashes are part
#     of the key), at EVERY escrow for the same reason: after a total outage recovery reads one file,
#     and a key that was replaced since the ceremony (regalia-kms recovery-key.sh --replace, after
#     any use) exists nowhere else;
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
# One definition of a disk recovery key's shape (systemd's recovery-key format, dashes included).
RECOVERY_KEY_RE='^([cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}$'
if [ "${1:-}" = --new-recovery-key ] && [ $# -eq 1 ]; then
  # 32 bytes from the kernel's random source, each half-byte as one letter: what systemd-cryptenroll
  # writes and what step 0 generates (ceremony.sh gen_secret recovery:256).
  # python3 -I (isolated): without it the CURRENT DIRECTORY is first on the module path, and this tool
  # is run from the top of the repository checkout. A secrets.py planted there by anyone who can
  # write to the repository would choose the key (measured: it printed cccccccc-…-cccccccc).
  key="$(python3 -I -c 'import secrets
letters = "".join("cbdefghijklnrtuv"[b >> 4] + "cbdefghijklnrtuv"[b & 15] for b in secrets.token_bytes(32))
print("-".join(letters[i:i + 8] for i in range(0, 64, 8)))')" || die "could not generate a key (python3)"
  [[ "$key" =~ $RECOVERY_KEY_RE ]] || die "the generator produced something that is not a recovery key; nothing shown"
  printf '%s\n' "$key"; key=""
  cat >&2 <<'NEXT'
A NEW DISK RECOVERY KEY, shown once and stored nowhere. The dashes are part of the key.
  1. Write it on a NEW KMS host recovery card, by hand, and check your copy letter by letter.
  2. At the host: recovery-key.sh --replace (the used key, then this one), then --check from the card.
  3. Only then run this tool with no argument to escrow it.
Clear this screen when it is written down.
NEXT
  exit 0
fi
# The header above, up to the first line that is not a comment: no line count to keep in step.
[ $# -eq 0 ] || { sed -n '2,/^set -uo pipefail$/{/^set -uo pipefail$/!p}' "$0"; [ "$1" = -h ] || [ "$1" = --help ]; exit; }
DEVICES="hsm_a hsm_b hsm_c yubikey_a yubikey_b yubikey_c tpm_a tpm_b tpm_c luks_a luks_b luks_c"; PREFIX=pins
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
# The key reaches Python through a pipe from the printf BUILTIN: never argv, and never a here-string,
# which some bash versions back with a temporary file on disk.
kcv="$(printf '%s\n' "$key" | python3 "$HERE/pin_escrow_mac.py" kcv)" || die "that is not a 32-hex escrow MAC key; nothing written"
[ "$kcv" = "$(tr -d '[:space:]' < "$KCV")" ] || die "the escrow MAC key does not match $KCV (mistyped?); nothing written"

declare -A pin
for d in $DEVICES; do
  case "$d" in
    hsm_[abc]) re='^[0-9]{10,15}$'; what="10-15 digits"; kind="PIN"; from="the PIN card";;
    yubikey_[abc]) re='^[[:print:]]{6,8}$'; what="6-8 printable single-byte characters"; kind="PIN"; from="the PIN card";;
    # A KMS host's TPM lockout authorization: what regalia-kms tpm-lockout.sh --set accepts.
    tpm_[abc]) re='^[[:graph:]]{16,32}$'; what="16-32 printable characters with no space"; kind="lockout authorization"; from="the KMS host card";;
    # A KMS host's disk recovery key: what regalia-kms recovery-key.sh accepts, dashes included.
    luks_[abc]) re="$RECOVERY_KEY_RE"; what="8 groups of 8 letters from cbdefghijklnrtuv with a dash between groups, lower case (the dashes are part of the key)"; kind="disk recovery key"; from="the KMS host recovery card";;
    *) die "unknown device id '$d' (hsm_a..c, yubikey_a..c, tpm_a..c, luks_a..c)";;
  esac
  a="$(ask "$d $kind, from $from: ")"; b="$(ask "$d $kind again: ")"
  [ "$a" = "$b" ] || die "the two entries for $d differ; nothing written"
  LC_ALL=C; [[ "$a" =~ $re ]] || die "the $d $kind must be $what; nothing written"; unset LC_ALL
  # Each KMS host has its own lockout authorization (step 0 generates three, and credential separation
  # refuses a repeat). The same value for two hosts here is a row of the card typed twice, and the
  # escrow would then hold a WRONG value for one of them: at that host, a wrong attempt.
  # The same holds for the disk recovery keys: a key escrowed under the wrong host opens nothing there.
  case "$d" in tpm_*|luks_*) for o in "${!pin[@]}"; do
    case "$o" in "${d%%_*}"_*) [ "${pin[$o]}" != "$a" ] || die "the $d $kind is the same as $o's: each KMS host has its own (the same row typed twice?); nothing written";; esac
  done;; esac
  pin[$d]="$a"; a=""; b=""
done

# From the whole history, as recovery reads it, and from VERIFIED escrows only: a deleted escrow must not
# let the numbering restart below one recovery would still prefer, and a forged high-numbered file must
# not push the numbering up (or exhaust it).
last="$(printf '%s\n' "$key" | python3 "$HERE/pin_escrow_mac.py" highest "$TOP" "$PREFIX")" || die "cannot read the escrow history"
[ "$last" -lt 9999 ] || die "the escrow sequence is exhausted at 9999 (recovery reads four digits); nothing written"
next="$(printf '%04d' $((last + 1)))"
out="escrow/$PREFIX-$next.age"
# Anything already at the next name cannot verify (it is above the highest verified escrow): it was not
# written with the key. Replace it, and say so; it stays in history, where recovery skips it.
# -L too: a dangling symlink is not -e, and writing through it would create its target.
if [ -e "$out" ] || [ -e "$out.mac" ] || [ -L "$out" ] || [ -L "$out.mac" ]; then
  printf 'pin-escrow: %s exists but does not verify (not written with the escrow MAC key): replacing it. Record it as an incident.\n' "$out" >&2
  # Check both paths before removing either: a directory collision is left whole for inspection.
  for f in "$out" "$out.mac"; do
    [ -L "$f" ] || [ ! -d "$f" ] || die "$f is a directory, not an escrow file: remove it by hand after checking it; nothing written"
  done
  for f in "$out" "$out.mac"; do
    { [ ! -e "$f" ] && [ ! -L "$f" ]; } || rm -f -- "$f" || die "cannot remove $f; nothing written"   # a link itself, never its target
  done
fi

tmp="$(mktemp /dev/shm/pin-escrow.XXXXXX)" || die "cannot create a file in /dev/shm"
trap 'rm -f "$tmp"' EXIT
( printf '# PIN escrow %s, written %s by tools/pin-escrow.sh; one device=PIN per line, tpm_<host>=<TPM lockout authorization> and luks_<host>=<disk recovery key>\n' "$next" "$(date -u +%FT%TZ)" \
  && for d in $DEVICES; do printf '%s=%s\n' "$d" "${pin[$d]}" || exit 1; done ) > "$tmp" \
  || die "could not write the plaintext to /dev/shm (full?); nothing written"
n="$(grep -cE '^(hsm|yubikey|tpm|luks)_[abc]=' "$tmp")"
[ "$n" -eq "$(wc -w <<< "$DEVICES")" ] || die "the plaintext holds $n of $(wc -w <<< "$DEVICES") values; nothing written"
pins="$(grep -cE '^(hsm|yubikey)_[abc]=' "$tmp")"; tpms="$(grep -cE '^tpm_[abc]=' "$tmp")"; luks="$(grep -cE '^luks_[abc]=' "$tmp")"
"$AGE" -R "$RCP" -o "$out" "$tmp" || { rm -f "$out"; die "encryption failed; nothing written"; }
rm -f "$tmp"
printf '%s\n' "$key" | python3 "$HERE/pin_escrow_mac.py" mac "$out" > "$out.mac" && [ -s "$out.mac" ] \
  || { rm -f "$out" "$out.mac"; die "could not write the MAC; nothing written"; }
key=""
cat <<REC
ESCROWED: $out and $out.mac (sequence $next: $pins device PIN(s), $tpms TPM lockout authorization(s), $luks disk recovery key(s)), encrypted to the recipient on the PIN card.
Commit both:
  git add $out $out.mac && git commit -m "escrow: PIN escrow $next"
REC
