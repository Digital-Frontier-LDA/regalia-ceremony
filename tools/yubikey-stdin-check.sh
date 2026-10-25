#!/usr/bin/env bash
# yubikey-stdin-check.sh --device SERIAL [--dry-run] — the owner's one hardware check for regalia-ceremony#98/#100:
# does the real ykman, on a real YubiKey, take a PIN change's two values from standard input when it is not a
# terminal? #100 makes ceremony.sh depend on that; the emulator cannot prove it.
#
# The check changes nothing on the card: the PIN is changed TO ITSELF, as ceremony.sh's binding proof does. It makes
# ONE attempt and never retries. A wrong PIN still costs a try, so it refuses to start unless the tries are full, and
# on a FAIL says how many remain.
#
#   tools/yubikey-stdin-check.sh --device 35718625 --dry-run   # reads the card, asks the PIN, changes nothing
#   tools/yubikey-stdin-check.sh --device 35718625             # the check
#
# The PIN is read from the terminal (/dev/tty), not from standard input: a stray `< file` or a pipe from an earlier
# command would otherwise feed a wrong PIN and spend a try (b9 on #153). --pin-stdin reads it from stdin instead, for
# a deliberate caller only.
#
# The PIN is read without echo, never on a command line (it reaches ykman through printf, a builtin), never traced
# (xtrace is off before it is read, whatever the caller set), never in a core dump (ulimit -c 0), and unset on every
# exit. The record printed at the end is for #98, a shared issue: the serial's last four digits only.
set +x                                   # before anything: `bash -x` or an exported SHELLOPTS=xtrace prints nothing here
ulimit -c 0 2>/dev/null || true
set -uo pipefail
# the collation pin of every script here whose ranges check caller input (test-locale-ranges.sh section 5): LC_ALL,
# which would override it, is moved into the other categories first
if [ -n "${LC_ALL:-}" ]; then
  for _lc in LANG LC_CTYPE LC_NUMERIC LC_TIME LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS \
             LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION; do export "$_lc=$LC_ALL"; done
  unset LC_ALL _lc
fi
export LC_COLLATE=C
export LC_CTYPE=C                        # bytes: the PIN's length, [[:graph:]] = 0x21-0x7e, ykman's output parsed as bytes
P=""
trap 'unset P' EXIT
trap 'unset P; echo; echo "yubikey-stdin-check: interrupted: nothing was sent to the card unless ATTEMPT was printed" >&2; exit 130' INT TERM

die(){ echo "yubikey-stdin-check: $*" >&2; exit 2; }
SERIAL=""; DRY=""; PIN_STDIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --device) SERIAL="${2:-}"; shift 2 || die "--device needs a serial" ;;
    --dry-run) DRY=1; shift ;;
    --pin-stdin) PIN_STDIN=1; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (only --device SERIAL, --dry-run and --pin-stdin)" ;;
  esac
done
[[ "$SERIAL" =~ ^[0-9]{6,10}$ ]] || die "--device must name the YubiKey's serial (6 to 10 digits), as ykman list --serials prints it"
last4="…${SERIAL: -4}"
command -v ykman >/dev/null || die "ykman is not installed"
BOUND="${YK_CHECK_TIMEOUT:-30}"
TTY="${YK_CHECK_TTY:-/dev/tty}"          # (the tests point it at a file; nothing else should)
if [ -z "$PIN_STDIN" ]; then
  { exec 3<"$TTY"; } 2>/dev/null || die "no terminal to read the PIN from ($TTY): run this at the console, or pass --pin-stdin to read it from standard input on purpose"
else
  exec 3<&0
fi
command -v timeout >/dev/null || die "timeout (coreutils) is not installed: the attempt must be bounded"

# 1. the card: present, the one named, and its tries full
serials="$(timeout 20 ykman list --serials 2>&1)" || die "ykman list --serials failed: $serials"
grep -qx "$SERIAL" <<< "$serials" || die "YubiKey $last4 is not connected (ykman sees: $(tr '\n' ' ' <<< "${serials:-none}" | sed -E 's/[0-9]*([0-9]{4})/…\1/g'))"
tries(){ local out n max
  out="$(timeout 20 ykman --device "$SERIAL" piv info 2>&1)" || { echo "ERR: $out"; return 1; }
  n="$(sed -nE 's/^PIN tries remaining: *([0-9]+)(\/([0-9]+))?.*/\1/p' <<< "$out" | head -1)"
  max="$(sed -nE 's/^PIN tries remaining: *([0-9]+)\/([0-9]+).*/\2/p' <<< "$out" | head -1)"
  [ -n "$n" ] || { echo "ERR: no 'PIN tries remaining' line in ykman piv info"; return 1; }
  echo "$n ${max:-3}"; }
t="$(tries)" || die "cannot read the PIN tries of $last4: ${t#ERR: }"
read -r before max <<< "$t"
[ "$before" = "$max" ] || die "YubiKey $last4 has $before of $max PIN tries left, not all: a wrong PIN here would bring it closer to a lockout. Not started; restore the counter first (a correct PIN resets it) and decide."
firmware="$(timeout 20 ykman --device "$SERIAL" info 2>/dev/null | sed -nE 's/^Firmware version: *//p' | head -1)"
ykv="$(timeout 20 ykman --version 2>/dev/null | sed -nE 's/.*version:? *([0-9][0-9.]*).*/\1/p' | head -1)"
echo "YubiKey $last4: firmware ${firmware:-unknown}, ykman ${ykv:-unknown}, PIN tries $before of $max"

# 2. the PIN: no echo, the rule ceremony.sh's yk_piv_change holds it to
printf 'PIV PIN of %s (not shown): ' "$last4" >&2
IFS= read -rs -u 3 P; echo >&2           # IFS=: a leading or trailing space is kept, then refused
exec 3<&-
[ "${#P}" -ge 6 ] && [ "${#P}" -le 8 ] && [[ "$P" =~ ^[[:graph:]]+$ ]] \
  || die "the PIN is not 6 to 8 printable ASCII characters with no spaces (the ceremony's rule): nothing was sent to the card"

if [ -n "$DRY" ]; then
  echo "DRY RUN: the card is found, its tries are full, the PIN has the right shape. Nothing was sent. Run again without --dry-run for the check."
  exit 0
fi

# 3. ONE attempt: both values on stdin from a builtin, stdin not a terminal, bounded
echo "ATTEMPT: ykman --device $last4 piv access change-pin, the PIN to itself, values on standard input (bounded at ${BOUND}s)"
printf '%s\n%s\n' "$P" "$P" | timeout "$BOUND" ykman --device "$SERIAL" piv access change-pin >/dev/null 2>&1; rc=$?
unset P
if t="$(tries)"; then read -r after max2 <<< "$t"; else after="?"; max2="$max"; fi
when="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

verdict=FAIL
if [ "$rc" = 0 ] && [ "$after" = "$before" ]; then verdict=PASS; fi
echo
echo "---- for regalia-ceremony#98 (paste as is: no PIN, the serial's last four only) ----"
echo "yubikey-stdin-check: $verdict"
echo "  YubiKey $last4, firmware ${firmware:-unknown}, ykman ${ykv:-unknown}"
echo "  change-pin with both values on stdin: rc=$rc$([ "$rc" = 124 ] && echo ' (timed out: ykman waited, probably on the terminal)')"
echo "  PIN tries: $before of $max before, $after of $max2 after"
echo "  at $when"
echo "-----------------------------------------------------------------------------------"
if [ "$verdict" = FAIL ]; then
  echo >&2
  if [ "$after" = "$before" ]; then
    # ykman stopped before the card counted a try (b9 on #153: e.g. a version asking a third line, stdin at EOF)
    echo "  >>> ykman failed (rc=$rc) but the tries are unchanged ($after of $max2 on $last4): no try was spent. The stdin" >&2
    echo "      mechanism #100 relies on did not work as measured. Report this on #98; do not change ceremony.sh's use of it. <<<" >&2
  else
    echo "  >>> $after of $max2 PIN tries remain on $last4. STOP: do not run this again. The next attempt needs a decision. <<<" >&2
  fi
  exit 1
fi
exit 0
