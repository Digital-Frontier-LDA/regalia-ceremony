#!/usr/bin/env bash
# test-yubikey-stdin-check.sh — tools/yubikey-stdin-check.sh, the owner's one hardware check for #98/#100, against
# a ykman fake that models what the check depends on: the serials, piv info's "PIN tries remaining: N/M", a wrong
# PIN costing a try, and a ykman that waits on the terminal instead of reading stdin. No card is reached.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
TOOL="$ROOT/tools/yubikey-stdin-check.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PIN='a1!B2@c3'
mkdir "$T/bin"
cat > "$T/bin/ykman" <<'FAKE'
#!/usr/bin/env bash
# the fake: argv to $YK_LOG (one line per call), stdin of a change to $YK_LOG.stdin, tries in $YK_STATE
printf '%s\n' "$*" >> "$YK_LOG"
[ "${1:-}" = --version ] && { echo "YubiKey Manager (ykman) version: 5.9.2"; exit 0; }
[ "${1:-}" = list ] && { tr ' ' '\n' <<< "$YK_SERIALS"; exit 0; }
[ "${1:-}" = --device ] || exit 2
dev="$2"; shift 2
grep -qx "$dev" <<< "$(tr ' ' '\n' <<< "$YK_SERIALS")" || { echo "ERROR: no YubiKey with serial $dev" >&2; exit 2; }
case "$*" in
  info) printf 'Device type: YubiKey 5 NFC\nSerial number: %s\nFirmware version: 5.7.4\n' "$dev" ;;
  "piv info") if [ "${YK_BARE:-}" = 1 ]; then printf 'PIN tries remaining: %s\n' "$(cat "$YK_STATE")"   # ykman 4.x: no maximum
              else printf 'PIV version: 5.7.4\nPIN tries remaining: %s/3\n' "$(cat "$YK_STATE")"; fi ;;
  "piv access change-pin")
    [ "${YK_MODE:-}" = wait ] && { sleep 60; exit 1; }      # a ykman that waits on the terminal
    IFS= read -r cur; IFS= read -r new; printf '%s|%s\n' "$cur" "$new" >> "$YK_LOG.stdin"
    if [ "$cur" = "$YK_PIN" ]; then echo 3 > "$YK_STATE"; exit 0; fi
    echo $(( $(cat "$YK_STATE") - 1 )) > "$YK_STATE"; echo "Error: wrong PIN" >&2; exit 1 ;;
  *) exit 2 ;;
esac
FAKE
chmod +x "$T/bin/ykman"
run(){ # run TRIES STDIN ARGS...: one run of the tool against a fresh fake; out, err, rc, the log
  : > "$T/log"; : > "$T/log.stdin"; echo "$1" > "$T/state"; local input="$2"; shift 2
  printf '%s\n' "$input" | env PATH="$T/bin:$PATH" YK_LOG="$T/log" YK_STATE="$T/state" YK_SERIALS="${SERIALS:-35718625}" \
    YK_PIN="$PIN" YK_MODE="${MODE:-}" YK_BARE="${BARE:-}" YK_CHECK_TIMEOUT="${BOUNDS:-3}" YK_CHECK_TTY="${TTYFILE:-/nonexistent/tty}" YK_CHECK_TEST="${TESTMARK-1}" ${XTRACE:+SHELLOPTS=xtrace} ${ERREXIT:+SHELLOPTS=errexit} \
    bash ${BASHX:+-x} "$TOOL" ${STDIN_PIN---pin-stdin} "$@" >"$T/out" 2>"$T/err"
  rc=$?; }
changed(){ grep -c 'piv access change-pin' "$T/log"; }

hdr "the check: one attempt, both values on stdin, the PIN nowhere else"
run 3 "$PIN" --device 35718625
[ "$rc" = 0 ] && grep -q "yubikey-stdin-check: PASS" "$T/out" && P "a card taking stdin: PASS, rc 0" || F "PASS run: rc=$rc $(cat "$T/out" "$T/err")"
[ "$(changed)" = 1 ] && [ "$(cat "$T/log.stdin")" = "$PIN|$PIN" ] && P "one change-pin, the PIN to itself, both values on stdin" || F "the attempt: $(cat "$T/log") / $(cat "$T/log.stdin")"
! grep -qF -- "$PIN" "$T/log" && P "the PIN is on no ykman command line" || F "the PIN reached an argv: $(cat "$T/log")"
! grep -qF -- "$PIN" "$T/out" "$T/err" && P "the PIN is printed nowhere" || F "the PIN was printed"
grep -q "YubiKey …8625, firmware 5.7.4, ykman 5.9.2" "$T/out" && ! grep -q 35718625 "$T/out" \
  && P "the record names the serial's last four only, with firmware and ykman version" || F "the record: $(cat "$T/out")"
grep -q "PIN tries: 3 of 3 before, 3 of 3 after" "$T/out" && P "the record states the tries before and after" || F "tries line missing"

hdr "refused before the card: nothing is sent"
run 3 "$PIN" --device 35718625 --dry-run
[ "$rc" = 0 ] && [ "$(changed)" = 0 ] && grep -q "DRY RUN" "$T/out" && P "--dry-run reads the card and the PIN, sends nothing" || F "dry run: rc=$rc changes=$(changed)"
run 2 "$PIN" --device 35718625
[ "$rc" = 2 ] && [ "$(changed)" = 0 ] && grep -q "2 of 3 PIN tries left, not all" "$T/err" && P "tries not full (2 of 3): refused, the PIN not even asked" || F "tries 2: rc=$rc $(cat "$T/err")"
SERIALS=11112222 run 3 "$PIN" --device 35718625
[ "$rc" = 2 ] && [ "$(changed)" = 0 ] && grep -q "…8625 is not connected" "$T/err" && ! grep -q 35718625 "$T/err" \
  && P "the named card absent: refused, and the other card's serial shown as its last four" || F "absent: rc=$rc $(cat "$T/err")"
for bad in '1234 567' ' 1234567' '1234567 ' '12345' '123456789' '12345é7'; do
  run 3 "$bad" --device 35718625
  [ "$rc" = 2 ] && [ "$(changed)" = 0 ] && ! grep -qF -- "$bad" "$T/out" "$T/err" && P "PIN '$bad' (the ceremony's rule): refused, nothing sent, not printed" || F "PIN '$bad': rc=$rc changes=$(changed)"
done
run 3 "$PIN" --device 3571-8625
[ "$rc" = 2 ] && [ ! -s "$T/log" ] && P "a malformed serial: refused before ykman runs" || F "malformed serial: rc=$rc"

hdr "the PIN comes from the terminal unless --pin-stdin is given (b9 on #153)"
STDIN_PIN='' run 3 "$PIN" --device 35718625
[ "$rc" = 2 ] && [ ! -s "$T/log" ] && grep -q "no terminal to read the PIN from" "$T/err" \
  && P "no terminal and no --pin-stdin: refused before ykman runs" || F "no tty: rc=$rc $(cat "$T/err") log: $(cat "$T/log")"
printf '%s\n' "$PIN" > "$T/tty"
STDIN_PIN='' TTYFILE="$T/tty" run 3 'wrongPIN' --device 35718625
[ "$rc" = 0 ] && [ "$(cat "$T/log.stdin")" = "$PIN|$PIN" ] \
  && P "with a terminal, the PIN is the terminal's: a wrong PIN on stdin (a stray pipe) is ignored, no try spent" || F "tty read: rc=$rc $(cat "$T/log.stdin")"

TESTMARK='' STDIN_PIN='' TTYFILE="$T/tty" run 3 "$PIN" --device 35718625
[ "$rc" = 2 ] && [ ! -s "$T/log" ] && grep -q "YK_CHECK_TTY is set .* without YK_CHECK_TEST=1" "$T/err" \
  && P "the tests' PIN-source override without their marker: refused, nothing run" || F "override without marker: rc=$rc $(cat "$T/err")"
STDIN_PIN='' TTYFILE="$T/tty" run 3 "$PIN" --device 35718625
grep -q "PIN read from: $T/tty" "$T/out" && P "the record says where the PIN was read from" || F "no 'PIN read from' line: $(cat "$T/out")"
run 3 "$PIN" --device 35718625
grep -q "PIN read from: standard input (--pin-stdin)" "$T/out" && P "and says so for --pin-stdin" || F "--pin-stdin not named in the record"

hdr "a FAIL says how many tries remain, and to stop"
run 3 'wrongPIN' --device 35718625
[ "$rc" = 1 ] && grep -q "yubikey-stdin-check: FAIL" "$T/out" && grep -q "2 of 3 PIN tries remain on …8625. STOP: do not run this again" "$T/err" \
  && P "a wrong PIN: FAIL, rc 1, '2 of 3 PIN tries remain ... STOP'" || F "wrong PIN: rc=$rc $(cat "$T/out" "$T/err")"
[ "$(changed)" = 1 ] && P "and exactly one attempt was made" || F "attempts: $(changed)"
MODE='wait' run 3 "$PIN" --device 35718625
[ "$rc" = 1 ] && grep -q "rc=124 (timed out: ykman waited" "$T/out" && P "a ykman that waits on the terminal: bounded, FAIL, said as such" || F "wait: rc=$rc $(cat "$T/out")"
grep -q "no try was spent" "$T/err" && ! grep -q "STOP: do not run this again" "$T/err" \
  && P "a FAIL with the tries unchanged says no try was spent (not STOP)" || F "unchanged-tries FAIL text: $(cat "$T/err")"

hdr "CodeRabbit on #153: a bound that is a bound, a maximum that is known, a record under errexit"
for b in 0 -1 abc 1000; do
  BOUNDS="$b" run 3 "$PIN" --device 35718625
  [ "$rc" = 2 ] && [ ! -s "$T/log" ] && grep -q "YK_CHECK_TIMEOUT must be" "$T/err" && P "YK_CHECK_TIMEOUT=$b: refused before ykman runs (timeout 0 would not bound the attempt)" \
    || F "YK_CHECK_TIMEOUT=$b: rc=$rc $(cat "$T/err")"
done
BARE=1 run 3 "$PIN" --device 35718625
[ "$rc" = 2 ] && [ "$(changed)" = 0 ] && grep -q "does not report the maximum" "$T/err" \
  && P "piv info without a maximum (ykman 4.x's bare count): 'tries full' cannot be proven, refused" || F "bare count: rc=$rc $(cat "$T/err")"
ERREXIT=1 run 3 'wrongPIN' --device 35718625
[ "$rc" = 1 ] && grep -q "yubikey-stdin-check: FAIL" "$T/out" && grep -q "PIN tries: 3 of 3 before, 2 of 3 after" "$T/out" && grep -q "2 of 3 PIN tries remain" "$T/err" \
  && P "SHELLOPTS=errexit from the caller: a failing ykman still gives the FAIL record and the tries after" || F "errexit: rc=$rc out: $(cat "$T/out") err: $(cat "$T/err")"
ERREXIT=1 run 3 "$PIN" --device 35718625
[ "$rc" = 0 ] && grep -q "yubikey-stdin-check: PASS" "$T/out" && P "and under errexit a PASS is still a PASS" || F "errexit pass: rc=$rc $(cat "$T/err")"

hdr "never traced, never dumped"
BASHX=1 run 3 "$PIN" --device 35718625
[ "$rc" = 0 ] && ! grep -qF -- "$PIN" "$T/out" "$T/err" && P "bash -x on the tool: the PIN is in no trace line" || F "bash -x printed the PIN (rc=$rc)"
XTRACE=1 run 3 "$PIN" --device 35718625
[ "$rc" = 0 ] && ! grep -qF -- "$PIN" "$T/out" "$T/err" && P "SHELLOPTS=xtrace exported by the caller: the PIN is in no trace line" || F "SHELLOPTS=xtrace printed the PIN"
grep -q '^ulimit -c 0' "$TOOL" && grep -q "^trap 'unset P' EXIT" "$TOOL" && [ "$(grep -n '^set +x' "$TOOL" | cut -d: -f1)" -lt "$(grep -n 'read -rs' "$TOOL" | cut -d: -f1)" ] \
  && P "core dumps off, the PIN unset on exit, xtrace off before the PIN is read" || F "the guards are not in place"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
