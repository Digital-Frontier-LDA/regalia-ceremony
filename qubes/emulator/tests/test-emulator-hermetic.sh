#!/usr/bin/env bash
# test-emulator-hermetic.sh — the emulator suite cannot reach a real card (regalia-ceremony#104).
#
# On 2026-10-02 the suite reached the bench's real tokens three times: go-nogo.sh runs the real
# opensc-tool, hsm-random.py opens pcscd through pyscard, and the daemon tier kills and restarts
# pcscd. Asserts:
#   - run-tests.sh points PCSCLITE_CSOCK_NAME at a socket that does not exist BEFORE its first suite,
#     and lifts it only after the daemon tier's refusal check;
#   - with that variable, OpenSC and pyscard see no daemon at all, even on a machine with readers
#     (checked for real when they are installed: nothing here connects, the socket does not exist);
#   - emu-boot.sh refuses to boot (which restarts pcscd) when sysfs shows a smart-card interface,
#     unless REGALIA_BENCH=1, and boots past the check when none is attached.
# This suite never talks to a real pcscd: it runs entirely under the nonexistent socket.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EMU="$(cd "$HERE/.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export PCSCLITE_CSOCK_NAME="$T/no-pcscd.comm"

hdr "run-tests.sh: the model tier runs with no card daemon reachable"
RT="$EMU/run-tests.sh"
guard="$(grep -n '^export PCSCLITE_CSOCK_NAME="\$PCSC_NOWHERE"' "$RT" | head -1 | cut -d: -f1)"
first="$(grep -n '"\$HERE/tests/' "$RT" | head -1 | cut -d: -f1)"
refuse="$(grep -n '^emu_refuse_on_real_readers || exit 2' "$RT" | head -1 | cut -d: -f1)"
lift="$(grep -n '^unset PCSCLITE_CSOCK_NAME' "$RT" | head -1 | cut -d: -f1)"
[ -n "$guard" ] && [ -n "$first" ] && [ "$guard" -lt "$first" ] \
  && P "the socket is pointed at nothing (line $guard) before the first suite (line $first)" \
  || F "PCSCLITE_CSOCK_NAME is not set before the first suite (guard '${guard:-none}', first suite '${first:-none}')"
[ -n "$refuse" ] && [ -n "$lift" ] && [ "$refuse" -lt "$lift" ] \
  && P "it is lifted only after the daemon tier's reader check (lines $refuse, $lift)" \
  || F "the socket is lifted before, or without, the reader check (check '${refuse:-none}', unset '${lift:-none}')"
[ "$(grep -c '^unset PCSCLITE_CSOCK_NAME' "$RT")" = 1 ] && P "and lifted in exactly one place" || F "PCSCLITE_CSOCK_NAME is unset in more than one place"
grep -q '^boot_all || exit 2' "$RT" && P "a refused boot stops the run" || F "run-tests.sh goes on after boot_all refuses"

hdr "every suite of the model tier carries the guard itself, so a suite run BY HAND is covered too"
unset_at="$(grep -n '^unset PCSCLITE_CSOCK_NAME' "$RT" | head -1 | cut -d: -f1)"
missing=""; nostub=""; counted=0
for t in $(head -n "$((unset_at - 1))" "$RT" | grep -o '"\$HERE/tests/test-[A-Za-z0-9_-]*\.sh"' | sed 's#"\$HERE/tests/##;s#"$##' | sort -u); do
  counted=$((counted + 1))
  grep -q '^export PCSCLITE_CSOCK_NAME="\${PCSCLITE_CSOCK_NAME:-/nonexistent/' "$HERE/$t" \
    || [ "$t" = test-emulator-hermetic.sh ] || grep -q 'PCSCLITE_CSOCK_NAME=' "$HERE/$t" || missing="$missing $t"
  grep -qF 'PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"' "$HERE/$t" \
    || [ "$t" = test-emulator-hermetic.sh ] || grep -q 'PCSCLITE_CSOCK_NAME=' "$HERE/$t" || nostub="$nostub $t"
done
pymissing=""; pycounted=0
for t in $(head -n "$((unset_at - 1))" "$RT" | grep -o 'tests/test_[A-Za-z0-9_]*\.py' | sed 's#tests/##' | sort -u); do
  pycounted=$((pycounted + 1))
  grep -q 'environ.setdefault("PCSCLITE_CSOCK_NAME", "/nonexistent/' "$HERE/$t" && grep -q '"\.\.", "bin")' "$HERE/$t" || pymissing="$pymissing $t"
done
[ "$pycounted" -gt 20 ] && [ -z "$pymissing" ] && P "the $pycounted Python suites of the model tier set both too, before their imports" || F "Python suites without the guards ($pycounted read):$pymissing"
[ "$counted" -gt 80 ] && P "$counted model-tier suites found in run-tests.sh" || F "only $counted model-tier suites found: the list was not read"
[ -z "$missing" ] && P "each sets PCSCLITE_CSOCK_NAME to a socket that does not exist unless the runner already did" || F "suites without the guard:$missing"
[ -z "$nostub" ] && P "each puts the emulator's stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first on PATH, as the runner does" || F "suites that would run the real tools by hand:$nostub"

hdr "nothing the model tier runs elevates a card tool (sudo, env -i and systemd-run drop the variable)"
QUBES="$(cd "$EMU/.." && pwd)"
CARD='opensc-tool|pkcs11-tool|pkcs15-tool|sc-hsm-tool|ykman|pcsc_scan|gpg --card|hsm-random|smartcard|scriptrunner'
elevated="$(grep -nE "(\bsudo\b|env -i|systemd-run)[^#]*($CARD)" "$QUBES"/scripts/*.sh "$QUBES"/scripts/*.py "$EMU"/tests/*.sh "$QUBES"/../tools/*.sh 2>/dev/null \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#|printf|echo|test-emulator-hermetic' || true)"
[ -z "$elevated" ] && P "no card tool is run through sudo, env -i or systemd-run" || F "these would reach the real pcscd: $elevated"
# the premise of that limit, without sudo: env -i really drops it
[ -z "$(env -i PATH="$PATH" bash -c 'printf %s "${PCSCLITE_CSOCK_NAME:-}"')" ] && P "the premise: env -i drops PCSCLITE_CSOCK_NAME" || F "env -i kept the variable"

hdr "with that socket, the tools that reached the bench see no daemon"
if command -v opensc-tool >/dev/null 2>&1; then
  out="$(timeout 20 opensc-tool -l 2>&1)"
  grep -q 'No smart card readers found' <<< "$out" && ! grep -qi 'yubico\|nitrokey\|ccid\|reader' <<< "${out//No smart card readers found/}" \
    && P "opensc-tool -l: no readers" || F "opensc-tool saw something: $out"
else P "opensc-tool is not installed here (nothing to reach)"; fi
if python3 -I -c 'import smartcard' 2>/dev/null; then
  out="$(timeout 20 python3 -I -c 'from smartcard.System import readers; print(readers())' 2>&1)"
  grep -q 'Service not available\|EstablishContext' <<< "$out" && P "pyscard: no context (hsm-random.py's path)" || F "pyscard reached a daemon: $out"
else P "pyscard is not installed here (nothing to reach)"; fi

hdr "gpg cannot reach a card: its agent never starts scdaemon, and card commands are refused before it runs"
# PCSCLITE_CSOCK_NAME stops what goes through pcscd. GnuPG's scdaemon tries its built-in CCID driver (libusb) FIRST, so
# a gpg card path (ceremony.sh step_ownerauth's --card-status, offline-keys.py card_serial, --change-pin, --edit-key's
# keytocard, a card stub's decryption) could reach a real developer card on the bench with no daemon. The emulator's gpg
# stand-in starts gpg's agent with --disable-scdaemon (the control) and refuses card commands and their abbreviations
# (defence in depth; b9 on #150: gpg takes any unambiguous prefix, --card-stat reached the card path).
# Layer 2, with a canary: a "real" gpg and gpg-agent behind the stand-in that record every call.
# EVERY call to the stand-in is bounded: one that found itself would exec itself for ever, and a regressed control could
# wait on a real card; either must fail here, not hang the suite. `timeout` is resolved before PATH narrows.
bound="$(command -v timeout)"
mkdir -p "$T/realgpg"
for tool in gpg gpg-agent; do
  printf '#!/usr/bin/env bash\nprintf "%%s %%s\\n" "%s" "$*" >> "${GPG_CANARY_LOG:?}"\nexit 0\n' "$tool" > "$T/realgpg/$tool"
  chmod +x "$T/realgpg/$tool"
done
export GPG_CANARY_LOG="$T/gpg-calls"
for card in --card-status --card-edit --edit-card --change-pin --card-stat --card-s --car-st --edit-c --change-pi "--homedir $T/h --batch --card-status"; do
  : > "$GPG_CANARY_LOG"
  # shellcheck disable=SC2086  # the option list is words on purpose
  out="$(PATH="$EMU/bin:$T/realgpg:/usr/bin:/bin" "$bound" 10 gpg $card 2>&1)"; rc=$?
  [ "$rc" = 2 ] && [ ! -s "$GPG_CANARY_LOG" ] && grep -q 'regalia-ceremony#104' <<< "$out" \
    && P "gpg $card: refused (status 2), the real gpg never ran" || F "gpg $card reached the real gpg (status $rc): $(cat "$GPG_CANARY_LOG") $out"
done
for fine in --change-passphrase --change-recipients --edit-key; do
  : > "$GPG_CANARY_LOG"
  PATH="$EMU/bin:$T/realgpg:/usr/bin:/bin" "$bound" 10 gpg "$fine" x >/dev/null 2>&1
  [ -s "$GPG_CANARY_LOG" ] && P "gpg $fine is not a card command: it reaches the real gpg (the control stops what it may do with a card)" \
    || F "gpg $fine was refused, and it is not a card command"
done
: > "$GPG_CANARY_LOG"
PATH="$EMU/bin:$EMU/bin:$T/realgpg:/usr/bin:/bin" "$bound" 10 gpg --batch --list-keys x >/dev/null 2>&1
[ "$(cat "$GPG_CANARY_LOG")" = "gpg --agent-program $T/realgpg/gpg-agent|--disable-scdaemon --batch --list-keys x" ] \
  && P "anything else is the real gpg's, its arguments as given, its agent started with --disable-scdaemon (never itself)" \
  || F "a non-card gpg call did not reach the real gpg as expected: '$(cat "$GPG_CANARY_LOG")'"
unset GPG_CANARY_LOG

# Layer 1, against the real gpg where it is installed: a fresh home, every card path the denylist does NOT see
# (keytocard inside --edit-key, a decryption), and then the agent itself is asked whether scdaemon ever ran.
if command -v gpg >/dev/null 2>&1 && command -v gpg-agent >/dev/null 2>&1 && command -v gpg-connect-agent >/dev/null 2>&1; then
  H="$T/gnupg"; mkdir -m 700 "$H"
  emu_gpg(){ PATH="$EMU/bin:$PATH" "$bound" 60 gpg --homedir "$H" --batch "$@"; }
  emu_gpg --passphrase '' --quick-gen-key canary@e2e ed25519 default never >/dev/null 2>&1
  printf 'keytocard\ny\n1\nsave\n' | emu_gpg --command-fd 0 --edit-key canary@e2e >/dev/null 2>&1
  printf 'x' | emu_gpg -r canary@e2e -e | emu_gpg -d >/dev/null 2>&1
  serialno="$("$bound" 20 gpg-connect-agent --homedir "$H" --no-autostart "scd serialno" /bye 2>&1)"
  running="$("$bound" 20 gpg-connect-agent --homedir "$H" --no-autostart "getinfo scd_running" /bye 2>&1 | head -1)"
  grep -q 'Not supported' <<< "$serialno" && [ "$running" != OK ] \
    && P "the real agent the stand-in started refuses scdaemon ('scd serialno': Not supported) and none ever ran, after keytocard and a decryption" \
    || F "the agent reached scdaemon: scd serialno '$serialno', scd_running '$running'"
  emu_gpg --list-secret-keys canary@e2e 2>/dev/null | grep -q '^sec ' \
    && P "keytocard moved nothing: the secret key is still this home's, not a card stub" || F "keytocard changed the key: $(emu_gpg --list-secret-keys canary@e2e 2>&1)"
  gpgconf --homedir "$H" --kill all 2>/dev/null || true
else P "gpg, gpg-agent or gpg-connect-agent is not installed here (nothing to reach)"; fi
# #104's step 2: every card tool go-nogo.sh and ceremony.sh can run either has a stand-in in the emulator's bin, or speaks
# only PC/SC, which the socket above already stops
QUBES_SCRIPTS="$(cd "$EMU/../scripts" && pwd)"
for tool in ykman pkcs11-tool sc-hsm-tool gpg; do
  [ -x "$EMU/bin/$tool" ] && P "$tool has an emulator stand-in" || F "$tool has no stand-in in $EMU/bin"
done
for tool in opensc-tool pkcs15-tool pcsc_scan; do
  grep -qw "$tool" "$QUBES_SCRIPTS/go-nogo.sh" "$QUBES_SCRIPTS/ceremony.sh" 2>/dev/null || continue
  [ ! -e "$EMU/bin/$tool" ] && P "$tool speaks PC/SC only: stopped by the socket, no stand-in needed" || P "$tool has a stand-in"
done

hdr "emu-boot.sh refuses to restart pcscd under a real reader"
fake(){ rm -rf "$T/sys"; mkdir -p "$T/sys"; local n=0 c; for c in "$@"; do n=$((n+1)); mkdir -p "$T/sys/1-$n:1.0"; echo "$c" > "$T/sys/1-$n:1.0/bInterfaceClass"; done; }
refuses(){ ( export EMU_SYSFS_USB="$T/sys" EMU_RUN="$T/run"; unset REGALIA_BENCH; [ -n "${1:-}" ] && export REGALIA_BENCH="$1"
  # shellcheck disable=SC1091
  source "$EMU/bin/emu-boot.sh" >/dev/null 2>&1; emu_refuse_on_real_readers ) >"$T/out" 2>&1; }
fake 09 03 0b; refuses; [ $? = 1 ] && grep -q 'REFUSING to boot' "$T/out" && P "a CCID interface (class 0b) attached: refused, with the reason" || F "a CCID interface did not stop the boot: $(cat "$T/out")"
fake 09 03 0b; refuses 1; [ $? = 0 ] && P "REGALIA_BENCH=1: the bench is this run's, allowed" || F "REGALIA_BENCH=1 was not honoured"
fake 09 03 0b; refuses 0; [ $? = 1 ] && P "REGALIA_BENCH set to anything but 1: still refused" || F "REGALIA_BENCH=0 allowed the boot"
fake 09 03 08; refuses; [ $? = 0 ] && P "no smart-card interface (a hub, a keyboard, a disk): allowed" || F "a machine without readers was refused"
fake; refuses; [ $? = 0 ] && P "no USB at all (a container): allowed" || F "an empty sysfs was refused"
grep -q '^  emu_refuse_on_real_readers || return 1' "$EMU/bin/emu-boot.sh" \
  && [ "$(grep -n 'emu_refuse_on_real_readers || return 1' "$EMU/bin/emu-boot.sh" | cut -d: -f1)" -lt "$(grep -n '^  start_pcsc$' "$EMU/bin/emu-boot.sh" | cut -d: -f1)" ] \
  && P "boot_all checks before start_pcsc (every caller is covered, the container entrypoint too)" || F "boot_all can restart pcscd without the check"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
