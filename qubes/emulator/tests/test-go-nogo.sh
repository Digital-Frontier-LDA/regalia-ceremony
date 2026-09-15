#!/usr/bin/env bash
# test-go-nogo.sh — exercise the real scripts/go-nogo.sh against the live emulators and
# assert it reaches a GO verdict for every device class. Only the air-gap network probe is
# faked (a one-line `ip` stub, like the other harnesses); the reader/HSM/YubiKey/printer/
# drive probes hit the real emulators. Also asserts go-nogo says NO-GO when a YubiKey PIN
# is one try from PUK lockout, proving the gate actually bites.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1   # stubs the air-gap probe only
RUN="${EMU_RUN:-/run/vault-emu}"
[ -f "$RUN/env.sh" ] && . "$RUN/env.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Default to the REPO copy like the other suites do (test-chipcard-step.sh:16 and friends).
# Defaulting to the install path made this suite exit 127 on any host without /opt/vault-ceremony,
# reporting 6 failures that were really "the script is not installed here".
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"

# THIS SUITE NEEDS THE LIVE EMULATORS, and says so in its own header: it drives the real
# reader/HSM/YubiKey/printer/drive probes and fakes only the air-gap check. Without that
# environment every probe fails, and five reds that all mean "no emulator on this host" read
# exactly like a broken gate — the misdirection this repo keeps removing. Skip honestly instead,
# the way test-doc-map.sh skips when its input is absent.
_missing=""
[ -d "$RUN" ] || _missing="$_missing $RUN"
command -v ykman >/dev/null 2>&1 || _missing="$_missing ykman"
command -v softhsm2-util >/dev/null 2>&1 || _missing="$_missing softhsm2-util"
if [ -n "$_missing" ]; then
  printf '  (skipping: this suite drives the live emulators, and these are absent:%s)\n' "$_missing"
  printf '  (run it inside the emulator container, or set EMU_RUN to a live emulator root)\n'
  exit 0
fi

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# fake ONLY the air-gap probe (container has a network; the real vault qube won't)
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE/ip"; chmod +x "$FAKE/ip"
export EMU_HSM_PIN="648219"
softhsm2-util --init-token --free --label akash-funding --so-pin 3537363231383830 --pin "$EMU_HSM_PIN" >/dev/null 2>&1
cleanup(){ rm -rf "$FAKE"; }
trap cleanup EXIT

hdr "go-nogo with every device required -> expect GO"
out="$("$SCRIPTS/go-nogo.sh" --need yubikey,hsm,sle4442,printer,drives 2>&1)"; rc=$?
echo "$out" | sed 's/^/   /'
[ "$rc" = 0 ] && P "verdict is GO (exit 0)" || F "expected GO, got exit $rc"
grep -q "================  GO" <<< "$out" && P "prints the GO banner" || F "no GO banner"
grep -qi "SLE-4442 SELECT" <<< "$out" && P "ran the SLE-4442 memory-card capability probe" || F "no SLE-4442 probe"
grep -qiE "funding-key HSM .*is present" <<< "$out" && P "saw the funding-key HSM (SmartCard-HSM/akash-funding token)" || F "HSM token not seen"
grep -qi "PIV PIN retries = 3" <<< "$out" && P "read the YubiKey PIV retry counter" || F "no PIV retry read"

hdr "go-nogo bites: a YubiKey 1 try from PUK lockout -> expect NO-GO"
EMU_YKMAN_SERIAL=99999999 out2="$(EMU_YKMAN_PIV_RETRIES=1 "$SCRIPTS/go-nogo.sh" --need yubikey 2>&1)"; rc2=$?
if [ "$rc2" != 0 ] && grep -qi "one wrong PIN locks it" <<< "$out2"; then
  P "NO-GO when PIV retries = 1 (PUK-lockout guard works)"
else
  F "expected NO-GO on low PIV retries (got exit $rc2)"; echo "$out2" | grep -i retries | sed 's/^/      /'
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
