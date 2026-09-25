#!/usr/bin/env bash
# preflight's token section against the three shapes opensc-tool -l really prints: nothing attached
# ("No smart card readers found." — which the old grep for "reader" counted as a reader), a
# Nitrokey HSM, and only a YubiKey. Owner's first disposable, 2026-09-25: no HSM attached, and
# preflight said "a PC/SC reader is visible" with no HSM warning.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PF="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/preflight.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
FAKE="$(mktemp -d)"; trap 'rm -rf "$FAKE"' EXIT
printf '#!/usr/bin/env bash\ncat "$OPENSC_OUT"\n' > "$FAKE/opensc-tool"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE/ykman"
chmod +x "$FAKE/opensc-tool" "$FAKE/ykman"
run(){ OPENSC_OUT="$1" PATH="$FAKE:$PATH" CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 bash "$PF" 2>&1 \
        | sed $'s/\033\\[[0-9;]*m//g' | sed -n '/== Smartcard reader/,/== Printer/p'; }

printf 'No smart card readers found.\n' > "$FAKE/none"
cat > "$FAKE/nitrokey" <<'O'
# Detected readers (pcsc)
Nr.  Card  Features  Name
0    Yes             Nitrokey Nitrokey HSM (DENK04041440000         ) 00 00
O
cat > "$FAKE/yubikey" <<'O'
# Detected readers (pcsc)
Nr.  Card  Features  Name
0    Yes             Yubico YubiKey OTP+FIDO+CCID 00 00
O

hdr "nothing attached: WARN for the reader AND for the HSM, never 'reader visible'"
out="$(run "$FAKE/none")"
grep -q "reader(s) visible" <<< "$out" && F "'No smart card readers found.' reported as a visible reader" || P "no false 'reader visible'"
grep -q "WARN no smart-card reader" <<< "$out" && P "warns that no reader is attached" || F "no reader warning"
grep -q "WARN no Nitrokey HSM or Pico HSM" <<< "$out" && P "warns that no HSM is attached" || F "no HSM warning"

hdr "a Nitrokey HSM attached: named, no HSM warning"
out="$(run "$FAKE/nitrokey")"
grep -q "OK   HSM token(s) present: .*Nitrokey HSM (DENK0404144" <<< "$out" && P "the Nitrokey is named with its serial" || F "Nitrokey not reported: $out"
grep -q "no Nitrokey HSM" <<< "$out" && F "HSM warning despite a Nitrokey" || P "no HSM warning"

hdr "only a YubiKey: a reader is visible, but the HSM is still missing"
out="$(run "$FAKE/yubikey")"
grep -q "OK   1 PC/SC reader(s) visible" <<< "$out" && P "the YubiKey's reader is counted" || F "YubiKey reader not counted"
grep -q "WARN no Nitrokey HSM or Pico HSM" <<< "$out" && P "a YubiKey is not mistaken for an HSM" || F "YubiKey taken for an HSM"

hdr "an HSM reader with no token answering (Card No): not reported as present (review of #56)"
cat > "$FAKE/nocard" <<'O'
# Detected readers (pcsc)
Nr.  Card  Features  Name
0    No              Nitrokey Nitrokey HSM (DENK04041440000         ) 00 00
O
out="$(run "$FAKE/nocard")"
grep -q "HSM token(s) present" <<< "$out" && F "a Card No reader was reported as an HSM token" || P "no false 'HSM present'"
grep -q "no token answers" <<< "$out" && P "says the HSM reader has no token answering" || F "no warning for the silent HSM reader"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
