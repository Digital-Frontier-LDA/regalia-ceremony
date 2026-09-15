#!/usr/bin/env bash
# test-go-nogo-hsm-token.sh — the `--need hsm` gate must require the actual SmartCard-HSM
# (Nitrokey HSM 2) that holds the funding key, NOT just ANY OpenSC-visible PKCS#11 token.
# The YubiKey PIV (needed for the ops-identity step anyway) also enumerates through
# opensc-pkcs11.so, printing 'token label' / 'token state: present' lines. An over-broad
# match on the words 'token'/'present' therefore says GO with the YubiKey alone while the
# funding-key HSM is absent — the operator then walks into the HSM step believing hardware
# was verified. This is a set-once, real-money gate: it must key on 'SmartCard-HSM'.
#
# Runs natively, no daemons: `timeout` and `pkcs11-tool` are stubbed on PATH so
# `--list-slots` returns a configurable slot dump. We assert on the HSM section only
# (preflight noise on a non-vault host is irrelevant to this check).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GN="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/go-nogo.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

FAKE="$(mktemp -d)"
cleanup(){ rm -rf "$FAKE"; }
trap cleanup EXIT
export PATH="$FAKE:$PATH"

# `timeout <secs> cmd …` -> just run cmd (macOS/native host may lack coreutils timeout).
cat > "$FAKE/timeout" <<'EOS'
#!/usr/bin/env bash
shift
exec "$@"
EOS
# pkcs11-tool stub: --list-slots prints a slot dump chosen by $STUB_SLOTS:
#   yubikey -> a YubiKey PIV token as OpenSC really renders it (has 'token label' and
#              'token state:   present', but the model is NOT SmartCard-HSM)
#   hsm     -> a Nitrokey HSM 2 / SmartCard-HSM token
cat > "$FAKE/pkcs11-tool" <<'EOS'
#!/usr/bin/env bash
case "$*" in
  *--list-slots*)
    if [ "${STUB_SLOTS:-hsm}" = "yubikey" ]; then
      cat <<'OUT'
Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
  token label        : user_pin (PIV Card Holder pin)
  token manufacturer : piv_II
  token model        : PKCS#15 emulated
  token flags        : login required, PIN initialized, token initialized
  token state:   present
OUT
    else
      cat <<'OUT'
Available slots:
Slot 0 (0x0): Nitrokey Nitrokey HSM (DENK0123456700000        ) 00 00
  token label        : UserPIN (SmartCard-HSM)
  token manufacturer : www.CardContact.de
  token model        : PKCS#15 emulated
  token flags        : login required, PIN initialized, token initialized
  token state:   present
OUT
    fi
    exit 0;;
esac
exit 0
EOS
chmod +x "$FAKE/timeout" "$FAKE/pkcs11-tool"

run(){ STUB_SLOTS="$1" "$GN" --need hsm 2>&1 || true; }

hdr "only a YubiKey PIV token is visible (no SmartCard-HSM) -> HSM gate must NOT say GO"
out="$(run yubikey)"
if grep -qi 'funding-key HSM .*is present' <<< "$out"; then
  F "false GO: gate accepted a YubiKey PIV token as the funding-key HSM"
  echo "$out" | sed 's/^/      /'
else
  P "did not accept a generic PKCS#11 token as the HSM"
fi
grep -qi 'no SmartCard-HSM funding token visible' <<< "$(echo "$out")" \
  && P "STOPs and tells the operator to attach the Nitrokey HSM 2" \
  || { F "no STOP when the SmartCard-HSM is absent"; echo "$out" | sed 's/^/      /'; }

hdr "the real SmartCard-HSM (Nitrokey HSM 2) is visible -> HSM gate says GO"
out="$(run hsm)"
grep -qi 'funding-key HSM .*is present' <<< "$(echo "$out")" \
  && P "accepts the SmartCard-HSM token" \
  || { F "did not accept a genuine SmartCard-HSM token (would false NO-GO the ceremony)"; echo "$out" | sed 's/^/      /'; }

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
