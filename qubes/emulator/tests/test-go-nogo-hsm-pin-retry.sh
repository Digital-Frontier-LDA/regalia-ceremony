#!/usr/bin/env bash
# test-go-nogo-hsm-pin-retry.sh — the `--need hsm` gate must catch a SmartCard-HSM (Nitrokey
# HSM 2) that is one (or zero) wrong-PIN attempts away from lockout BEFORE any key-touching
# step, exactly like it already does for the YubiKey PIV (one wrong PIN from PUK lockout) and
# the SLE-4442 (one wrong PSC from a permanent brick).
#
# The failure it guards against: prior handling can leave the HSM user-PIN retry counter at 1
# (two earlier mistyped PINs). The presence probe (`pkcs11-tool --list-slots`) succeeds
# regardless of PIN-retry state, so the gate prints GO. During the keygen step the first
# `pkcs11-tool --login` with a single PIN typo BLOCKS the user PIN; if the SO-PIN is not on
# hand (or is also exhausted) the device is permanently bricked and the born-in-HSM funding
# key — real money, set-once — is lost. The gate must READ the HSM PIN retry counter (real
# OpenSC `sc-hsm-tool` prints 'User PIN tries left  : N' (alongside 'SO-PIN tries left : N'),
# a read-only op that consumes no attempt) and STOP on 0/1, warning only if it genuinely
# cannot be read. The gate MUST read the User-PIN line specifically, not the SO-PIN line.
#
# Runs natively, no daemons: `timeout`, `pkcs11-tool` and `sc-hsm-tool` are stubbed on PATH so
# the SmartCard-HSM is "present" and the PIN retry counter is configurable. We assert on the
# HSM section only (preflight noise on a non-vault host is irrelevant to this check).
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
# pkcs11-tool stub: the funding-key SmartCard-HSM is present (so the gate gets PAST the
# presence check and on to the PIN-retry check under test).
cat > "$FAKE/pkcs11-tool" <<'EOS'
#!/usr/bin/env bash
case "$*" in
  *--list-slots*)
    cat <<'OUT'
Available slots:
Slot 0 (0x0): Nitrokey Nitrokey HSM (DENK0123456700000        ) 00 00
  token label        : UserPIN (SmartCard-HSM)
  token manufacturer : www.CardContact.de
  token model        : PKCS#15 emulated
  token flags        : login required, PIN initialized, token initialized
  token state:   present
OUT
    exit 0;;
esac
exit 0
EOS
# sc-hsm-tool stub: with no operation, real OpenSC prints the device info incl. BOTH the
# SO-PIN and the User-PIN retry counters, using the exact labels 'SO-PIN tries left' and
# 'User PIN tries left' (NOT 'PIN retry counter', which OpenSC never prints). $STUB_HSM_RETRY
# sets the User-PIN line; STUB_HSM_RETRY=missing models a tool that cannot read the counter
# (empty output) so the gate must WARN, not silently pass. The SO-PIN line is pinned HEALTHY
# (15) and printed FIRST, so a gate that greps the wrong line would read 15 and never STOP —
# the near-lock cases below then fail, catching a wrong-counter regression.
#
# $STUB_SO_RETRY sets the SO-PIN line independently (default 15 = healthy) so the SO-PIN gate
# can be exercised on its own. STUB_SO_RETRY=absent omits the line entirely, modelling a tool
# or device that does not report it.
cat > "$FAKE/sc-hsm-tool" <<'EOS'
#!/usr/bin/env bash
if [ "${STUB_HSM_RETRY:-3}" = "missing" ]; then exit 0; fi
cat <<OUT
Using reader with a card: Nitrokey Nitrokey HSM
Version              : 3.4
Config options:
  User PIN reset with SO-PIN enabled
OUT
[ "${STUB_SO_RETRY:-15}" = "absent" ] || printf 'SO-PIN tries left    : %s\n' "${STUB_SO_RETRY:-15}"
cat <<OUT
User PIN tries left  : ${STUB_HSM_RETRY:-3}
DKEK shares          : 1
OUT
exit 0
EOS
chmod +x "$FAKE/timeout" "$FAKE/pkcs11-tool" "$FAKE/sc-hsm-tool"

run(){ STUB_HSM_RETRY="$1" STUB_SO_RETRY="${2:-15}" "$GN" --need hsm 2>&1 || true; }

hdr "PIN retry = 1 (one wrong PIN blocks it) -> STOP (near lockout, could brick on one slip)"
out="$(run 1)"
grep -qiE 'SmartCard-HSM PIN retries = 1|one wrong PIN blocks' <<< "$out" \
  && P "STOPs on 1 PIN retry left (one wrong PIN blocks the user PIN before keygen)" \
  || { F "no STOP for a near-locked HSM (1 PIN retry left) — false GO possible, funding key at risk"; echo "$out" | sed 's/^/      /'; }

hdr "PIN retry = 0 (user PIN already BLOCKED) -> STOP (needs SO-PIN to unblock)"
out="$(run 0)"
grep -qiE 'SmartCard-HSM PIN retries = 0|is BLOCKED' <<< "$out" \
  && P "STOPs on a blocked user PIN (0 retries)" \
  || { F "no STOP for an already-blocked HSM user PIN"; echo "$out" | sed 's/^/      /'; }

hdr "PIN retry = 3 (healthy) -> reports OK, no lockout STOP"
out="$(run 3)"
grep -qiE 'SmartCard-HSM PIN retries = 3' <<< "$(echo "$out")" \
  && P "reports 3 PIN retries on a healthy HSM" \
  || { F "did not read/report the healthy HSM PIN retry counter"; echo "$out" | sed 's/^/      /'; }
grep -qiE 'PIN retries = 1|PIN retries = 0|one wrong PIN blocks|is BLOCKED' <<< "$out" \
  && F "wrongly flagged a healthy HSM as near lockout" \
  || P "no false lockout STOP on a healthy HSM"

hdr "SO-PIN healthy (15) but User PIN = 1 -> STOP on the USER-PIN counter, not the SO-PIN one"
# The stub prints 'SO-PIN tries left : 15' BEFORE 'User PIN tries left : 1'. A gate that
# grabs the first number it sees would read 15 and wrongly GO. The gate must read the
# User-PIN line specifically, so this must STOP.
out="$(run 1)"
grep -qiE 'SmartCard-HSM PIN retries = 1|one wrong PIN blocks' <<< "$out" \
  && ! grep -qiE 'SmartCard-HSM PIN retries = 15' <<< "$out" \
  && P "reads the User-PIN counter (1), not the healthy SO-PIN counter (15) -> STOP" \
  || { F "read the wrong counter (SO-PIN 15 instead of User PIN 1) -> false GO on a near-locked HSM"; echo "$out" | sed 's/^/      /'; }

hdr "counter unreadable -> WARN (confirm manually), never a silent pass"
out="$(run missing)"
grep -qiE 'could not read the SmartCard-HSM PIN retry counter' <<< "$(echo "$out")" \
  && P "WARNs (and tells the operator to confirm manually) when the counter can't be read" \
  || { F "no WARN when the HSM PIN retry counter is unreadable"; echo "$out" | sed 's/^/      /'; }

hdr "SO-PIN = 0 -> STOP: the SO-PIN is BLOCKED and can NEVER be unblocked"
# The SO-PIN is the only way to unblock a blocked user PIN, and unlike the user PIN it has no
# recovery path of its own ("Blocking the SO-PIN will prevent any further token initialization
# or PIN unblock" — OpenSC SmartCardHSM wiki). Generating a funding key on such a token means
# the next user-PIN lockout is terminal, and the key is gone unless a DKEK backup exists.
out="$(run 3 0)"
grep -qiE 'SO-PIN tries left = 0|SO-PIN is BLOCKED' <<< "$out" \
  && P "STOPs on a blocked SO-PIN even when the user PIN is healthy" \
  || { F "no STOP for a BLOCKED SO-PIN — the token has no unblock path left"; echo "$out" | sed 's/^/      /'; }

hdr "SO-PIN = 1 -> STOP: critically low, and it cannot be unblocked"
out="$(run 3 1)"
grep -qiE 'SO-PIN tries left = 1' <<< "$(echo "$out")" \
  && P "STOPs on a critically low SO-PIN counter" \
  || { F "no STOP for an SO-PIN one attempt from permanent loss"; echo "$out" | sed 's/^/      /'; }

hdr "SO-PIN healthy -> reports the DEVICE-read value, no STOP (docs disagree: 15 vs 3)"
out="$(run 3 15)"
grep -qiE 'SO-PIN tries left = 15' <<< "$(echo "$out")" \
  && P "reports the device-reported SO-PIN counter so the operator sees the real number" \
  || { F "did not surface the SO-PIN counter on a healthy token"; echo "$out" | sed 's/^/      /'; }
grep -qiE 'SO-PIN is BLOCKED|SO-PIN tries left = 0' <<< "$out" \
  && F "wrongly flagged a healthy SO-PIN as blocked" \
  || P "no false SO-PIN STOP on a healthy token"

hdr "SO-PIN counter absent -> WARN (read it off the device), never a silent pass"
out="$(run 3 absent)"
grep -qiE 'could not read the SmartCard-HSM SO-PIN retry counter' <<< "$(echo "$out")" \
  && P "WARNs when the SO-PIN counter cannot be read" \
  || { F "no WARN when the SO-PIN counter is unreadable"; echo "$out" | sed 's/^/      /'; }

hdr "REGRESSION: the two counters are read INDEPENDENTLY (neither masks the other)"
# A single grep across both lines would let a healthy SO-PIN (15) hide a near-locked user PIN.
out="$(run 1 15)"
grep -qiE 'SmartCard-HSM PIN retries = 1|one wrong PIN blocks' <<< "$out" \
  && P "a healthy SO-PIN does not mask a near-locked user PIN" \
  || { F "BUG: healthy SO-PIN masked the near-locked user PIN -> false GO"; echo "$out" | sed 's/^/      /'; }
out="$(run 3 0)"
grep -qiE 'SmartCard-HSM PIN retries = 3' <<< "$(echo "$out")" \
  && P "a blocked SO-PIN does not corrupt the user-PIN reading" \
  || { F "user-PIN counter misread when the SO-PIN was blocked"; echo "$out" | sed 's/^/      /'; }

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
