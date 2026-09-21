#!/usr/bin/env bash
# test-hsm-init-hardened.sh — the APDU that sets the card's security posture, checked byte for byte.
# NO HARDWARE: opensc-explorer is stubbed, and what the script sends it is the thing under test.
#
# WHY BYTE FOR BYTE. The options field is two bits (SmartCardHSM.js: bit 0 RRC enabled, bit 5 PIN
# reset disabled) inside an INITIALIZE DEVICE command this script builds by hand. Get it wrong and
# the card comes up with RESET RETRY COUNTER ENABLED — the posture where the SO-PIN alone sets a
# new user PIN and then uses every key (measured 2026-08-01, doc/drills/2026-08-01-so-pin-reset.md).
# Nothing downstream would notice: the card initialises, the label is right, every later step
# passes, and the only tell is a bit in an APDU nobody reads back. So the bytes are the test.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
INIT="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/hsm-init-hardened.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$INIT" ] || { echo "no hsm-init-hardened.sh at $INIT" >&2; exit 1; }
BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT

# The stub records BOTH what it was given on stdin (the APDUs) and its own argv, so "the PIN never
# reaches the process table" is checkable rather than asserted.
cat > "$BIN/opensc-explorer" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_ARGV:?}"
cat >> "${STUB_STDIN:?}"
printf 'OpenSC Explorer\nReceived (SW1=0x90, SW2=0x00)\n'
STUB
cat > "$BIN/devaut-read" <<'STUB'
#!/usr/bin/env bash
[ -n "${STUB_CHR:-}" ] || exit 1
printf 'DEVAUT_CHR=%s\n' "$STUB_CHR"
STUB
chmod +x "$BIN/opensc-explorer" "$BIN/devaut-read"
export PATH="$BIN:$PATH"

run_init(){   # run_init <env assignments...> -- <args...>
  local envs=() args=() seen=0 a
  for a in "$@"; do
    if [ "$a" = "--" ] && [ "$seen" = 0 ]; then seen=1; continue; fi
    if [ "$seen" = 0 ]; then envs+=("$a"); else args+=("$a"); fi
  done
  : > "$BIN/stdin.txt"; : > "$BIN/argv.txt"
  env STUB_STDIN="$BIN/stdin.txt" STUB_ARGV="$BIN/argv.txt" HSM_DEVAUT_READ_SH="$BIN/devaut-read" \
      ${envs[@]+"${envs[@]}"} bash "$INIT" ${args[@]+"${args[@]}"} 2>&1
}
apdus(){ grep -oE '^apdu [0-9A-Fa-f]+' "$BIN/stdin.txt" | awk '{print $2}'; }
init_apdu(){ apdus | grep -iE '^805000' | head -1 | tr 'a-f' 'A-F'; }
label_apdu(){ apdus | grep -iE '^00D72F03' | head -1 | tr 'a-f' 'A-F'; }

PINS=(HSM_SO_PIN=0011223344556677 HSM_USER_PIN=123456)

hdr "the INITIALIZE DEVICE command, byte for byte"
out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --expect-serial DENK0404144)"
got="$(init_apdu)"
# 80 50 00 00 1C | 80 02 0000 | 81 06 "123456" | 82 08 <so-pin> | 91 01 03 | 92 01 01
want="805000001C80020000810631323334353682080011223344556677910103920101"
if [ "$got" = "$want" ]; then P "RRC off builds exactly the expected APDU"; else
  F "RRC off built the wrong APDU"; printf '      got  %s\n      want %s\n' "$got" "$want"; fi

case "$got" in
  8050*8002"0000"*) P "options are 0x0000 — RESET RETRY COUNTER disabled entirely (the D3 posture)";;
  *) F "the options field is not 0x0000; a wrong bit here hands the card to the SO-PIN";;
esac

out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --rrc reset-only)"
case "$(init_apdu)" in
  8050*8002"0021"*) P "reset-only builds options 0x0021 (bit 0 RRC + bit 5 no-PIN-change)";;
  *) F "reset-only did not build options 0x0021: $(init_apdu)";;
esac

out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --retries 5 --dkek-shares 2)"
case "$(init_apdu)" in
  *910105920102*) P "--retries and --dkek-shares reach the card in their own TLVs";;
  *) F "retries/shares are not in the APDU: $(init_apdu)";;
esac

out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --pka-keys 3 --pka-required 2)"
case "$(init_apdu)" in
  *930203"02"*) P "PKA (public-key authentication) adds 93 02 <keys><required>";;
  *) F "PKA parameters are missing from the APDU: $(init_apdu)";;
esac

hdr "the label goes to EF 2F03 in the PKCS#15 shape"
out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --label regalia)"
got="$(label_apdu)"
want="00D72F031854020000531230100201008007726567616C696103020500"
if [ "$got" = "$want" ]; then P "the TokenInfo write matches the initializer's structure"; else
  F "the label APDU is not the expected TokenInfo write"; printf '      got  %s\n      want %s\n' "$got" "$want"; fi

hdr "the PINs never reach the process table"
# `opensc-tool -s <apdu>` would put the whole command — both PINs inside it — in argv, where any
# local user reading /proc sees them. This is why the APDU goes in on stdin.
if grep -q '313233343536\|0011223344556677\|123456' "$BIN/argv.txt"; then
  F "a PIN appears in the child's argv: $(cat "$BIN/argv.txt")"
else
  P "no PIN, in ASCII or hex, appears in the child's argv"
fi
grep -q '0011223344556677' "$BIN/stdin.txt" && P "…and the SO-PIN does reach the card, on stdin" \
  || F "the SO-PIN never reached the card at all"

hdr "refusals: it wipes the card it reaches, so it may not guess"
out="$(run_init "${PINS[@]}" -- --expect-serial DENK0404144)"
grep -q 'reader is required' <<<"$out" && P "no --reader is a refusal" || F "ran without a named reader"

out="$(run_init HSM_SO_PIN=nothex HSM_USER_PIN=123456 -- --reader 0)"
grep -q '16 hex digits' <<<"$out" && P "an SO-PIN that is not 8 bytes of hex is a refusal" \
  || F "a malformed SO-PIN was accepted"

out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --expect-serial DENK9999999)"
grep -q 'DIFFERENT CARD' <<<"$out" && P "a card whose certificate names another serial is refused" \
  || F "initialised a card that did not carry the expected serial"
[ -z "$(init_apdu)" ] && P "…and no INITIALIZE DEVICE was sent" || F "sent INITIALIZE to the wrong card"

# A blank card has no EF 2F02 — and this script is how a blank card gets provisioned — so absence
# cannot be fatal. But "blank" says nothing about WHICH card, so identity must come from the board
# id the caller verified out of band.
out="$(run_init "${PINS[@]}" -- --reader 0 --expect-serial ESP41D722E2)"
grep -q 'EF 2F02 is absent' <<<"$out" && P "a blank card with no verified board id is refused" \
  || F "wiped a card that could not identify itself"

out="$(run_init "${PINS[@]}" HSM_EXPECT_BOARD=8625B32841D722E2 HSM_BOARD_VERIFIED=1 \
        -- --reader 0 --expect-serial ESP41D722E2)"
grep -q 'proceeding on the verified board id' <<<"$out" \
  && P "a blank card WITH a verified board id that matches the serial proceeds" \
  || F "refused a blank card whose verified board id matches: $(tail -2 <<<"$out")"

out="$(run_init "${PINS[@]}" HSM_EXPECT_BOARD=DEADBEEFDEADBEEF HSM_BOARD_VERIFIED=1 \
        -- --reader 0 --expect-serial ESP41D722E2)"
grep -q 'does not end in the bytes' <<<"$out" \
  && P "a board id that disagrees with the serial is a refusal, not a preference" \
  || F "accepted a board id and a serial that describe different devices"

hdr "values that do not fit their field are refused, not encoded badly"
# printf '%02X' 256 is "100": three hex digits, an odd-length TLV value, and every byte after it in
# the APDU shifts by half a byte. The card would be initialised from a command nobody wrote.
for bad in "--retries 256" "--dkek-shares 300" "--pka-keys 999 --pka-required 1"; do
  # shellcheck disable=SC2086  # the fixture is a literal argument pair
  out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 $bad)"
  if grep -q 'does not fit in the single byte' <<<"$out"; then
    P "'$bad' is refused before the APDU is built"
  else
    F "'$bad' was encoded anyway: $(init_apdu)"
  fi
done
out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --retries 0)"
grep -q 'at least 1' <<<"$out" && P "--retries 0 is refused (it would lock the card on one wrong PIN)" \
  || F "--retries 0 was accepted"
out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --label "$(printf 'x%.0s' $(seq 1 240))")"
grep -q 'keep it under 200' <<<"$out" && P "an over-long label is refused, not truncated into a bad Lc" \
  || F "a label too long for a short APDU was accepted"

hdr "a label the card rejected is not reported as written"
cat > "$BIN/opensc-explorer" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_ARGV:?}"
cat >> "${STUB_STDIN:?}"
# SELECT ok, INITIALIZE ok, label write refused — the shape measured when the write lands in a
# second session.
printf 'Received (SW1=0x90, SW2=0x00)\nReceived (SW1=0x90, SW2=0x00)\nReceived (SW1=0x69, SW2=0x82)\n'
STUB
chmod +x "$BIN/opensc-explorer"
out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0 --label regalia)"; rc=$?
# THE STATUS AS WELL AS THE MESSAGE. A caller — hsm-staging-restore.sh, which now stops on a
# non-zero init — sees only the exit code, so a fatal message with a zero status would be read as
# success by everything downstream of the words.
if [ "$rc" -ne 0 ] && grep -q 'does NOT carry the label' <<<"$out"; then
  P "a 6982 on the TokenInfo write exits non-zero AND says the posture was still set"
else
  F "a refused label write was reported as a complete init (rc=$rc)"
fi

hdr "the child does not inherit the PINs it does not need"
# The APDU on stdin already carries both PINs; a child that also has them in its environment can
# leak them through /proc/<pid>/environ, a core dump or a crash reporter.
cat > "$BIN/opensc-explorer" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_ARGV:?}"
{ printf 'SO=%s USER=%s\n' "${HSM_SO_PIN:-<unset>}" "${HSM_USER_PIN:-<unset>}"; cat; } >> "${STUB_STDIN:?}"
printf 'Received (SW1=0x90, SW2=0x00)\nReceived (SW1=0x90, SW2=0x00)\nReceived (SW1=0x90, SW2=0x00)\n'
STUB
chmod +x "$BIN/opensc-explorer"
out="$(run_init "${PINS[@]}" STUB_CHR=DENK040414400000 -- --reader 0)"
if grep -q 'SO=<unset> USER=<unset>' "$BIN/stdin.txt"; then
  P "neither PIN is in the child's environment"
else
  F "the child inherited a PIN: $(grep -o 'SO=.* USER=.*' "$BIN/stdin.txt" | head -1)"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
