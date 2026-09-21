#!/usr/bin/env bash
# test-hsm-unwrap-key.sh — the two APDUs that put a key on the card and make it visible. NO CARD.
#
# UNWRAP KEY STORES THE KEY AND NOTHING ELSE. OpenSC's sc-hsm emulation enumerates private keys
# from their PKCS#15 description in EF C4xx, so a bare unwrap is invisible to every PKCS#11
# consumer — measured on DENK0404144 2026-09-17: after the unwrap the card held only CC01 and
# `pkcs11-tool --login --list-objects` listed no private key at all. A script that sent the first
# APDU and not the second would look like it worked, and the failure would surface as "the ceremony
# imported nothing" days later. So both APDUs, and all four status words, are the test.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
UNWRAP="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/hsm-unwrap-key.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$UNWRAP" ] || { echo "no hsm-unwrap-key.sh at $UNWRAP" >&2; exit 1; }
BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
head -c 363 /dev/urandom > "$BIN/blob.bin"

cat > "$BIN/opensc-explorer" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_ARGV:?}"
printf 'PIN_IN_ENV=%s\n' "${HSM_USER_PIN:-<unset>}" >> "${STUB_STDIN:?}"
cat >> "${STUB_STDIN:?}"
for sw in ${STUB_SW:-9000 9000 9000 9000}; do
  printf 'Received (SW1=0x%s, SW2=0x%s)\n' "${sw:0:2}" "${sw:2:2}"
done
STUB
chmod +x "$BIN/opensc-explorer"

# The opensc-explorer stub is not the only child. Every helper the script runs — wc, grep, od, tr —
# inherits the environment too, and an exported PIN is readable from /proc for as long as one lives.
# This stub records what `wc` saw, then becomes the real wc so the byte counts stay honest.
cat > "$BIN/wc" <<'STUB'
#!/usr/bin/env bash
# NO :? HERE. Tests that invoke the script directly set no ledger, and a stub that dies on its own
# bookkeeping turns every one of them into a false failure about the script under test.
[ -n "${STUB_HELPER_ENV:-}" ] && printf 'WC_PIN_IN_ENV=%s\n' "${HSM_USER_PIN:-<unset>}" >> "$STUB_HELPER_ENV"
exec /usr/bin/wc "$@"
STUB
chmod +x "$BIN/wc"
export PATH="$BIN:$PATH"

run_unwrap(){
  : > "$BIN/stdin.txt"; : > "$BIN/argv.txt"; : > "$BIN/helperenv.txt"
  local args=(--reader 0 --key-id 2 --blob "$BIN/blob.bin" --label akash-funding)
  local envs=()
  while [ $# -gt 0 ]; do case "$1" in *=*) envs+=("$1"); shift;; *) break;; esac; done
  [ $# -gt 0 ] && args=("$@")
  env STUB_STDIN="$BIN/stdin.txt" STUB_ARGV="$BIN/argv.txt" STUB_HELPER_ENV="$BIN/helperenv.txt" \
      HSM_USER_PIN=123456 ${envs[@]+"${envs[@]}"} \
      bash "$UNWRAP" "${args[@]}" 2>&1
}
apdu_at(){ grep -oE '^apdu [0-9A-Fa-f]+' "$BIN/stdin.txt" | awk '{print $2}' | sed -n "$1p" | tr 'a-f' 'A-F'; }

hdr "both APDUs are sent, and the blob goes in an EXTENDED command"
out="$(run_unwrap)"
case "$(apdu_at 3)" in
  807402930"0016B"*) P "UNWRAP KEY is 80 74 <id> 93 with a 3-byte extended Lc (363 bytes does not fit a short APDU)";;
  *) F "the UNWRAP APDU is wrong: $(apdu_at 3 | cut -c1-24)";;
esac
case "$(apdu_at 4)" in
  00D7C402*) P "the PrKD is written to EF C402 — the id in the file name is the key's";;
  *) F "the PrKD APDU does not target EF C4<key id>: $(apdu_at 4 | cut -c1-16)";;
esac
# A0 { SEQ { UTF8String label }, SEQ { OCTET id, BIT STRING 072080 }, A1 { SEQ { SEQ { OCTET "" }, INTEGER size } } }
case "$(apdu_at 4)" in
  *"0C0D616B6173682D66756E64696E67"*) P "…carrying the label as a UTF8String";;
  *) F "the label is not in the PrKD: $(apdu_at 4)";;
esac
case "$(apdu_at 4)" in
  *"040102"*"0303072080"*) P "…the key id as an OCTET STRING and the usage BIT STRING 07 20 80";;
  *) F "the key id or usage bits are missing from the PrKD: $(apdu_at 4)";;
esac
case "$(apdu_at 4)" in
  *"02020100"*) P "…and the key size as a POSITIVE INTEGER (0x0100 = 256, leading zero kept)";;
  *) F "the key size is missing or encoded negative: $(apdu_at 4)";;
esac

hdr "the PIN reaches the card but not the process table"
grep -q '313233343536' "$BIN/stdin.txt" && P "the VERIFY APDU carries the PIN" || F "the PIN never reached the card"
grep -q '123456' "$BIN/argv.txt" && F "the PIN appears in the child's argv" || P "no PIN in the child's argv"
grep -q 'PIN_IN_ENV=<unset>' "$BIN/stdin.txt" && P "and the child does not inherit it either" \
  || F "the child inherited HSM_USER_PIN: $(grep PIN_IN_ENV "$BIN/stdin.txt")"
# NOT JUST THE CARD COMMAND. `env -u HSM_USER_PIN` on the opensc-explorer call left every other
# helper — wc, grep, od — holding the PIN in its own environment, readable from /proc while it ran.
if [ -s "$BIN/helperenv.txt" ]; then
  grep -q 'WC_PIN_IN_ENV=123456' "$BIN/helperenv.txt" \
    && F "a plain helper (wc) inherited HSM_USER_PIN — it is still exported" \
    || P "plain helpers (wc) do not inherit it either — the PIN is off the environment entirely"
else
  F "the wc stub never ran, so this test proves nothing about helper environments"
fi

hdr "malformed numbers and outsized inputs are refused BEFORE the card is touched"
refuses(){ # refuses <why> <expected message> <args...>
  local why="$1" want="$2"; shift 2
  local o; o="$(run_unwrap "$@")"; local rc=$?
  : > "$BIN/stdin.txt.check"
  if [ "$rc" -eq 0 ]; then F "$why: accepted (exit 0)"; return; fi
  grep -qi -- "$want" <<<"$o" && P "$why" || F "$why: refused, but not for that reason: $o"
  grep -q '^apdu' "$BIN/stdin.txt" && F "$why: an APDU was sent anyway" || true
}
refuses "--key-size 0 is refused (it would encode as an empty DER INTEGER, 02 00)"         "key-size must be between" --reader 0 --key-id 2 --key-size 0 --blob "$BIN/blob.bin" --label x123456
head -c 20 /dev/urandom > "$BIN/tiny.bin"
refuses "a 20-byte blob is refused — that is not a key blob"         "not a key blob" --reader 0 --key-id 2 --blob "$BIN/tiny.bin" --label akash-funding
head -c 70000 /dev/urandom > "$BIN/huge.bin"
refuses "a 70000-byte blob is refused — extended Lc tops out at 65535"         "tops out at 65535" --reader 0 --key-id 2 --blob "$BIN/huge.bin" --label akash-funding
EMOJI="$(printf '\xf0\x9f\x94\x91%.0s' $(seq 1 30))"   # 30 emoji = 30 chars, 120 bytes
refuses "a 30-character / 120-byte emoji label is refused on BYTES, not characters"         "encodes to 120 bytes" --reader 0 --key-id 2 --blob "$BIN/blob.bin" --label "$EMOJI"

hdr "a leading-zero key id still addresses the right file (base 10, not octal)"
out="$(run_unwrap --reader 0 --key-id 08 --blob "$BIN/blob.bin" --label akash-funding)"
case "$(apdu_at 4)" in
  00D7C408*) P "--key-id 08 writes EF C408 — read as decimal 8";;
  *) F "--key-id 08 did not produce EF C408: $(apdu_at 4 | cut -c1-16) (octal parse?)";;
esac

hdr "every status word is checked, and named"
out="$(run_unwrap STUB_SW="9000 63C2 9000 9000")"
grep -q 'user PIN was REFUSED' <<<"$out" && P "a refused PIN says so, with the attempts left" \
  || F "a refused PIN was not reported: $out"
grep -q '2 attempt' <<<"$out" && P "…reading the counter out of the 63Cx status" || F "the retry counter is not reported"

out="$(run_unwrap STUB_SW="9000 9000 6400 9000")"
grep -q 'UNWRAP KEY answered 6400' <<<"$out" && P "a rejected blob is a failure naming the status" \
  || F "a rejected blob was not reported: $out"
grep -qi 'KCV mismatch' <<<"$out" && P "…and names the likely cause (the card holds another DKEK)" \
  || F "the operator is given no reading of 6400"

# THE ONE THAT MATTERS MOST: the key is on the card, and invisible.
out="$(run_unwrap STUB_SW="9000 9000 9000 6982")"
if grep -q 'PKCS#15 description' <<<"$out" && grep -q 'EF C402' <<<"$out"; then
  P "a key stored WITHOUT its description is reported as such, naming the EF"
else
  F "a bare unwrap with no PrKD was reported as success: $out"
fi
grep -q 'No PKCS#11 consumer will see it' <<<"$out" \
  && P "…and says what that means for anything that looks for the key" \
  || F "the consequence is not stated"

hdr "refusals before anything is sent"
out="$(env STUB_STDIN=/dev/null STUB_ARGV=/dev/null HSM_USER_PIN=123456 bash "$UNWRAP" --reader 0 --key-id 2 --blob "$BIN/blob.bin" 2>&1)"
grep -q 'label is required' <<<"$out" && P "no --label is a refusal (it is how consumers find the key)" \
  || F "ran without a label"
out="$(env STUB_STDIN=/dev/null STUB_ARGV=/dev/null bash "$UNWRAP" --reader 0 --key-id 2 --blob "$BIN/blob.bin" --label x 2>&1)"
grep -q 'HSM_USER_PIN is required' <<<"$out" && P "no PIN is a refusal (UNWRAP needs it verified)" \
  || F "ran without a PIN"
printf 'tiny' > "$BIN/tiny.bin"
out="$(env STUB_STDIN=/dev/null STUB_ARGV=/dev/null HSM_USER_PIN=123456 bash "$UNWRAP" --reader 0 --key-id 2 --blob "$BIN/tiny.bin" --label x 2>&1)"
grep -q 'not a key blob' <<<"$out" && P "a file too small to be a blob is refused" || F "a 5-byte 'blob' was sent"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
