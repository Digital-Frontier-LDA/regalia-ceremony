#!/usr/bin/env bash
# test-payload-step.sh — adversarial tests for ceremony.sh step_payload, the wizard step that
# encrypts the Tier-0 recovery roots and emits their archival QR codes.
#
# WHAT MAKES THIS STEP DANGEROUS: everything it produces is meant to be printed, sealed, and
# not looked at again for years. A payload that is empty, or encrypted to the wrong key, or
# whose QR codes do not actually rebuild, still LOOKS completely successful on the day — the
# sheets come out of the printer, the seals go on, and the failure only surfaces at recovery
# when nothing can be done about it. So every one of those cases must abort loudly, here.
#
# Runs natively: real `age` and `qrencode` if present, otherwise the suite self-skips.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
TEST_HERE="$HERE"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

for t in age age-keygen qrencode; do
  command -v "$t" >/dev/null 2>&1 || { echo "  (skipping: $t not installed)"; exit 0; }
done

# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
pause(){ :; }
# shellcheck disable=SC2034  # consumed by the sourced ceremony.sh
PRINTER=""
init_work

# Silence the wizard's command echo. Unlike the abort suites, nothing here inspects WHAT was
# shown, so capturing it into LAST_SHOWN was dead weight (0 reads) — dropped.
show(){ :; }
ask(){ return 0; }

KEYDIR="$(mktemp -d)"; trap 'rm -rf "$KEYDIR"' EXIT
age-keygen -o "$KEYDIR/bg.key" 2>/dev/null
RECIP="$(grep 'public key:' "$KEYDIR/bg.key" | awk '{print $4}')"

filled_payload() {
  cat > "$WORK/payload.txt" <<'EOF'
# AKASH CONSOLE — TIER-0 RECOVERY ROOTS
derivation_wallet_mnemonic_v2: abandon abandon abandon abandon abandon about
funding_wallet_mnemonic_v2: legal winner thank year wave sausage worth yellow
API_KEY_HASH_SECRET: NOT-A-REAL-SECRET-test-fixture-only
hsm_a_user_pin: 648219
sle4442_psc: FFFFFF
EOF
}

# The wizard's new step 7 gate (commit 0c09ff2fd) refuses to produce the payload unless the
# operator has loaded HSM PIN defaults from a file via step 0. The test's reset_state rewinds
# the workdir AND re-runs step_set_pins so every test starts in a state where the gate is
# satisfied. The test exercises the dev path (the fail-closed default), so the dev defaults
# are loaded as the input. The prod-guard test verifies that a literal CEREMONY_MODE=prod
# change catches the dev defaults.
CEREMONY_MODE=dev
write_dev_pins() {
  printf 'hsm_a_user_pin=648219\nhsm_a_so_pin=3537363231383830\nhsm_b_user_pin=648219\nhsm_b_so_pin=3537363231383830\nhsm_c_user_pin=648219\nhsm_c_so_pin=3537363231383830\nyubikey_piv_pin=123456\nyubikey_piv_puk=12345678\nyubikey_mgmt_key=010203040506070801020304050607080102030405060708\n' > "$WORK/pins.env"
}
reset_state(){
  rm -rf "$WORK/payload.txt" "$WORK/payload.age" "$WORK/payload-qr" "$WORK/breakglass.key" "$WORK/pins.env"
  # Set the gate flag BEFORE step_set_pins so even if the function exits early (e.g. because
  # CEREMONY_MODE is wrong from a prior test), the gate is still satisfied. The function call
  # is best-effort and will set the PIN vars if it succeeds; if it fails, the next test's step
  # 0 call will retry.
  state_step0_done=1
  write_dev_pins
  CEREMONY_MODE=dev step_set_pins >/dev/null 2>&1 || true
}
# Initial run so the very first test sees a clean state.
write_dev_pins; step_set_pins >/dev/null 2>&1

# =====================================================================================
hdr "REFUSES a secret key pasted where the RECIPIENT belongs"
reset_state; filled_payload
out="$(BREAKGLASS_RECIPIENT='AGE-SECRET-KEY-1EXAMPLE' step_payload 2>&1)"
grep -qi "not an age recipient" <<< "$(echo "$out")" \
  && P "rejects an AGE-SECRET-KEY where a recipient was expected" \
  || F "accepted a secret key as the encryption recipient"
[ ! -s "$WORK/payload.age" ] && P "nothing was encrypted on a bad recipient" \
                             || F "produced an encrypted payload despite a bad recipient"

# =====================================================================================
hdr "GATE: step_payload refuses to run if step 0 (set HSM PINs) has not been completed"
# The gate is the whole point of this session's work — without it, the dev-default PIN block
# in the template would be load-bearing for a real operator who forgot to run step 0. Reset
# state_step0_done and verify the wizard's first failure is the gate, not anything downstream.
reset_state
state_step0_done=0
rm -f "$WORK/pins.env"
out="$(BREAKGLASS_RECIPIENT="age1test" step_payload 2>&1)"
grep -qi "requires PIN defaults" <<< "$(echo "$out")" \
  && P "step_payload refuses to run before step 0 completes" \
  || F "BUG: step_payload ran without step 0 — the gate is missing"
[ ! -s "$WORK/payload.age" ] && P "no payload produced when the gate fires" \
                             || F "BUG: payload produced despite the gate"
reset_state

# =====================================================================================
hdr "PROD GUARD: in CEREMONY_MODE=prod the dev-default PIN block refuses to start"
# The dev-default guard is the OTHER safety feature — it refuses even after step 0 if the loaded
# PIN values are still the recognised dev fixtures. Verify both directions.
state_step0_done=0
write_dev_pins
CEREMONY_MODE=prod out="$(step_set_pins 2>&1)"; grep -qi "PROD GUARD" <<< "$(echo "$out")" \
  && P "PROD mode rejects the dev-default PIN block" \
  || F "BUG: PROD mode accepted the dev-default PIN block"
CEREMONY_MODE=dev step_set_pins >/dev/null 2>&1
reset_state

# =====================================================================================
hdr "REFUSES an UNFILLED template (labels with no values)"
reset_state
# Step 0 has run (the gate test above covers the opposite). To exercise the empty-label guard,
# set the gate flag and clear the loaded PIN vars so the wizard's heredoc writes empty values.
state_step0_done=1
rm -f "$WORK/payload.txt"
unset hsm_a_user_pin hsm_a_so_pin hsm_b_user_pin hsm_b_so_pin hsm_c_user_pin hsm_c_so_pin
unset yubikey_piv_pin yubikey_piv_puk yubikey_mgmt_key
cat > "$WORK/payload.txt" <<'EOF'
# AKASH CONSOLE — TIER-0 RECOVERY ROOTS
derivation_wallet_mnemonic_v2:
funding_wallet_mnemonic_v2:
ops_age_key:
API_KEY_HASH_SECRET:
hsm_a_user_pin:
hsm_a_so_pin:
hsm_b_user_pin:
hsm_b_so_pin:
hsm_c_user_pin:
hsm_c_so_pin:
sle4442_psc:
yubikey_piv_pin:
yubikey_piv_puk:
yubikey_mgmt_key:
EOF
out="$(BREAKGLASS_RECIPIENT="$RECIP" step_payload 2>&1)"
grep -qiE "no filled-in values|empty label" <<< "$out" \
  && P "detects a template whose recovery-root values were never filled in" \
  || F "BUG: an empty template would have been encrypted, printed and sealed"
[ ! -s "$WORK/payload.age" ] && P "no payload emitted for an empty template" \
                             || F "BUG: emitted an encrypted payload with no actual secrets in it"
# Restore dev-mode for downstream tests. The unset above cleared the loaded PIN vars to
# force the empty-label guard; the cascading tests (happy path, regression, warns, end-to-end,
# secrets, burn) need the PINs back. Re-write the file, re-run step_set_pins to set them,
# and leave state_step0_done=1 so the gate is satisfied for the next test.
state_step0_done=1
write_dev_pins
step_set_pins >/dev/null 2>&1

# =====================================================================================
hdr "HAPPY PATH: encrypts, emits QR symbols, and PROVES the round-trip"
reset_state; filled_payload
cp "$KEYDIR/bg.key" "$WORK/breakglass.key"
out="$(BREAKGLASS_RECIPIENT="$RECIP" step_payload 2>&1)"
[ -s "$WORK/payload.age" ] && P "payload encrypted" || F "no encrypted payload produced"
grep -q "BEGIN AGE ENCRYPTED FILE" <<< "$(head -1 "$WORK/payload.age" 2>/dev/null)" \
  && P "payload is age-armored ciphertext" || F "payload is not age armor"
ls "$WORK/payload-qr"/qr-*.png >/dev/null 2>&1 \
  && P "QR symbols emitted" || F "no QR symbols emitted"
[ -s "$WORK/payload-qr/INSTRUCTIONS.txt" ] \
  && P "reassembly instructions emitted alongside the symbols" \
  || F "no INSTRUCTIONS.txt — the sheets would be unreadable without this repo"
grep -qi "ROUND-TRIP PROVEN" <<< "$(echo "$out")" \
  && P "wizard PROVES QR -> rebuild -> decrypt returns the exact payload" \
  || F "wizard did not prove the round-trip before telling the operator to print"

# =====================================================================================
hdr "REGRESSION: a payload whose QR codes do NOT rebuild must ABORT before printing"
# The catastrophic silent case: sheets print fine, seals go on, and the failure is invisible
# until recovery. Corrupt a chunk after emission and re-run the verification the step does.
reset_state; filled_payload
cp "$KEYDIR/bg.key" "$WORK/breakglass.key"
BREAKGLASS_RECIPIENT="$RECIP" step_payload >/dev/null 2>&1
sed '1s/.$/X/' "$WORK/payload-qr/chunks.txt" > "$WORK/payload-qr/chunks.corrupt.txt"
if python3 "$SCRIPTS/payload-qr.py" --join "$WORK/payload-qr/chunks.corrupt.txt" \
     --out "$WORK/x.age" >/dev/null 2>&1; then
  F "BUG: a corrupted chunk set rebuilt without complaint"
else
  P "a corrupted chunk set is rejected, not silently rebuilt"
fi

# =====================================================================================
hdr "WARNS (does not silently pass) when no key is present to prove the round-trip"
reset_state; filled_payload
out="$(BREAKGLASS_RECIPIENT="$RECIP" step_payload 2>&1)"
grep -qi "WITHOUT a decrypt round-trip proof" <<< "$(echo "$out")" \
  && P "tells the operator the sheets are unproven when no key is available" \
  || F "silently emitted unproven sheets with no warning"
grep -qi "ROUND-TRIP PROVEN" <<< "$(echo "$out")" \
  && F "BUG: claimed a round-trip proof it could not have performed" \
  || P "did not claim a proof it could not perform"

# =====================================================================================
hdr "The emitted payload really does decrypt back to the original (end-to-end)"
reset_state; filled_payload
cp "$KEYDIR/bg.key" "$WORK/breakglass.key"
BREAKGLASS_RECIPIENT="$RECIP" step_payload >/dev/null 2>&1
python3 "$SCRIPTS/payload-qr.py" --join "$WORK/payload-qr/chunks.txt" --out "$WORK/rt.age" >/dev/null 2>&1
age -d -i "$KEYDIR/bg.key" "$WORK/rt.age" > "$WORK/rt.txt" 2>/dev/null
if cmp -s "$WORK/payload.txt" "$WORK/rt.txt"; then
  P "scanned-chunk rebuild decrypts to a byte-identical payload"
else
  F "end-to-end rebuild did NOT match the original payload"
fi

# =====================================================================================
hdr "Secret VALUES never reach the terminal"
reset_state; filled_payload
cp "$KEYDIR/bg.key" "$WORK/breakglass.key"
out="$(BREAKGLASS_RECIPIENT="$RECIP" step_payload 2>&1)"
leaked=0
for v in "abandon abandon abandon" "legal winner thank" "NOT-A-REAL-SECRET" "648219" "FFFFFF"; do
  grep -qF "$v" <<< "$out" && { F "LEAKED a payload value to the terminal: $v"; leaked=1; }
done
[ "$leaked" = 0 ] && P "no payload value appeared in the step's output"

# =====================================================================================
hdr "BURN GUARD: payload.age may be archived; payload.txt and QR PNGs may NOT"
reset_state; filled_payload
cp "$KEYDIR/bg.key" "$WORK/breakglass.key"
BREAKGLASS_RECIPIENT="$RECIP" step_payload >/dev/null 2>&1
ceremony_code="$(python3 "$TEST_HERE/source_lexing.py" shell "$SCRIPTS/ceremony.sh")" \
  || { echo "source lexer failed" >&2; exit 2; }
grep -q "payload.age" <<<"$ceremony_code" \
  && P "payload.age is on the M-DISC allowlist" || F "payload.age is not staged for the disc"
grep -qE "name 'payload.txt'" <<<"$ceremony_code" \
  && P "the PLAINTEXT payload.txt is a refused stray artifact" \
  || F "BUG: payload.txt (both mnemonics + every PIN) could reach write-once media"
grep -qE "name '\*\.png'" <<<"$ceremony_code" \
  && P "the *.png stray guard is intact (QR symbols stay on paper, not the disc)" \
  || F "BUG: the *.png burn guard was relaxed — a plaintext share QR could be archived"
grep -qE "name 'mixed.hex'" <<<"$ceremony_code" \
  && P "mixed master-secret entropy is a refused stray artifact" \
  || F "BUG: the mixed entropy (the master secret itself) could reach the disc"

# =====================================================================================
hdr "BORN-IN-HSM path is UNSUPPORTED and gated OFF by default"
# The custody principle is that every secret reconstructs from the 4-of-6 shares alone. A
# born-in-HSM key does not — its only backup is a DKEK blob needing a compatible SmartCard-HSM.
# It must therefore be unreachable by accident, and must say why rather than just failing.
out="$(step_hsm_funding 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "step_hsm_funding refuses to run without an explicit opt-in" \
                || F "BUG: the unsupported born-in-HSM path ran by default"
grep -qi "NOT reconstructible from the 4-of-6" <<< "$(echo "$out")" \
  && P "explains WHY it is unsupported (not just that it failed)" \
  || F "refused without explaining the custody reason"
grep -qi "CEREMONY_ALLOW_BORN_IN_HSM=1" <<< "$(echo "$out")" \
  && P "names the explicit opt-in for anyone who accepts the hardware dependency" \
  || F "gave no way to run the path deliberately"
grep -qi "step 3 option (c)" <<< "$(echo "$out")" \
  && P "points the operator at the supported seed-based path" \
  || F "did not point at the supported alternative"

# =====================================================================================
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
