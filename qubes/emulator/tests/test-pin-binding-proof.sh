#!/usr/bin/env bash
# test-pin-binding-proof.sh — REQUIREMENTS A6, B6. Implements PLAN.md 3.1.
#
# THE GAP. Two PIN values existed and nothing connected them:
#   escrow: pins.env -> hsm_a_user_pin -> tier-0 payload -> 4-of-6 metal shares
#   card:   whatever the operator typed into Smart Card Shell at initialisation
# `fail_ceremony_default_pin` guards the ESCROW value only. A ceremony could pass every guard,
# engrave a strong PIN onto metal, and rack a card answering to something else.
#
# WHY IT MATTERS MORE THAN IT SOUNDS. The failure is silent and delayed by YEARS. A custodian
# recovers the payload, reads the PIN, presents it — wrong. Two attempts left, no context, no way to
# derive the real value. The seed still recovers the KEY, but the deployed card is bricked by its
# own escrow. Under the colocated topology that card is in a rack in another city.
#
# WHAT IS ASSERTED HERE. These are STATIC assertions over ceremony.sh, and they say so. The proof
# itself runs against a real card inside step_hsm_import, so nothing here executes it — this pins
# that the check EXISTS, that it FAILS CLOSED, and that its message tells an operator what to do.
# Whether it fires correctly belongs to the hardware drill.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CEREMONY="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/ceremony.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$CEREMONY" ] || { echo "  (skipping: $CEREMONY not found)"; exit 0; }

# Only the executable body — a grep over the whole file would match the prose explaining the trap.
BODY="$(python3 "$HERE/source_lexing.py" shell "$CEREMONY")" \
  || { echo "source lexer failed" >&2; exit 2; }

hdr "The proof exists and uses the ESCROWED value, not a fresh prompt"
grep -q 'hsm_a_user_pin' <<<"$BODY" \
  && P "step_hsm_import references the escrowed hsm_a_user_pin" \
  || F "the escrowed PIN is never read back — escrow and card remain unconnected"
grep -qE 'pkcs11-tool --login --pin "\$hsm_a_user_pin"' <<<"$BODY" \
  && P "it PRESENTS that value to the card (a positive control, not an inspection)" \
  || F "nothing presents the escrowed PIN to the card; the binding is asserted, not proven"

hdr "It FAILS CLOSED — a mismatch aborts the ceremony"
# The dangerous shape would be a warning that lets the operator continue and engrave anyway.
if grep -qE '^\s*return 1' <<< "$(grep -A22 'PIN BINDING FAILED' <<<"$BODY")"; then
  P "a failed binding returns non-zero (the ceremony stops)"
else
  F "a mismatch does not abort — an operator could engrave a PIN that does not open the card"
fi

hdr "The failure message is ACTIONABLE at the moment it can still be fixed"
MSG="$(grep -A20 'PIN BINDING FAILED' <<<"$BODY" || true)"
grep -qi 'FIX IT NOW' <<<"$MSG" \
  && P "tells the operator to fix it now, while both values are known" \
  || F "does not convey that this is the last cheap moment to fix it"
grep -qiE 'change the card PIN|correct pins.env' <<<"$MSG" \
  && P "names BOTH remedies (change the card, or correct the escrow)" \
  || F "the operator is told it failed but not which of the two values to move"
grep -qiE 'bricked by its own backup|does not open the card' <<<"$MSG" \
  && P "states the consequence, so the check does not read as bureaucracy" \
  || F "no consequence stated — a check whose cost is unexplained gets bypassed"

hdr "The retry-counter cost is disclosed, not hidden"
grep -qiE 'PIN tries.*->|attempt was consumed' <<<"$MSG" \
  && P "reports that one attempt was spent proving the mismatch" \
  || F "silently burns a PIN attempt without telling the operator"
grep -q 'hsm_pin_tries_left' <<<"$BODY" \
  && P "reads the counter from the card rather than assuming a value" \
  || F "no counter readout — the message would have to guess"
# The count is genuinely unknown (Nitrokey says 15, OpenSC says 3), so a guessed default in an
# error message would be inventing a fact. PLAN.md 1.3 measures it.
if grep -qE 'echo "\?"|\|\| echo "\?"' <<< "$(grep -A6 'hsm_pin_tries_left()' <<<"$BODY")"; then
  P "returns \"?\" when the counter cannot be read (no invented number)"
else
  F "falls back to a hardcoded count — F6 is unreconciled, so that would be a fabricated fact"
fi

hdr "An UNSET escrow value is reported as SKIPPED, never as passed"
# The subtle failure: step 0 not run, no PIN to compare, and the ceremony continues looking green.
SKIP="$(grep -B2 -A6 'PIN-BINDING PROOF was SKIPPED' <<<"$BODY" || true)"
[ -n "$SKIP" ] \
  && P "an unset hsm_a_user_pin produces an explicit SKIPPED warning" \
  || F "an unset escrow value would silently skip the proof and read as success"
grep -qi 'SKIPPED, not passed' <<<"$SKIP" \
  && P "…and says plainly that skipped is not passed" \
  || F "the skip does not distinguish itself from a pass"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
