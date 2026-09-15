#!/usr/bin/env bash
# test-prove-ceremony-slip39.sh — regression guard for prove-ceremony.sh PROOF 3
# REQUIREMENTS B5 — SLIP-39 share reconstruction.
# (the operator's pre-ceremony proof that the SLIP-0039 4-of-6 backup recovers).
#
# Background: slip39-mint.py intentionally NEVER writes the minted master secret to
# disk (that was the old `shamir create` leak). PROOF 3 used to grep slip39.txt for a
# 'master secret' line and compare it to a single 4-share recovery. Since that line no
# longer exists, the reference was always empty and PROOF 3 could NEVER pass — the very
# proof meant to catch a broken SLIP-39 backup path before a real ceremony was dead.
#
# This test runs prove-ceremony.sh and asserts PROOF 3 is PROVEN (and not FAILED). It is
# scoped to PROOF 3 only: other proofs (e.g. the HSM address derivation) may legitimately
# not pass on every dev box, so we never gate on the whole-script exit code here.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

for t in ssss-split ssss-combine shamir qrencode age age-keygen python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing real tool: $t — skipping"; exit 0; }
done
python3 -c "import shamir_mnemonic" 2>/dev/null || { echo "shamir_mnemonic not installed — skipping"; exit 0; }

hdr "PROOF 3 — SLIP-0039 4-of-6 backup actually recovers (reference-free)"
out="$(bash "$SCRIPTS/prove-ceremony.sh" 2>&1)"

# The dead reference-based check reports this exact failure line; it must be gone.
if grep -qi "FAILED.*SLIP-39 recovery mismatch" <<< "$out"; then
  F "PROOF 3 still FAILS on SLIP-39 recovery (stale master-secret reference check)"
else
  P "PROOF 3 does not report a SLIP-39 recovery mismatch"
fi

# And it must positively prove recovery of the SLIP-0039 word-shares.
if grep -qi "PROVEN.*SLIP-0039 word-shares recover" <<< "$out"; then
  P "PROOF 3 positively proves the 4-of-6 SLIP-0039 backup recovers"
else
  F "PROOF 3 did not emit a PROVEN result for SLIP-0039 recovery"
fi

# Defense-in-depth: the minted master secret must never be written to the shares file.
if grep -qi "master secret LEAKED" <<< "$out"; then
  F "prove-ceremony.sh reported the master secret leaked into the shares file"
else
  P "no master-secret leak reported by PROOF 3"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
