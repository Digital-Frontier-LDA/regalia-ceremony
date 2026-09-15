#!/usr/bin/env bash
# test-commission-card.sh — REQUIREMENTS B3, B6, B7. Implements PLAN.md 3.6.
#
# Commissioning is the ONLY gate for properties that can only be false at the rack: whether the host
# carries a DKEK, whether the card really has RRC disabled, and whether it is OUR card rather than
# merely a genuine one. Once the card is in service nobody checks any of this again.
#
# So the property under test is not "does it check things" but "does it REFUSE when it cannot tell".
# A commissioning script that exits 0 because a tool was missing certifies nothing while looking
# like it certified everything — and that is the exact failure this project has shipped repeatedly.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="$HERE/../../../../hsm-host-role/files/commission-card.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$CC" ] || { echo "  (skipping: commission-card.sh not found at $CC)"; exit 0; }

FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
trap 'rm -rf "$FAKE"' EXIT

# sc-hsm-tool stub. RRC_STATE controls whether the card reports the vulnerable configuration.
cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
case "${RRC_STATE:-absent}" in
  enabled)  printf 'Version              : 4.0\nConfig options       :\n  User PIN reset with SO-PIN enabled\nCHR: %s\n' "${FAKE_CHR:-DEVCHR001}";;
  disabled) printf 'Version              : 4.0\nConfig options       :\nCHR: %s\n' "${FAKE_CHR:-DEVCHR001}";;
  *) exit 1;;
esac
STUB
cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *--list-slots*) printf 'Slot 0 (0x0): Reader\n  token label        : t\n  serial num         : %s\n' "${FAKE_SERIAL:-SER123}";;
  *--list-objects*) printf 'Private Key Object\n';;
esac
exit 0
STUB
chmod +x "$FAKE/sc-hsm-tool" "$FAKE/pkcs11-tool"

# The DevAut readout needs Smart Card Shell — sc-hsm-tool cannot print a CHR (measured
# 2026-08-01). Stub the scriptrunner so these tests exercise the real parsing path.
mkdir -p "$FAKE/scsh"
cat > "$FAKE/scsh/scriptrunner" <<'STUB'
#!/usr/bin/env bash
printf 'DEVAUT_CHR=%s\n' "${FAKE_CHR:-DEVCHR001}"
printf 'DEVAUT_CAR=%s\n' "${FAKE_CAR:-ISSUER-CA-01}"
printf 'DEVAUT_SHA256=%s\n' "${FAKE_SHA:-AABBCC}"
printf 'DEVAUT_BYTES=940\n'
STUB
chmod +x "$FAKE/scsh/scriptrunner"
: > "$FAKE/devaut.js"

run_cc(){ RRC_STATE="${1}" FAKE_CHR="${2:-DEVCHR001}" FAKE_SERIAL="${3:-SER123}" \
  SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" \
  bash "$CC" --expect-chr "${4:-DEVCHR001}" --expect-serial "${5:-SER123}" >"$FAKE/out" 2>&1; echo $?; }

# =================================================================================================
hdr "The RRC check BITES — a vulnerable card must be refused"
rc="$(run_cc enabled)"
[ "$rc" != 0 ] && P "a card reporting 'User PIN reset with SO-PIN enabled' is REFUSED (rc=$rc)" \
               || F "a card with RRC ENABLED was accepted — the D3 ruling is unenforceable"
grep -qi 'DO NOT RACK THIS CARD' "$FAKE/out" \
  && P "…and says so unambiguously" || F "the refusal is not stated in operator language"
grep -qi 'hardcodes the option ON\|SmartCardHSMInitializer' "$FAKE/out" \
  && P "…and names the fix (scsh, because sc-hsm-tool cannot produce such a card)" \
  || F "the operator is refused without being told how to produce a compliant card"

hdr "A compliant card passes the RRC check"
rc="$(run_cc disabled)"
grep -q 'RRC is disabled' "$FAKE/out" \
  && P "an RRC-disabled card passes that check" \
  || F "a compliant card failed the RRC check — the gate cries wolf and will be bypassed"

hdr "IDENTITY: a swapped genuine card must be caught"
# The attack colocation introduces. Any genuine Nitrokey passes every policy check ever written;
# only the pinned CHR and serial distinguish OURS.
rc="$(run_cc disabled OTHERCHR SER123 DEVCHR001 SER123)"
[ "$rc" != 0 ] && P "a CHR mismatch is refused (a swapped genuine Nitrokey)" \
               || F "a different device passed commissioning — substitution is undetected"
grep -qi 'CHR MISMATCH' "$FAKE/out" && P "…named as a mismatch, not a generic error" || F "the CHR failure is not identified"

rc="$(run_cc disabled DEVCHR001 OTHERSER DEVCHR001 SER123)"
[ "$rc" != 0 ] && P "a SERIAL mismatch is refused" || F "a serial mismatch passed"

hdr "CANNOT-EVALUATE IS A FAILURE, NOT A SKIP"
# The defect class this whole repo keeps hitting: a check that could not run reporting success.
rc="$(run_cc absent)"   # sc-hsm-tool exits 1 -> card unreadable
[ "$rc" != 0 ] && P "an unreadable card FAILS rather than skipping the RRC check" \
               || F "an unreadable card was treated as compliant — the worst available outcome"
grep -qi 'CANNOT BE EVALUATED' "$FAKE/out" \
  && P "…and says explicitly that it could not be evaluated" \
  || F "the output does not distinguish 'checked and fine' from 'could not check'"

hdr "Commissioning without pinned identity is itself a failure"
RRC_STATE=disabled bash "$CC" >"$FAKE/out2" 2>&1; rc=$?
[ "$rc" != 0 ] && P "running with no --expect-chr/--expect-serial is refused" \
               || F "commissioning passed without ever pinning identity — it proves nothing"
grep -qi 'substitution is the attack' "$FAKE/out2" \
  && P "…and explains why identity pinning is the point" || F "no rationale given"

hdr "A SELF-SIGNED device certificate is refused"
# Measured on a Pico 2026-08-01: CHR == CAR, i.e. nothing above the device vouches for it. There is
# no manufacturer root to validate against, so "genuine hardware" cannot be established at all.
rc="$(FAKE_CAR=DEVCHR001 run_cc disabled)"
[ "$rc" != 0 ] && P "CHR == CAR (self-signed) is refused — cannot be proven genuine" \
               || F "a self-signed device certificate passed commissioning"
grep -qi 'never hold production keys' "$FAKE/out" \
  && P "…and names the Pico as the expected case" || F "no explanation of when this is expected"

hdr "The DevAut DIGEST is pinnable, and a mismatch is refused"
rc="$(FAKE_SHA=DEADBEEF SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" RRC_STATE=disabled FAKE_SERIAL=SER123 \
      bash "$CC" --expect-serial SER123 --expect-devaut-sha AABBCC >"$FAKE/out3" 2>&1; echo $?)"
[ "$rc" != 0 ] && P "a digest mismatch is refused (stronger than the CHR, which is just a name)" \
               || F "a substituted device passed on the digest check"

hdr "Missing Smart Card Shell is CANNOT-EVALUATE, not a pass"
rc="$(RRC_STATE=disabled FAKE_SERIAL=SER123 SCSH_HOME=/nonexistent \
      bash "$CC" --expect-serial SER123 --expect-chr X >"$FAKE/out4" 2>&1; echo $?)"
[ "$rc" != 0 ] && P "no scsh available -> identity CANNOT BE EVALUATED -> failure" \
               || F "identity silently skipped when scsh is absent"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
