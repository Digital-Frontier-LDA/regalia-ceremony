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
CC="$HERE/../../../hsm-host-role/files/commission-card.sh"

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
# EC_POINT is a real secp256k1 point read off DENK0404144; EC_PARAMS 06052b8104000a is secp256k1.
# FAKE_CURVE lets a test put a non-secp256k1 key at the wallet id.
case "$*" in
  *--list-slots*) printf 'Slot 0 (0x0): Reader\n  token label        : t\n  serial num         : %s\n' "${FAKE_SERIAL:-SER123}";;
  *"--type pubkey"*)
    printf 'Public Key Object; EC  EC_POINT 256 bits\n'
    printf '  EC_POINT:   0441042e3986e7ff710e3a8b8d2e4c1fbab63ee23d7cf92a691906250b4ab6d8c723d35f432bcbd2a7f5e24cb6329cbba4379b990c1b1811179ee3fba9193a61458840\n'
    printf '  EC_PARAMS:  %s\n' "${FAKE_CURVE:-06052b8104000a}"
    printf '  label:      wallet\n  ID:         %s\n' "${FAKE_KEY_ID:-01}"
    ;;
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

# The OpenSC-only reader (qubes/scripts/hsm-devaut-read.sh) prints the same fields without Java.
# Stubbed here so these tests never touch a card; the reader itself is covered, against a real
# card blob, by test_hsm_devaut_read.py.
cat > "$FAKE/devaut-read.sh" <<'STUB'
#!/usr/bin/env bash
printf 'DEVAUT_CHR=%s\n' "${FAKE_CHR:-DEVCHR001}"
printf 'DEVAUT_CAR=%s\n' "${FAKE_CAR:-ISSUER-CA-01}"
printf 'DEVAUT_SHA256=%s\n' "${FAKE_SHA:-AABBCC}"
STUB
chmod +x "$FAKE/devaut-read.sh"

# derive-akash-address.py stub: turns the card's EC point into whatever FAKE_ADDR says.
cat > "$FAKE/derive.py" <<'STUB'
#!/usr/bin/env python3
import os, sys
print(os.environ.get("FAKE_ADDR", "akash1cardkey"))
STUB
chmod +x "$FAKE/derive.py"

# The DKEK guard is exercised for real by test-day0-dkek-rule-and-roles.sh. Here it is stubbed so
# the suite is hermetic — otherwise every run scans the developer's own home directory — and so the
# THREE outcomes it can return (clean / found / could-not-scan) can each be put to commissioning.
cat > "$FAKE/assert-no-dkek.sh" <<'STUB'
#!/usr/bin/env bash
case "${FAKE_DKEK:-clean}" in
  found)   echo "DKEK MATERIAL PRESENT ON A HOST WITH PIN ACCESS" >&2; exit 1;;
  unknown) echo "REFUSING: /root could not be scanned completely" >&2; exit 2;;
  *)       echo "OK: no DKEK material found on this host"; exit 0;;
esac
STUB
chmod +x "$FAKE/assert-no-dkek.sh"
export HSM_ASSERT_NO_DKEK="$FAKE/assert-no-dkek.sh"

run_cc(){ RRC_STATE="${1}" FAKE_CHR="${2:-DEVCHR001}" FAKE_SERIAL="${3:-SER123}" \
  SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" HSM_DEVAUT_READ_SH="$FAKE/devaut-read.sh" \
  bash "$CC" --expect-chr "${4:-DEVCHR001}" --expect-serial "${5:-SER123}" \
             --expect-devaut-sha "${6:-AABBCC}" >"$FAKE/out" 2>&1; echo $?; }

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

hdr "No reader for C.DevAut at all is CANNOT-EVALUATE, not a pass"
rc="$(RRC_STATE=disabled FAKE_SERIAL=SER123 SCSH_HOME=/nonexistent HSM_DEVAUT_READ_SH=/nonexistent \
      bash "$CC" --expect-serial SER123 --expect-devaut-sha AABBCC >"$FAKE/out4" 2>&1; echo $?)"
[ "$rc" != 0 ] && P "neither scsh nor the OpenSC reader -> identity CANNOT BE EVALUATED -> failure" \
               || F "identity silently skipped when no C.DevAut reader is available"
grep -qi 'CANNOT BE EVALUATED' "$FAKE/out4" && P "…and says so" || F "the failure is not named as unevaluable"

hdr "Commissioning does NOT require a Java toolchain at the rack"
# Requiring a Smart Card Shell install in a colocation cage is how a mandatory check becomes a
# skipped one. hsm-devaut-read.sh reads the same EF 2F02 with opensc-tool alone.
rc="$(RRC_STATE=disabled FAKE_SERIAL=SER123 SCSH_HOME=/nonexistent HSM_DEVAUT_READ_SH="$FAKE/devaut-read.sh" \
      bash "$CC" --expect-serial SER123 --expect-devaut-sha AABBCC >"$FAKE/out5" 2>&1; echo $?)"
[ "$rc" = 0 ] && P "with no scsh, the OpenSC-only reader satisfies the identity check" \
              || { F "commissioning failed with the OpenSC reader available"; sed 's/^/      /' "$FAKE/out5"; }
grep -q 'digest matches' "$FAKE/out5" && P "…and the pinned digest is what was compared" || F "the digest was not compared"

hdr "PINNING ONE FIELD IS NOT PINNING IDENTITY"
# A serial is self-reported and a CHR is a name; only the C.DevAut digest covers the device public
# key. Accepting any ONE of the three let a run that pinned only the CHR report a commissioned card.
rc="$(RRC_STATE=disabled FAKE_SERIAL=SER123 SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" \
      bash "$CC" --expect-chr DEVCHR001 >"$FAKE/out6" 2>&1; echo $?)"
[ "$rc" != 0 ] && P "--expect-chr alone is refused" || F "a CHR alone was accepted as identity"
rc="$(RRC_STATE=disabled FAKE_SERIAL=SER123 SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" \
      bash "$CC" --expect-serial SER123 >"$FAKE/out6" 2>&1; echo $?)"
[ "$rc" != 0 ] && P "--expect-serial without the digest is refused" \
               || F "a self-reported serial alone was accepted as identity"
grep -qi 'expect-devaut-sha' "$FAKE/out6" && P "…and the missing flag is named" || F "the operator is not told what to pass"

hdr "--expect-address is CHECKED, not merely accepted"
# It used to parse and then be ignored: the operator read "Commissioning PASSED" believing the
# funding address had been confirmed. A silently ignored expectation manufactures confidence.
cc_addr(){ RRC_STATE=disabled FAKE_SERIAL=SER123 FAKE_ADDR="${2:-akash1cardkey}" \
  SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" HSM_DERIVE_ADDRESS_PY="$FAKE/derive.py" \
  bash "$CC" --expect-serial SER123 --expect-devaut-sha AABBCC --expect-address "$1" \
    >"$FAKE/out7" 2>&1; echo $?; }
rc="$(cc_addr akash1cardkey)"
[ "$rc" = 0 ] && P "the address the card's key derives to is accepted" \
              || { F "a matching funding address was rejected"; sed 's/^/      /' "$FAKE/out7"; }
rc="$(cc_addr akash1somebodyelse)"
[ "$rc" != 0 ] && P "a DIFFERENT funding address is refused" \
               || F "--expect-address was accepted and ignored — the check is decorative"
grep -qi 'ADDRESS MISMATCH' "$FAKE/out7" && P "…named as an address mismatch" || F "the mismatch is not identified"
rc="$(RRC_STATE=disabled FAKE_SERIAL=SER123 SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" \
      HSM_DERIVE_ADDRESS_PY=/nonexistent bash "$CC" --expect-serial SER123 --expect-devaut-sha AABBCC \
      --expect-address akash1cardkey >"$FAKE/out8" 2>&1; echo $?)"
[ "$rc" != 0 ] && P "no deriver present -> the address CANNOT BE EVALUATED -> failure" \
               || F "the address check was silently skipped when the deriver was missing"

hdr "A card the staging registry still lists as wipeable is not commissionable"
# Future-production units are registered `staging` so the drills that qualify them can run, which
# means automation may erase them on schedule. Commissioning is where that has to stop: a
# production key on a card the fleet may wipe is not custody. The way out of the wipe list is
# enforced here rather than remembered (regalia#481).
REG_STAGING="$FAKE/reg-staging.json"
cat > "$REG_STAGING" <<'JSON'
{"schema": "regalia.staging-hardware/v1", "environment": "staging", "devices": [
  {"id": "n-a", "role": "staging", "kind": "nitrokey-hsm2", "token_serial": "SER123",
   "devaut_chr": "DEVCHR001", "devaut_sha256": "aabbcc"}
]}
JSON
REG_ABSENT="$FAKE/reg-absent.json"
cat > "$REG_ABSENT" <<'JSON'
{"schema": "regalia.staging-hardware/v1", "environment": "staging", "devices": [
  {"id": "p-a", "role": "staging", "kind": "pico-hsm2", "token_serial": "ESPAAAAAAAA",
   "board_id": "C858BA452202E14A", "debug_probe": {"kind": "raspberry-pi-debug-probe", "serial": "E6647C74038B9430"}}
]}
JSON
cc_reg(){ RRC_STATE=disabled FAKE_SERIAL=SER123 SCSH_HOME="$FAKE/scsh" HSM_DEVAUT_JS="$FAKE/devaut.js" \
  HSM_STAGING_REGISTRY_FILE="$1" bash "$CC" --expect-serial SER123 --expect-devaut-sha AABBCC \
  >"$FAKE/out9" 2>&1; echo $?; }

rc="$(cc_reg "$REG_STAGING")"
[ "$rc" != 0 ] && P "a card still listed staging is REFUSED at commissioning" \
               || F "a card automation may wipe was commissioned"
grep -qi 'STILL LISTED staging' "$FAKE/out9" && P "…and the refusal names the registry entry" || F "the refusal is not named"
rc="$(cc_reg "$REG_ABSENT")"
[ "$rc" = 0 ] && P "a card the registry does not list passes the interlock" \
              || { F "a card outside the registry was refused"; sed 's/^/      /' "$FAKE/out9"; }
rc="$(cc_reg /nonexistent/registry.json)"
[ "$rc" != 0 ] \
  && P "no readable registry is a REFUSAL — the card cannot show it left the wipe list" \
  || F "a missing registry let the card be commissioned without proving it is off the wipe list"
grep -qi 'CANNOT BE EVALUATED' "$FAKE/out9" \
  && P "…and says so, rather than implying the card is clear" \
  || F "a missing registry was reported as something other than unevaluable"

hdr "B3 at the rack: found and could-not-scan are DIFFERENT failures"
# Collapsing them sends an operator hunting for a share that does not exist while the real fault —
# a scan that never ran — goes unnamed. Both must still refuse the card.
rc="$(FAKE_DKEK=found run_cc disabled)"
[ "$rc" != 0 ] && P "DKEK material on the host refuses the card" || F "a host carrying a DKEK was commissioned"
grep -q 'DKEK MATERIAL PRESENT' "$FAKE/out" && P "…named as material present" || F "the DKEK failure is not named"
rc="$(FAKE_DKEK=unknown run_cc disabled)"
[ "$rc" != 0 ] && P "a DKEK scan that could not complete refuses the card" \
               || F "an unscannable host was commissioned — cannot-evaluate was treated as clean"
grep -q 'CANNOT BE EVALUATED' "$FAKE/out" \
  && P "…and is reported as unevaluable, not as material found" \
  || F "could-not-scan is reported as if a DKEK share had been found"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
