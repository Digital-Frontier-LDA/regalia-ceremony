#!/usr/bin/env bash
# test-hsm-staging-ci.sh — the staging HSM battery must FAIL CLOSED. No hardware needed.
#
# WHAT IS UNDER TEST. hsm-staging-ci.sh is the scheduler's entry point to every hardware proof
# this project has: the e2e phases, the scenarios, the drills, the soak. Once it runs unattended
# on the DL360, NOBODY READS ITS OUTPUT unless it goes red. So the property that matters is not
# "does it run the suites" — it is "can it ever report green without having run them".
#
# That is the exact defect this repo keeps shipping: a CI gate that skipped every staging deploy
# for four days, a coverage suite that returned rc=0 while asserting nothing, a two-device test
# that reported a clean skip for everyone but its author. A battery that silently degrades to
# nothing is worse than no battery, because it manufactures confidence.
#
# HOW IT IS TESTED WITHOUT A CARD. A complete fake repo tree is built in a tmpdir — the real
# orchestrator is SYMLINKED into it (it resolves its own paths from $0, so it finds the fakes)
# and every child it shells out to is a stub that records having been called. `pkcs11-tool`,
# `sc-hsm-tool` and `opensc-tool` are stubbed on PATH and driven by environment variables, so
# every card state — absent, wrong serial, near-locked, vulnerable RRC, wrong ATR — is reachable.
# The orchestrator itself is never modified for testability; it runs exactly as CI runs it.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REAL_CI="$HERE/../../scripts/hsm-staging-ci.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$REAL_CI" ] || { echo "  (skipping: hsm-staging-ci.sh not found at $REAL_CI)"; exit 0; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
FAKE="$T/bin"; mkdir -p "$FAKE"
TRIP="$T/tripwire"                     # every stub child appends the fact that it ran
SCRIPTS="$T/qubes/scripts"
EMUT="$T/qubes/emulator/tests"
TOOLS="$T/tools"
mkdir -p "$SCRIPTS" "$EMUT" "$TOOLS" "$T/qubes/emulator"
ln -s "$HERE/../../../../tools/hsm-bench-lock.sh" "$TOOLS/hsm-bench-lock.sh"

# ---------------------------------------------------------------------------- the fake tree
ln -s "$REAL_CI" "$SCRIPTS/hsm-staging-ci.sh"

# The transcript redactor, symlinked like the orchestrator itself: the orchestrator reaches it
# through its own $REPO resolution, so the fake tree must carry the REAL filter for the
# redaction cases below to exercise anything.
REAL_REDACT="$(cd "$(dirname "$REAL_CI")/../../.." && pwd)/tools/hsm-transcript-redact.sh"
[ -r "$REAL_REDACT" ] && ln -s "$REAL_REDACT" "$TOOLS/hsm-transcript-redact.sh"

# Stub children. Each records the call and honours CHILD_RC so a failing suite can be simulated.
# FAKE_LEAK=1 makes them print the credential values from their environment — the synthesized
# shape of "the day a tool starts echoing what it was handed" (#185), because no real tool does
# today (measured 2026-09-05) and a redaction test that waits for a real echo tests nothing.
for child in "$SCRIPTS/hsm-staging-e2e.sh" "$SCRIPTS/hsm-recovery-drill.sh" \
             "$SCRIPTS/hsm-fleet-drill.sh" "$TOOLS/hsm-scenarios.sh" \
             "$TOOLS/hsm-cycle-test.sh" "$T/qubes/emulator/run-tests.sh"; do
  cat > "$child" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TRIP"
printf '  0 passed, 0 failed, 0 skipped (stub)\n'
[ "${FAKE_LEAK:-0}" = 1 ] && printf 'child env: HSM_USER_PIN=%s HSM_CI_REDACT_EXTRA=%s\n' \
  "${HSM_USER_PIN:-<unset>}" "${HSM_CI_REDACT_EXTRA:-<unset>}"
exit "${CHILD_RC:-0}"
STUB
  chmod +x "$child"
done

# The device-identity path: scsh scriptrunner + the offline CVC verifier.
mkdir -p "$T/scsh"
cat > "$T/scsh/scriptrunner" <<'STUB'
#!/usr/bin/env bash
printf 'DEVAUT_CHR=%s\n' "${FAKE_CHR:-ESPICOHSM0001}"
printf 'DEVAUT_CAR=%s\n' "${FAKE_CAR:-ESPICOHSM0001}"
printf 'DEVAUT_SHA256=%s\n' "${FAKE_SHA:-aabbcc}"
printf 'DEVAUT_BYTES=940\n'
printf 'DEVAUT_HEX=%s\n' "${FAKE_HEX:-7f2181}"
STUB
cat > "$SCRIPTS/cvc-devaut-verify.py" <<'STUB'
#!/usr/bin/env python3
import os, sys
print("CVC_CHR=" + os.environ.get("FAKE_CHR", "ESPICOHSM0001"))
print("CVC_CAR=" + os.environ.get("FAKE_CAR", "ESPICOHSM0001"))
print("CVC_CHAIN=" + os.environ.get("FAKE_CHAIN", "unverified"))
sys.exit(int(os.environ.get("FAKE_CVC_RC", "0")))
STUB
cat > "$SCRIPTS/verify-hsm-control.py" <<'STUB'
#!/usr/bin/env python3
import os, sys
sys.exit(int(os.environ.get("FAKE_VERIFY_RC", "0")))
STUB
: > "$SCRIPTS/hsm-devaut-id.js"
chmod +x "$T/scsh/scriptrunner" "$SCRIPTS/cvc-devaut-verify.py" "$SCRIPTS/verify-hsm-control.py"

# Host unit suites: one trivially-passing stub per suite the orchestrator expects, plus the CVC one.
for s in test_sle4442_model test_schsm_crypto test_derive_address test_slip39_mint \
         test_metal_stamp test_recovery_procedure test_payload_qr test_entropy_mix \
         test_seed_to_pkcs12 test_verify_hsm_control test_recovery_card test_cvc_devaut_verify; do
  printf '#!/usr/bin/env python3\nimport os,sys,time\ntime.sleep(float(os.environ.get("FAKE_SUITE_SLEEP","0")))\nprint("Ran 1 test")\nsys.exit(int(os.environ.get("FAKE_SUITE_RC","0")))\n' \
    > "$EMUT/$s.py"
done

# ---------------------------------------------------------------------------- card stubs on PATH
cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
# FAKE_LEAK=1 echoes the PIN from the ARGUMENT LIST, not the environment: that is the actual
# shape of the future bug (a tool printing what it was handed), and unlike an env echo it fires
# on the DEFAULT path too, where the effective PIN is the published default and nothing in the
# environment names it (found on #211).
[ "${FAKE_LEAK:-0}" = 1 ] && for a in "$@"; do
  [ "${prev:-}" = "--pin" ] && printf 'error: argv --pin %s (simulating a tool that starts echoing its arguments)\n' "$a" >&2
  prev="$a"
done
case "$*" in
  *--list-slots*)
    # FAKE_APPEAR_AFTER=N makes the card absent for the first N probes and present afterwards,
    # reproducing the transient USB re-enumeration measured on the real Pico. The counter lives
    # in a file because each probe is a fresh process.
    if [ -n "${FAKE_APPEAR_AFTER:-}" ]; then
      n=$(( $(cat "${FAKE_PROBE_COUNT:-/dev/null}" 2>/dev/null || echo 0) + 1 ))
      [ -n "${FAKE_PROBE_COUNT:-}" ] && echo "$n" > "$FAKE_PROBE_COUNT"
      [ "$n" -le "$FAKE_APPEAR_AFTER" ] && { echo "No slots."; exit 1; }
    fi
    [ "${FAKE_PRESENT:-1}" = 1 ] || { echo "No slots."; exit 1; }
    # ${FAKE_SERIAL-…}, not ${FAKE_SERIAL:-…}: an explicitly EMPTY serial is a real state a real
    # Pico was observed in, and the colon form would paper over it with the default.
    printf 'Slot 0 (0x0): Reader\n  token label        : staging\n  serial num         : %s\n' "${FAKE_SERIAL-ESP2202E14A}";;
  *--list-token-slots*)
    # FAKE_SLOTS is "id serial" entries separated by ';'. Empty by default, so the slot-id resolver
    # finds nothing and the battery keeps its pre-two-card behaviour.
    printf '%s\n' "${FAKE_SLOTS:-}" | tr ';' '\n' | while IFS= read -r l; do
      [ -n "$l" ] || continue
      printf 'Slot 0 (0x%x): Reader\n  token label        : staging\n  serial num         : %s\n' "${l%% *}" "${l#* }"
    done;;
  *--sign*)
    [ "${FAKE_SIGN_RC:-0}" = 0 ] || { echo "CKR_GENERAL_ERROR"; exit 1; }
    for a in "$@"; do [ "$prev" = "--output-file" ] && printf 'sig' > "$a"; prev="$a"; done;;
esac
exit 0
STUB
cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
[ "${FAKE_LEAK:-0}" = 1 ] && printf 'so-pin guard value: %s\n' "${HSM_SO_PIN:-<no-so-pin>}"
[ "${FAKE_SCT_OK:-1}" = 1 ] || exit 1
printf 'Version              : 4.0\n'
printf 'Config options       :\n'
[ "${FAKE_RRC:-off}" = on ] && printf '  User PIN reset with SO-PIN enabled\n'
# ${FAKE_TRIES-3}, NOT ${FAKE_TRIES:-3}: an explicitly EMPTY FAKE_TRIES means "the card printed
# no counter at all", which is the case under test. The colon form would substitute the default
# and quietly turn the unreadable-counter test into another healthy-card test.
[ -n "${FAKE_TRIES-3}" ] && printf 'User PIN tries left  : %s\n' "${FAKE_TRIES-3}"
exit 0
STUB
cat > "$FAKE/opensc-tool" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *--atr*) printf '%s\n' "${FAKE_ATR:-3b:de:18:ff}";;
  *--list-readers*)
    # FAKE_READER_NAMES is "idx=name" entries separated by ';', with '_' standing for a space so one
    # variable can carry names containing blanks. EMPTY BY DEFAULT, which is exactly what every
    # assertion written before two-card support assumed: no listing at all.
    [ -n "${FAKE_READER_NAMES:-}" ] || exit 0
    printf '# Detected readers (pcsc)\n'
    printf 'Nr.  Card  Features  Name\n'
    printf '%s\n' "$FAKE_READER_NAMES" | tr ';' '\n' | while IFS= read -r pair; do
      [ -n "$pair" ] || continue
      printf '%-3s  %-4s  %-8s  %s\n' "${pair%%=*}" "Yes" "" "$(printf '%s' "${pair#*=}" | tr '_' ' ')"
    done;;
esac
exit 0
STUB
# opensc-explorer is how the battery now reads EF 2F02 (scsh cannot address a specific card when
# two are attached — its reader matching is prefix-based and one name is a prefix of the other).
# It MUST be stubbed: without a stub the suite silently ran the real binary against the real card
# on the bench, and "hw_devaut fails with no scsh" passed for the wrong reason — it had quietly
# become a hardware test on a host that happened to have a card plugged in.
# Writes a blob only when FAKE_DEVAUT_HEX is set; otherwise it produces nothing, which is the
# "identity cannot be read" condition the fail-closed assertions depend on.
cat > "$FAKE/pkcs15-tool" <<'STUB'
#!/usr/bin/env bash
# FAKE_SERIAL_<idx> is the token serial at that reader. Unset means the read produced nothing, which
# every resolver here must treat as "cannot prove", never as "not the protected card".
idx=""; while [ $# -gt 0 ]; do case "$1" in -r) idx="$2"; shift 2;; *) shift;; esac; done
var="FAKE_SERIAL_${idx}"; val="${!var-}"
[ -n "$val" ] || exit 0
printf 'PKCS#15 Card [Pico-HSM]:\n\tSerial number  : %s\n' "$val"
STUB
cat > "$FAKE/opensc-explorer" <<'STUB'
#!/usr/bin/env bash
out=""
while IFS= read -r line; do case "$line" in "get 2F02 "*) out="${line#get 2F02 }";; esac; done
[ -n "${FAKE_DEVAUT_HEX:-}" ] && [ -n "$out" ] && printf '%s' "$FAKE_DEVAUT_HEX" | xxd -r -p > "$out"
exit 0
STUB
chmod +x "$FAKE/pkcs11-tool" "$FAKE/sc-hsm-tool" "$FAKE/opensc-tool" "$FAKE/opensc-explorer" "$FAKE/pkcs15-tool"

# A pinned public key + a PKCS#11 module file, so the happy path has its preconditions.
printf 'DER' > "$T/expected-pub.der"
printf 'so'  > "$T/opensc-pkcs11.so"

# The orchestrator refuses to evaluate the CVC step unless `import cvc` works, which is correct
# (pycvc is a hash-pinned dependency and a missing one must not silently drop the check). This
# harness is not testing pycvc, so satisfy the import with an empty module on PYTHONPATH rather
# than making the whole suite depend on the host having the real thing installed.
mkdir -p "$T/pylib/cvc"; : > "$T/pylib/cvc/__init__.py"

CI="$SCRIPTS/hsm-staging-ci.sh"
OUT="$T/out"

# Run the orchestrator with a clean, fully-controlled environment.
#
# EVERY per-case override goes INSIDE the command substitution — `FAKE_X=y rc="$(run_ci …)"` is
# two assignments rather than a prefixed command, so the fake card state would persist into every
# later case and quietly turn the rest of the file into a test of the wrong thing.
# The battery finds its reader resolver relative to $0, and we drive it through a SYMLINK, so without
# this the resolver is never sourced and every two-card assertion below would pass vacuously against
# single-card defaults.
# FOUR levels, not three: tests -> emulator -> qubes -> ceremony -> repo root. Three lands on
# ceremony/ and the file is simply absent, so the battery falls back, the resolver is never sourced,
# and every two-card assertion passes vacuously against single-card defaults. Asserted below rather
# than trusted, because a missing path here fails silently in exactly that direction.
REAL_RS="$(cd "$HERE/../../../.." && pwd)/tools/hsm-reader-select.sh"
[ -r "$REAL_RS" ] || { echo "  (cannot find the reader resolver at $REAL_RS — two-card cases would pass vacuously)"; exit 1; }

run_ci(){ # $@ = orchestrator args; card state from FAKE_*, harness paths from TEST_*
  : > "$TRIP"
  PATH="$FAKE:$PATH" TRIP="$TRIP" HSM_READER_SELECT="$REAL_RS" \
  PYTHONPATH="$T/pylib${PYTHONPATH:+:$PYTHONPATH}" \
  HSM_PKCS11_MODULE="${TEST_P11:-$T/opensc-pkcs11.so}" \
  HSM_CI_DIR="$T/runs" \
  HSM_CI_EXPECT_PUB="${TEST_PUB:-$T/expected-pub.der}" \
  HSM_CI_EXPECT_ATR="${TEST_ATR:-}" \
  HSM_CI_SLOT_B="${TEST_SLOT_B:-}" \
  HSM_CI_PRESENCE_TRIES="${TEST_PRESENCE_TRIES:-1}" \
  SCSH_HOME="${TEST_SCSH:-$T/scsh}" \
  HSM_USER_PIN="${TEST_USER_PIN:-}" \
  HSM_SO_PIN="${TEST_SO_PIN:-}" \
  HSM_CI_REDACT_EXTRA="${TEST_REDACT_EXTRA:-}" \
  HSM_STAGING_DIR="${TEST_STAGING:-}" \
  HSM_STAGING_REGISTRY_AUTOLOAD=0 \
  HSM_BENCH_LOCK_PATH="$T/bench.lock" \
  HSM_CI_YUBIKEY_SERIAL="${TEST_YK_SERIAL:-}" \
  REGALIA_PIV_PIN="${TEST_PIV_PIN:-}" \
  FAKE_GO_MODE="${FAKE_GO_MODE:-pass}" \
  HSM_CI_KMS_DIR="${TEST_KMS_DIR:-$T/kms}" \
  HOME="$T" \
    bash "$CI" "$@" > "$OUT" 2>&1
  echo $?
}

# status of one step, read from the summary table the orchestrator prints
st(){ grep -aE "^  $1 " "$OUT" | tail -1 | awk '{print $2}'; }
ran(){ grep -qa "^$1" "$TRIP"; }

export FAKE_PRESENT=1 FAKE_SERIAL=ESP2202E14A FAKE_SCT_OK=1 FAKE_RRC=off FAKE_TRIES=3

# =================================================================================================
hdr "ARGUMENT CONTRACT — an ambiguous invocation must not silently pick a tier"
rc="$(run_ci)"
[ "$rc" = 2 ] && P "no --tier is an operator error (rc=2), not a default run" \
              || F "running with no tier returned $rc — a defaulted tier is a surprise wipe waiting to happen"
rc="$(run_ci --tier notatier)"
[ "$rc" = 2 ] && P "an unknown tier is refused" || F "an unknown tier returned $rc"
rc="$(run_ci --list)"
[ "$rc" = 0 ] && grep -qa 'YES' "$OUT" && P "--list works and marks the destructive steps" \
              || F "--list did not print the battery with its destructive column"

hdr "NO-HARDWARE MODE IS FOR THE GATE ONLY"
# The dangerous combination: a destructive tier with the hardware steps skipped would print a
# green 'nightly' that never touched a device — a staging attestation of nothing.
rc="$(run_ci --tier nightly --allow-no-hardware)"
[ "$rc" = 2 ] && P "--tier nightly --allow-no-hardware is REFUSED outright" \
              || F "a destructive tier accepted --allow-no-hardware (rc=$rc) — it can now report green without hardware"
grep -qa 'REFUSING' "$OUT" && P "…and says why" || F "the refusal is not explained"

rc="$(run_ci --tier gate --allow-no-hardware)"
[ "$rc" = 0 ] && P "the gate tier runs host-only and passes when the host suites pass" \
              || F "gate --allow-no-hardware returned $rc with all stubs green"
[ "$(st hw_present)" = SKIP ] && P "hardware steps are SKIPPED, not silently passed" \
                             || F "hw_present reported $(st hw_present) with no hardware"
grep -qa 'NO-HARDWARE RUN' "$OUT" \
  && P "…and the summary refuses to let the run be read as an attestation" \
  || F "a no-hardware run is not labelled as such in the summary"

# =================================================================================================
hdr "CANNOT-EVALUATE IS A FAILURE, NOT A SKIP"
rc="$(FAKE_PRESENT=0 run_ci --tier gate)"
[ "$rc" = 1 ] && [ "$(st hw_present)" = FAIL ] \
  && P "no card on the bus FAILS the gate (the single most likely CI condition)" \
  || F "an absent card produced rc=$rc / hw_present=$(st hw_present) — a battery with no device must never be green"

rc="$(FAKE_SCT_OK=0 run_ci --tier gate)"
[ "$(st hw_rrc)" = FAIL ] && P "an unreadable card FAILS the RRC check rather than skipping it" \
                          || F "hw_rrc reported $(st hw_rrc) when sc-hsm-tool could not read the card"

rc="$(FAKE_TRIES='' run_ci --tier gate)"
[ "$(st hw_pin_health)" = FAIL ] && P "an UNREADABLE retry counter is a failure" \
                                 || F "hw_pin_health reported $(st hw_pin_health) with no counter in the readout"

rc="$(TEST_SCSH=/nonexistent run_ci --tier gate)"
[ "$(st hw_devaut)" = FAIL ] \
  && P "no Smart Card Shell -> device identity CANNOT BE EVALUATED -> failure" \
  || F "hw_devaut reported $(st hw_devaut) with no scsh — identity was silently skipped"

rc="$(TEST_PUB="$T/no-such-key.der" run_ci --tier gate)"
[ "$(st hw_sign)" = FAIL ] \
  && P "no pinned public key -> the gate cannot prove key retention -> failure" \
  || F "hw_sign reported $(st hw_sign) with nothing pinned — it would never notice a lost key"

# =================================================================================================
hdr "A TRANSIENT USB DROP IS TOLERATED — ONCE, BOUNDED, AND REPORTED"
# MEASURED twice on 2026-08-06: the Pico leaves the bus and re-enumerates a few seconds later,
# and a gate run that probed during the gap failed a perfectly healthy card. Retrying is right;
# retrying SILENTLY, or forever, is not. So: it must come back green, the settle time must appear
# in the evidence, and exhausting the window must still be a hard failure.
: > "$T/probes"
rc="$(FAKE_APPEAR_AFTER=2 FAKE_PROBE_COUNT="$T/probes" TEST_PRESENCE_TRIES=6 run_ci --tier gate)"
[ "$(st hw_present)" = PASS ] \
  && P "a card that re-enumerates on the 3rd probe is picked up, not failed" \
  || F "hw_present reported $(st hw_present) for a card that came back within the window"
grep -qa 're-enumeration' "$OUT" \
  && P "…and the settle time is REPORTED, so a degrading card shows as a trend" \
  || F "the retry was silent — a card getting slower to enumerate would never be noticed"

: > "$T/probes"
rc="$(FAKE_APPEAR_AFTER=99 FAKE_PROBE_COUNT="$T/probes" TEST_PRESENCE_TRIES=2 run_ci --tier gate)"
[ "$rc" = 1 ] && [ "$(st hw_present)" = FAIL ] \
  && P "a card that never returns still FAILS — the retry window is bounded, not a loophole" \
  || F "an absent card survived the retry window with rc=$rc / hw_present=$(st hw_present)"

: > "$T/probes"
rc="$(FAKE_APPEAR_AFTER=99 FAKE_PROBE_COUNT="$T/probes" TEST_PRESENCE_TRIES=3 run_ci --tier nightly)"
[ "$(st e2e_phases)" = FAIL ] && ! ran hsm-staging-e2e.sh \
  && P "…and nothing destructive runs against a card that never came back" \
  || F "the destructive battery ran after the presence window was exhausted"

hdr "THE CHECKS ACTUALLY BITE"
rc="$(FAKE_RRC=on run_ci --tier gate)"
[ "$(st hw_rrc)" = FAIL ] && P "the vulnerable-RRC tell is caught (D3 posture is enforceable)" \
                          || F "a card advertising 'User PIN reset with SO-PIN enabled' passed"

rc="$(FAKE_TRIES=1 run_ci --tier gate)"
[ "$(st hw_pin_health)" = FAIL ] && P "a near-locked card (1 try left) is stopped before anything writes to it" \
                                 || F "hw_pin_health passed with 1 retry left — the next wrong PIN bricks the card"

rc="$(FAKE_SERIAL=SOMEOTHERCARD run_ci --tier gate)"
[ "$(st hw_serial)" = FAIL ] && P "a different card is refused on the serial pin" \
                             || F "a card that is not the staging device passed the pin"

rc="$(TEST_ATR=deadbeef run_ci --tier gate)"
[ "$(st hw_atr)" = FAIL ] && P "a pinned ATR mismatch is refused (reader index is not evidence; the ATR is)" \
                          || F "hw_atr reported $(st hw_atr) against a pinned ATR that did not match"

rc="$(FAKE_SIGN_RC=1 run_ci --tier gate)"
[ "$(st hw_sign)" = FAIL ] && P "a card that cannot sign fails the gate" \
                           || F "hw_sign passed while signing failed"

rc="$(FAKE_VERIFY_RC=1 run_ci --tier gate)"
[ "$(st hw_sign)" = FAIL ] \
  && P "a signature that does NOT verify against the pinned key fails (the substitution case)" \
  || F "hw_sign passed on a signature that failed verification"

rc="$(FAKE_CVC_RC=1 run_ci --tier gate)"
[ "$(st hw_devaut)" = FAIL ] && P "a C.DevAut that fails offline verification fails the gate" \
                             || F "hw_devaut passed while the offline CVC check went red"

# =================================================================================================
hdr "THE DESTRUCTIVE GATE — nothing writes to a card that has not proven what it is"
rc="$(FAKE_SERIAL=SOMEOTHERCARD run_ci --tier nightly)"
[ "$rc" = 1 ] || F "a nightly run against the wrong card returned $rc"
blocked=1
for s in e2e_phases e2e_scenarios e2e_recovery; do
  [ "$(st $s)" = FAIL ] || { F "$s reported $(st $s) on an unproven card — a blocked destructive step must be a FAILURE"; blocked=0; }
done
[ "$blocked" = 1 ] && P "every destructive step is FAILED (not skipped) when the card is not the pinned device"
if ran hsm-staging-e2e.sh || ran hsm-scenarios.sh || ran hsm-recovery-drill.sh; then
  F "a destructive child RAN against a card that failed the serial pin: $(cat "$TRIP")"
else
  P "…and NOT ONE of them was actually executed against the wrong card"
fi

rc="$(FAKE_TRIES=1 run_ci --tier nightly)"
[ "$(st e2e_phases)" = FAIL ] && ! ran hsm-staging-e2e.sh \
  && P "a near-locked card also blocks the destructive battery" \
  || F "the destructive battery ran against a card with 1 PIN try left"

hdr "…but an unrecognised card is still INTERROGATED, because the findings still count"
# Blocking the read-only checks on the serial pin would be strictly worse than useless: a card
# that is the wrong serial AND advertises the vulnerable RRC config AND has one PIN try left is
# an actionable report, whereas four repetitions of "blocked, could not evaluate" is noise. This
# came straight off real hardware — a Pico whose serial read back empty and which was sitting in
# the RRC-enabled configuration, where the first version of this battery reported nothing useful.
rc="$(FAKE_SERIAL='' FAKE_RRC=on FAKE_TRIES=1 run_ci --tier gate)"
[ "$(st hw_serial)" = FAIL ] && P "an unreadable serial fails the pin" || F "hw_serial=$(st hw_serial) with no serial"
[ "$(st hw_rrc)" = FAIL ] \
  && P "…and the RRC posture is STILL evaluated and still goes red on the unrecognised card" \
  || F "hw_rrc reported $(st hw_rrc) — the read-only finding was lost behind the serial mismatch"
[ "$(st hw_pin_health)" = FAIL ] \
  && P "…and the PIN counter is STILL read and still goes red" \
  || F "hw_pin_health reported $(st hw_pin_health) — another read-only finding lost"
[ "$(st hw_devaut)" != FAIL ] \
  && P "…and the device identity is STILL read (that is how you learn WHICH card you have)" \
  || F "hw_devaut was blocked by the serial mismatch — identity is exactly what you want here"
grep -qa 'refusing to spend a PIN attempt' "$OUT" \
  && P "but hw_sign refuses to spend a PIN attempt on an unrecognised card's retry counter" \
  || F "hw_sign was not withheld from a card that had not proven its identity"

hdr "…and when the card DOES prove itself, the suites really run"
rc="$(run_ci --tier nightly)"
allran=1
for c in hsm-staging-e2e.sh hsm-scenarios.sh hsm-recovery-drill.sh; do
  ran "$c" || { F "$c was NOT executed on a fully-green nightly run"; allran=0; }
done
[ "$allran" = 1 ] && P "e2e phases, scenarios and the recovery drill all executed"
# Asserted per-step rather than on the process exit code: unit_emulator's outcome depends on the
# HOST (Linux + root or passwordless sudo), so a bare `rc = 0` here would pass on a developer's
# Mac and fail on a Linux runner without sudo — a test that means different things on different
# machines. The exit-code contract itself is pinned by the gate-tier cases above.
green=1
for s in unit_cvc hw_present hw_serial hw_atr hw_rrc hw_pin_health hw_devaut hw_sign \
         e2e_phases e2e_scenarios e2e_recovery; do
  [ "$(st $s)" = PASS ] || { F "$s reported $(st $s) on an otherwise-green nightly"; green=0; }
done
[ "$green" = 1 ] && P "every card-facing step passes when the card is healthy"
case "$(uname -s):$(st unit_emulator)" in
  Linux:PASS|Linux:FAIL) P "unit_emulator was evaluated on Linux (result: $(st unit_emulator))";;
  Linux:*) F "unit_emulator reported '$(st unit_emulator)' on Linux — the emulator suite applies here and must not be skipped";;
  *:SKIP)  P "unit_emulator is a reasoned skip off Linux (the suite boots pcscd/vpcd/cups)";;
  *)       F "unit_emulator reported '$(st unit_emulator)' on $(uname -s) — expected a reasoned SKIP";;
esac
[ "$(st e2e_fleet)" = SKIP ] \
  && P "the two-device drill is a REASONED skip with no second card, not a fake pass" \
  || F "e2e_fleet reported $(st e2e_fleet) with no HSM_CI_SLOT_B"
grep -qa 'A3/A5/A6/A7 stay MODELLED' "$OUT" && P "…and names exactly which requirements stay unproven" \
  || F "the fleet skip does not say what it leaves unproven"

hdr "The soak tier adds the reliability cycles, and only the soak tier"
rc="$(run_ci --tier nightly)"
ran hsm-cycle-test.sh && F "the soak ran in the nightly tier" || P "hsm-cycle-test.sh does NOT run in --tier nightly"
rc="$(run_ci --tier soak --soak-cycles 3)"
ran hsm-cycle-test.sh && P "hsm-cycle-test.sh runs in --tier soak" || F "the soak tier did not run the cycle test"
grep -qa 'cycles 3' "$TRIP" && P "…with the requested cycle count passed through" \
  || F "--soak-cycles was not forwarded to the cycle test: $(cat "$TRIP")"

# =================================================================================================
hdr "A CHILD THAT FAILS, AND A CHILD THAT VANISHES"
rc="$(CHILD_RC=1 run_ci --tier nightly)"
[ "$rc" = 1 ] && [ "$(st e2e_phases)" = FAIL ] \
  && P "a child suite exiting non-zero fails its step and the whole run" \
  || F "a failing child produced rc=$rc / e2e_phases=$(st e2e_phases)"

mv "$SCRIPTS/hsm-recovery-drill.sh" "$T/parked"
rc="$(run_ci --tier nightly)"
[ "$(st e2e_recovery)" = FAIL ] \
  && P "a MISSING child script is a failure — a suite that moved must not vanish from the battery" \
  || F "e2e_recovery reported $(st e2e_recovery) when its script did not exist"
mv "$T/parked" "$SCRIPTS/hsm-recovery-drill.sh"

rm "$EMUT/test_entropy_mix.py"
rc="$(run_ci --tier gate)"
grep -qa 'unit_models.test_entropy_mix.*FAIL' "$OUT" \
  && P "a host unit suite that disappeared is a failure, not a shorter run" \
  || F "a deleted unit suite was silently dropped from the battery"
printf '#!/usr/bin/env python3\nimport os,sys\nprint("Ran 1 test")\nsys.exit(int(os.environ.get("FAKE_SUITE_RC","0")))\n' \
  > "$EMUT/test_entropy_mix.py"

rc="$(FAKE_SUITE_RC=1 run_ci --tier gate)"
[ "$rc" = 1 ] && P "a failing host unit suite fails the run" || F "a failing unit suite returned $rc"

# =================================================================================================
hdr "MACHINE-READABLE OUTPUT — the scheduler must not have to parse prose"
rc="$(FAKE_PRESENT=0 run_ci --tier gate --junit "$T/j.xml")"
if [ -f "$T/j.xml" ]; then
  P "a JUnit report is written"
  if python3 - "$T/j.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
s = ET.parse(sys.argv[1]).getroot()[0]
cases = s.findall("testcase")
fails = s.findall(".//failure")
assert cases, "no testcases"
assert fails, "a run with an absent card produced no <failure> element"
assert int(s.attrib["failures"]) == len(fails), "the failures attribute disagrees with the elements"
assert any("hw_present" in c.attrib["name"] for c in cases), "hw_present is missing from the report"
PY
  then P "…it is well-formed XML whose counts match its elements, and the absent card is a <failure>"
  else F "the JUnit report is malformed or does not report the failure"; fi
else
  F "no JUnit report was written"
fi

# The report must survive cancellation. GitHub Actions cancels a job with SIGTERM, and the soak
# tier runs long enough for that to be routine — a run that found something must not come back
# indistinguishable from a run that found nothing. The suites are slowed down deliberately so the
# kill lands MID-BATTERY; without the sleep the stubs finish first and the case proves nothing.
# `bash` is backgrounded directly rather than wrapped in ( ), or the signal would hit the
# subshell and never reach the orchestrator.
PATH="$FAKE:$PATH" TRIP="$TRIP" PYTHONPATH="$T/pylib" HSM_PKCS11_MODULE="$T/opensc-pkcs11.so" \
HSM_STAGING_REGISTRY_AUTOLOAD=0 \
HSM_CI_DIR="$T/runs" HSM_CI_EXPECT_PUB="$T/expected-pub.der" SCSH_HOME="$T/scsh" HOME="$T" \
HSM_BENCH_LOCK_PATH="$T/bench-sigterm.lock" \
FAKE_SUITE_SLEEP=3 \
  bash "$CI" --tier gate --junit "$T/j2.xml" > "$T/killed.out" 2>&1 &
kpid=$!
sleep 4; kill -TERM "$kpid" 2>/dev/null; wait "$kpid" 2>/dev/null; krc=$?
if [ -f "$T/j2.xml" ]; then
  P "a SIGTERM'd run still emits its JUnit report (partial results beat no results)"
  python3 -c "import sys,xml.etree.ElementTree as ET; ET.parse('$T/j2.xml')" 2>/dev/null \
    && P "…and the partial report is still well-formed XML" \
    || F "the report written on SIGTERM is malformed — a CI parser would reject it"
  [ "$krc" = 143 ] && P "…and the run exits 143, so the cancellation is not mistaken for a pass" \
                   || F "a SIGTERM'd run exited $krc — a cancelled battery must never look green"
else
  F "SIGTERM produced no report at all — a cancelled battery would be indistinguishable from one that never found anything"
fi

# =================================================================================================
hdr "THE UPLOADED ARTIFACT CANNOT CARRY A CREDENTIAL — redaction at write time (#185)"
# The transcript, every per-step log and the JUnit report ship as a 90-day artifact. GitHub masks
# `secrets.*` in the JOB LOG only; nothing masks what the job writes to disk. No tool echoes its
# arguments today (measured 2026-09-05), so waiting for a real echo would test nothing — FAKE_LEAK=1
# makes the stubs print the LIVE credential values from their environment, which is byte-for-byte
# the day a real tool starts echoing argv. The values are generated at runtime from /dev/urandom:
# never a repo literal (nothing for the secret scanner to reason about), and never a string the
# filter could have baked in.
latest_run_dir(){ ls -td "$T/runs"/*/ 2>/dev/null | head -1; }

LEAKPIN="ci$(od -An -N10 -tx1 /dev/urandom | tr -d ' \n')"
LEAKEX="dk$(od -An -N10 -tx1 /dev/urandom | tr -d ' \n')"

# -- a failing pkcs11-tool exposes every surface at once -----------------------------------------
# A failing sign is the densest case in the battery: the tool's output lands in hw_sign.log
# (uploaded), its first error line is quoted as the step's 'why' (printed to the console AND the
# transcript through the tee, recorded in results.psv, and emitted into the JUnit report). If the
# PIN can survive THAT run, it can survive any of them; if all four surfaces come out clean, the
# whole write-time chain is proven on the live path.
rc="$(TEST_USER_PIN="$LEAKPIN" FAKE_LEAK=1 FAKE_SIGN_RC=1 run_ci --tier gate --junit "$T/j3.xml")"
rdir="$(latest_run_dir)"
if [ -f "$rdir/hw_sign.log" ]; then
  if grep -qaF "$LEAKPIN" "$rdir/hw_sign.log"; then
    F "the PIN survived into hw_sign.log inside the uploaded run dir — per-step logs bypass the tee and need their own filter"
  elif grep -qa '\[redacted:user-pin\]' "$rdir/hw_sign.log"; then
    P "a captured tool log inside the artifact is redacted at write time"
  else
    F "hw_sign.log has no PIN and no marker — the sign path's capture is not the live stream, assert on what it is"
  fi
else
  F "no hw_sign.log was copied into the run dir — the failure branch of hw_sign changed shape"
fi
if [ -f "$T/j3.xml" ]; then
  grep -qaF "$LEAKPIN" "$T/j3.xml" \
    && F "the PIN reached the JUnit report via the failure message — tool excerpts flow into junit unless filtered at the source" \
    || P "the JUnit report's failure messages carry no PIN (the 'why' is quoted from an already-redacted log)"
else
  F "no JUnit report from the sign-failure run"
fi
tlog="$rdir/transcript.log"
if [ -f "$tlog" ]; then
  if grep -qaF "$LEAKPIN" "$tlog"; then
    F "the PIN reached the UPLOADED TRANSCRIPT via the step's failure message — the tee path is unfiltered"
  elif grep -qa '\[redacted:user-pin\]' "$tlog"; then
    P "the transcript carries the marker where the 'why' was printed — the tee filter is on the live path"
  else
    F "transcript without the PIN but without the marker — nothing flowed the path under test"
  fi
  grep -qa '^  hw_present ' "$tlog" \
    && P "…and the redacted transcript still carries the step table (the filter passes bytes through, it does not judge them)" \
    || F "the redacted transcript lost the step table — the filter is dropping output"
else
  F "no transcript in the run dir — the tee itself stopped writing"
fi
if grep -qaF "$LEAKPIN" "$OUT"; then
  F "the PIN reached the CONSOLE/job-log capture — the filter is not between the battery and its output"
elif grep -qa '\[redacted:user-pin\]' "$OUT"; then
  P "…and the console/job-log stream is redacted too (GitHub retains it exactly like the artifact)"
else
  F "no PIN in the console but no marker either — redaction happened somewhere other than the live stream"
fi

# -- the DEFAULT path: no HSM_USER_PIN configured, the published default is the live PIN --------
# Found on #211 review: the export used to carry the pre-resolution variable, so an unset run —
# an unattended nightly, a bare local invocation — shipped an empty HSM_USER_PIN to the redactor
# and the EFFECTIVE PIN (the published default) went unredacted on exactly that path. Every
# earlier case sets the variable, which is why none of them could see it; this one runs with it
# unset and asserts on the argv the tool was actually handed.
rc="$(FAKE_LEAK=1 FAKE_SIGN_RC=1 run_ci --tier gate)"
rdir="$(latest_run_dir)"
if grep -qa 'error: argv --pin 648219' "$rdir/hw_sign.log" 2>/dev/null; then
  F "the DEFAULT effective PIN (the published value) reached the artifact unredacted — the export does not carry the effective value"
elif grep -qa 'error: argv --pin \[redacted:user-pin\]' "$rdir/hw_sign.log" 2>/dev/null; then
  P "with HSM_USER_PIN unset the effective default PIN is redacted too — the default path is covered"
else
  F "hw_sign.log shows neither the default PIN nor its marker — the argv echo did not reach the capture"
fi

# -- the per-step child logs, and a shape that is not a PIN ---------------------------------------
# nightly so the destructive children run; the card is the healthy pinned stub. LEAKEX stands in
# for a DKEK-share-shaped value: not a PIN, redacted because HSM_CI_REDACT_EXTRA named it.
rc="$(TEST_USER_PIN="$LEAKPIN" TEST_REDACT_EXTRA="$LEAKEX:second-token-unused" FAKE_LEAK=1 run_ci --tier nightly)"
rdir="$(latest_run_dir)"
if [ -f "$rdir/e2e_phases.log" ]; then
  if grep -qaF "$LEAKPIN" "$rdir/e2e_phases.log" || grep -qaF "$LEAKEX" "$rdir/e2e_phases.log"; then
    F "a credential reached a per-step child log inside the artifact — run_child's capture is unfiltered"
  elif grep -qa '\[redacted:user-pin\]' "$rdir/e2e_phases.log" && grep -qa '\[redacted:extra\]' "$rdir/e2e_phases.log"; then
    P "per-step child logs are redacted at write time, for PINs and for non-PIN shapes alike"
  else
    F "child log without the credential but without markers — the assertion is not on the live path"
  fi
else
  F "no e2e_phases.log in the run dir — the child-logging path changed shape"
fi

# -- the PIN FILE must not be able to move into the uploaded tree --------------------------------
# hsm-auto-import.sh writes the PIN to a file under HSM_STAGING_DIR. That directory is outside
# the uploaded glob today by configuration only — the tidy-up that moves CI working files under
# the run dir would put pin.txt in a 90-day artifact with no diff showing it. The orchestrator
# must refuse that configuration rather than trust it.
rc="$(TEST_STAGING="$T/runs/inside-uploaded-tree" run_ci --tier gate)"
if [ "$rc" = 2 ] && grep -qa 'REFUSING' "$OUT"; then
  P "a staging dir inside the uploaded run tree is refused before anything runs (rc=2)"
else
  F "HSM_STAGING_DIR inside HSM_CI_DIR was accepted (rc=$rc) — the pin file could be uploaded by a config change no diff would flag"
fi
# …and the refusal must be specific, not a blanket failure that could mean anything
rc="$(TEST_STAGING="$T/staging-outside" run_ci --tier gate --allow-no-hardware)"
[ "$rc" = 0 ] \
  && P "a staging dir outside the run tree is unaffected by the guard" \
  || F "the staging-dir guard fired on a legitimate configuration (rc=$rc)"

# =================================================================================================
# =================================================================================================
hdr "ROLE REGISTRY — a matching pin is permission from the OPERATOR; staging comes from the registry"
# The pin (HSM_CI_SERIAL) proves the card is the one the operator NAMED. Nothing used to connect
# that name to the committed registry, so pointing the pin at a card that matters satisfied the
# pin and unlocked every destructive tier. hw_serial must now also require the registry to list
# the pinned serial as staging, and a 'prod' registration must FAIL the pin and block the
# destructive gate. The registry is redirected to a fixture; the control restores the real one.
# The registry is the committed tools/hsm-staging-registry.json -- the same file the board/probe-map
# loader reads -- and it is staging-only, so a card that matters is protected by being ABSENT from it.
# The fixture is the real registry with the pinned serial removed: it still loads, so what is exercised
# is the hw_serial cross-check, not a load failure.
REG_FIXTURE="$T/registry-without-pin.json"
python3 - "$(cd "$HERE/../../../.." && pwd)/tools/hsm-staging-registry.json" "$REG_FIXTURE" <<'PYFIX'
import json, sys
data = json.load(open(sys.argv[1]))
data["devices"] = [d for d in data["devices"] if d["token_serial"] != "ESP2202E14A"]
assert data["devices"], "fixture would be empty"
json.dump(data, open(sys.argv[2], "w"))
PYFIX
rc="$(HSM_STAGING_REGISTRY_FILE="$REG_FIXTURE" run_ci --tier nightly)"
if [ "$(st hw_serial)" = FAIL ] && grep -qa 'staging registry' "$OUT"; then
  P "a pin the registry does not list fails hw_serial, and says it is the registry"
else
  F "hw_serial status $(st hw_serial) with an unregistered pin — the registry cross-check does not gate the pin"
fi
grep -qa 'blocked by the destructive gate' "$OUT" \
  && P "…and every destructive step is blocked by the gate" \
  || F "an unregistered pin still admitted destructive steps"
# THE CONTROL. Without it the two assertions above would pass for a battery whose cross-check
# refuses EVERYTHING — an instrument that cannot distinguish 'checked and staging' from 'broken'
# is fail-closed the way a removed engine is fuel-efficient.
rc="$(run_ci --tier nightly)"
[ "$(st hw_serial)" = PASS ] \
  && P "the same serial pins normally when the committed registry lists it staging" \
  || F "hw_serial failed against the committed registry (status $(st hw_serial)) — the cross-check is broken, not the registry"

# =================================================================================================
# =================================================================================================
hdr "THE CUSTODIAN ARM — a second card is offered only when it can actually be used"
# STEP 2 of hsm-recovery-drill.sh (custodian-rotation rehearsal, requirement C5's open Verify step)
# recorded UNVERIFIED on EVERY run because the battery never passed --cust. A bench with two cards can
# perform it, so that was a gap rather than a property of the bench. But the drill's custodian key
# import goes through hsm-import-key.sh, which matches reader names by PREFIX, so offering the
# prefix-named card would aim the import at the WRONG device (#398). These three cases pin the
# decision: offer it when usable, never otherwise, and never nominate the pinned card as its own
# custodian.
cust_args(){ grep -a '^hsm-recovery-drill.sh' "$TRIP" | tail -1; }

: > "$TRIP"
rc="$(FAKE_READER_NAMES='0=Pico_Key_CCID_Interface;1=Pico_Key_CCID_Interface_01' \
      FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP41D722E2 \
      FAKE_SLOTS='0 ESP2202E14A;4 ESP41D722E2' run_ci --tier nightly)"
case "$(cust_args)" in
  *--cust*4*) P "an ADDRESSABLE second card is offered as the custodian stand-in (--cust 4)" ;;
  *)          F "the drill was run without --cust although reader 1 was addressable: $(cust_args)" ;;
esac

: > "$TRIP"
rc="$(FAKE_READER_NAMES='0=Pico_Key_CCID_Interface_01;1=Pico_Key_CCID_Interface' \
      FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP41D722E2 \
      FAKE_SLOTS='0 ESP2202E14A;4 ESP41D722E2' run_ci --tier nightly)"
case "$(cust_args)" in
  *--cust*) F "a PREFIX-named second card was offered as the custodian — scsh would reach the wrong card: $(cust_args)" ;;
  *)        P "a second card whose reader name is a strict PREFIX of the other's is NOT offered" ;;
esac

: > "$TRIP"
rc="$(FAKE_READER_NAMES='0=Pico_Key_CCID_Interface;1=Pico_Key_CCID_Interface_01' \
      FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP2202E14A \
      FAKE_SLOTS='0 ESP2202E14A' run_ci --tier nightly)"
case "$(cust_args)" in
  *--cust*) F "the PINNED card was nominated as its own custodian stand-in: $(cust_args)" ;;
  *)        P "the pinned card is never nominated as its own custodian, even when addressable" ;;
esac

# The control. Without it all three assertions above pass for a battery that never passes --cust at
# all — which is precisely the behaviour being changed, so the positive case carries the whole claim.
: > "$TRIP"
rc="$(run_ci --tier nightly)"
case "$(cust_args)" in
  *--cust*) F "a single-card bench was given a custodian: $(cust_args)" ;;
  '')       F "the recovery drill did not run at all, so these cases prove nothing" ;;
  *)        P "a single-card bench still runs the drill, without --cust" ;;
esac

# =================================================================================================
# =================================================================================================
hdr "THE YUBIKEY HALF — the pinned YubiKey PIV slot is qualified read-only, and a skip is never a pass"
# A stub go stands in for `go test`: FAKE_GO_MODE picks what the physical test reports, and the stub
# records whether REGALIA_PIV_PIN reached it. The real test logs in and signs when that variable is set,
# so a PIN reaching the child would be a PIN attempt spent on every scheduled gate run.
cat > "$FAKE/go" <<'STUB'
#!/usr/bin/env bash
printf 'go %s pin=%s serial=%s\n' "$*" "${REGALIA_PIV_PIN-<unset>}" "${REGALIA_PIV_SERIAL-<unset>}" >> "$TRIP"
case "${FAKE_GO_MODE:-pass}" in
  pass) printf '=== RUN   TestPIVPhysicalReadOnlyQualification\n--- PASS: TestPIVPhysicalReadOnlyQualification (0.21s)\nPASS\n'; exit 0 ;;
  skip) printf '=== RUN   TestPIVPhysicalReadOnlyQualification\n--- SKIP: TestPIVPhysicalReadOnlyQualification (0.00s)\nPASS\n'; exit 0 ;;
  fail) printf '    piv_physical_test.go:51: 9A policy = pin "never", touch "never"; want once/never\n--- FAIL: TestPIVPhysicalReadOnlyQualification (0.2s)\nFAIL\n'; exit 1 ;;
esac
STUB
chmod +x "$FAKE/go"
mkdir -p "$T/kms" && printf 'module fake\n' > "$T/kms/go.mod"

rc="$(run_ci --tier gate)"
if [ "$(st hw_yubikey_piv)" = SKIP ] && grep -qa 'HSM_CI_YUBIKEY_SERIAL' "$OUT"; then
  P "no YubiKey pinned is a visible SKIP that names the variable to set"
else F "hw_yubikey_piv with no pin: status $(st hw_yubikey_piv)"; fi

rc="$(TEST_YK_SERIAL=25923902 TEST_PIV_PIN=123456 FAKE_GO_MODE=pass run_ci --tier gate)"
if [ "$(st hw_yubikey_piv)" = PASS ]; then
  P "a pinned YubiKey whose read-only qualification PASSES passes the step"
else F "hw_yubikey_piv with a passing qualification: status $(st hw_yubikey_piv): $(grep -a hw_yubikey_piv "$OUT" | tail -1)"; fi
if grep -qa '^go .*TestPIVPhysicalReadOnlyQualification.* pin=<unset> serial=25923902' "$TRIP"; then
  P "…and it ran against the pinned serial with NO PIN in its environment, although the job had one"
else F "the PIV child did not run as a PIN-free read-only check: $(grep -a '^go ' "$TRIP" | tail -1)"; fi

rc="$(TEST_YK_SERIAL=25923902 TEST_KMS_DIR="$T/no-module-here" run_ci --tier gate)"
if [ "$(st hw_yubikey_piv)" = FAIL ] && grep -qa 'no Go module at' "$OUT"; then
  P "a pinned YubiKey with no Go module to run is a FAIL that says so, not a silent rc=1"
else F "missing Go module: status $(st hw_yubikey_piv)"; fi

rc="$(TEST_YK_SERIAL=25923902 FAKE_GO_MODE=skip run_ci --tier gate)"
if [ "$(st hw_yubikey_piv)" = FAIL ] && grep -qa 'SKIPPED itself' "$OUT"; then
  P "a qualification that SKIPPED (exit 0) is a FAIL, not a pass — nothing was checked"
else F "a skipped PIV qualification was not a failure: status $(st hw_yubikey_piv)"; fi

rc="$(TEST_YK_SERIAL=25923902 FAKE_GO_MODE=fail run_ci --tier gate)"
if [ "$(st hw_yubikey_piv)" = FAIL ] && grep -qa 'piv_physical_test.go:51' "$OUT"; then
  P "a failing qualification FAILS the step and quotes the test's own reason"
else F "a failing PIV qualification: status $(st hw_yubikey_piv)"; fi

: > "$TRIP"
rc="$(TEST_YK_SERIAL=25923902 FAKE_GO_MODE=pass run_ci --tier gate --allow-no-hardware)"
if [ "$(st hw_yubikey_piv)" = SKIP ] && ! grep -qa '^go .*TestPIVPhysical' "$TRIP"; then
  P "--allow-no-hardware SKIPs it without running the qualification"
else F "--allow-no-hardware still ran the PIV qualification: status $(st hw_yubikey_piv)"; fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
