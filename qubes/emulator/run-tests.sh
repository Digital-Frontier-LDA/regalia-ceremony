#!/usr/bin/env bash
# run-tests.sh — run the ceremony hardware-emulator test suites NATIVELY (no Docker).
#
# This is the primary test path. It boots the emulator daemons (pcscd + vpcd + the SLE-4442
# vpicc, SoftHSM2, cups-pdf) in the CURRENT Linux session and drives every ceremony route
# + the full wizard + the go/no-go gate against them. Designed for:
#   * the Debian Qubes vault-tools box (where the real ceremony runs), or
#   * a native Debian/Ubuntu CI runner (e.g. GitHub `ubuntu-latest`, no container).
#
#   sudo qubes/emulator/run-tests.sh            # full suite (needs root)
#   qubes/emulator/run-tests.sh --install-deps  # apt-install the stack first
#   qubes/emulator/run-tests.sh --models-only   # only host-runnable suites
#
# On non-Linux (e.g. macOS) it runs ONLY the suites that need no Linux daemons (the SLE-4442
# pure model, the DKEK model, the age round-trip) and clearly skips the daemon-backed ones.
set -uo pipefail

# PREFER THE CEREMONY VENV, exactly as qubes/scripts/hsm-staging-ci.sh does.
#
# The hash-pinned Python dependencies (pycvc, mnemonic, shamir_mnemonic) are installed into a venv,
# not the system interpreter. Without this, `python3 tests/test_cvc_devaut_verify.py` died with
# `ModuleNotFoundError: No module named 'cvc'` — a bare Traceback that set rc=1 and made the whole
# host suite report FAILED, while every individual suite printed "0 failed". The real failure was
# invisible: the summary said nothing was wrong and the runner disagreed.
#
# The staging battery had this preamble and this runner did not, so the same test passed there
# (25 assertions) and crashed here.
#
# IT ALSO LOOKED IN THE WRONG PLACE. This hard-coded ~/.local/share/akash-hsm-venv while
# dev-image-bootstrap.sh creates /opt/dev-bin/regalia-venv — so on a freshly bootstrapped image the
# venv was never found, the tier silently ran against the system python3, and six suites failed
# with ModuleNotFoundError and "EVM derivation needs keccak256": failures that describe the
# environment and say nothing about the code. tools/ceremony-python.sh now knows every location and
# accepts one only after its interpreter IMPORTS the modules, and this REFUSES when none can — a
# tier that cannot evaluate must not report results.
. "$(cd "$(dirname "$0")/../.." && pwd)/tools/ceremony-python.sh"
ceremony_python_require cvc mnemonic shamir_mnemonic Crypto || exit 2

HERE="$(cd "$(dirname "$0")" && pwd)"          # …/emulator
QUBES="$(cd "$HERE/.." && pwd)"                # …/qubes
export EMU_BIN="$HERE/bin"
export CEREMONY_SCRIPTS="$QUBES/scripts"
export EMU_RUN="${EMU_RUN:-/run/vault-emu}"
export PATH="$EMU_BIN:$CEREMONY_SCRIPTS:$PATH"
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1

INSTALL=0; MODELS_ONLY=0
for a in "$@"; do case "$a" in
  --install-deps) INSTALL=1;;
  --models-only)  MODELS_ONLY=1;;
  -h|--help) sed -n '2,20p' "$0"; exit 0;;
esac; done

say(){ printf '\n\033[1;35m========== %s ==========\033[0m\n' "$1"; }
rc=0
# Every failing suite is NAMED at the end. A bare `|| rc=1` made CI end on "SOME SUITES FAILED" with
# every per-suite summary reading 0 failed, and no way to tell from the log which one went red.
FAILED_SUITES=()
suite_failed(){ rc=1; FAILED_SUITES+=("$1"); printf '  \033[31m>> SUITE FAILED: %s\033[0m\n' "$1"; }

APT_PKGS="age opensc pcscd libccid pcsc-tools yubikey-manager ssss qrencode zbar-tools \
gnupg python3 python3-pip xxd softhsm2 opensc-pkcs11 vsmartcard-vpcd cups cups-client \
printer-driver-cups-pdf xorriso python3-pyscard"

if [ "$INSTALL" = 1 ]; then
  say "installing dependencies (apt)"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y --no-install-recommends $APT_PKGS curl
    pip3 install --break-system-packages --require-hashes -r "$QUBES/requirements.txt" 2>/dev/null \
      || pip3 install --require-hashes -r "$QUBES/requirements.txt"
    # sops isn't in Debian apt — install the same hash-pinned binary the vault image uses
    # (preflight.sh checks for it). Pin matches salt/vault-tools.sls.
    if ! command -v sops >/dev/null 2>&1; then
      curl -fsSL -o /tmp/sops https://github.com/getsops/sops/releases/download/v3.13.1/sops-v3.13.1.linux.amd64
      echo "620a9d7e3352ababeca6908cea24a6e8b14ce89a448ddbd3f94f1ef3398f470a  /tmp/sops" | sha256sum -c - \
        && sudo install -m 0755 /tmp/sops /usr/local/bin/sops
    fi
  else
    echo "apt-get not found — install manually: $APT_PKGS"; exit 2
  fi
fi

# ---------------------------------------------------------------------------------------
say "host-runnable suites (no Linux daemons needed)"
python3 "$HERE/tests/test_sle4442_model.py" || suite_failed "test_sle4442_model.py"
python3 "$HERE/tests/test_schsm_crypto.py" || suite_failed "test_schsm_crypto.py"
python3 "$HERE/tests/test_derive_address.py" || suite_failed "test_derive_address.py"
python3 "$HERE/tests/test_slip39_mint.py" || suite_failed "test_slip39_mint.py"
python3 "$HERE/tests/test_metal_stamp.py" || suite_failed "test_metal_stamp.py"
python3 "$HERE/tests/test_recovery_procedure.py" || suite_failed "test_recovery_procedure.py"
python3 "$HERE/tests/test_payload_qr.py" || suite_failed "test_payload_qr.py"
python3 "$HERE/tests/test_equivalence_vector.py" || suite_failed "test_equivalence_vector.py"
python3 "$HERE/tests/test_entropy_mix.py" || suite_failed "test_entropy_mix.py"
python3 "$HERE/tests/test_seed_to_pkcs12.py" || suite_failed "test_seed_to_pkcs12.py"
python3 "$HERE/tests/test_verify_hsm_control.py" || suite_failed "test_verify_hsm_control.py"
python3 "$HERE/tests/test_recovery_card.py" || suite_failed "test_recovery_card.py"
python3 "$HERE/tests/test_cvc_devaut_verify.py" || suite_failed "test_cvc_devaut_verify.py"
python3 "$HERE/tests/test_hsm_key_attestation_verify.py" || suite_failed "test_hsm_key_attestation_verify.py"
python3 "$HERE/tests/test_hsm_devaut_read.py" || suite_failed "test_hsm_devaut_read.py"
python3 "$HERE/tests/test_hsm_time_bound.py" || suite_failed "test_hsm_time_bound.py"
python3 "$HERE/tests/test_hsm_firmware_invariants.py" || suite_failed "test_hsm_firmware_invariants.py"
python3 "$HERE/tests/test_drain_analyzer.py" || suite_failed "test_drain_analyzer.py"
python3 "$HERE/tests/test_forensic_decode.py" || suite_failed "test_forensic_decode.py"

# The forensic ring invariant is a C-level property of the recorder, so it is compiled natively
# against the SDK source rather than modelled in Python. Skipped, loudly, when the SDK is not
# checked out beside this repo — a silent skip would let the invariant rot unnoticed.
_FSDK="${PICOKEYS_SDK_DIR:-$HOME/code/pico-hsm/pico-keys-sdk}"
if [ -f "$_FSDK/src/forensic.c" ]; then
    if cc -O1 -DFORENSIC_CAUSAL -DENABLE_EMULATION -I"$_FSDK/src" \
           -o /tmp/hsm_forensic_ring "$HERE/tests/test_forensic_ring.c" \
           "$_FSDK/src/forensic.c" 2>/tmp/hsm_forensic_ring.cc.log; then
        # The BINARY's exit status is the result. Under pipefail, `ring | grep -v '^FORENSIC '` also
        # went red when the ring passed and printed only FORENSIC lines, because grep -v then selects
        # nothing and exits 1.
        _ring_out="$(/tmp/hsm_forensic_ring)"; _ring_rc=$?
        grep -v '^FORENSIC ' <<< "$_ring_out" || true
        [ "$_ring_rc" -eq 0 ] || suite_failed "test_forensic_ring.c"
    else
        echo "  FAIL: test_forensic_ring.c did not compile — see /tmp/hsm_forensic_ring.cc.log"; suite_failed "test_forensic_ring.c (compile)"
    fi
else
    echo ">> skipping the forensic ring invariant: no pico-keys-sdk at $_FSDK"
    echo "   (set PICOKEYS_SDK_DIR; this invariant is what keeps the recorder from"
    echo "    applying backpressure to the race it measures)"
fi

say "FORENSIC SNAPSHOT ordering (pristine reads must precede the destructive probe)"
"$HERE/tests/test-forensic-ordering.sh" || suite_failed "test-forensic-ordering.sh"

say "SECRET-LEAK suite (logs / files / argv / recombination — no secret ever exposed)"
"$HERE/tests/test-secret-leak.sh" || suite_failed "test-secret-leak.sh"

say "CUPS spool purge (print_share must delete completed job data, not just cancel active jobs)"
"$HERE/tests/test-cups-spool-purge.sh" || suite_failed "test-cups-spool-purge.sh"

say "CUPS print-before-purge (spool must not be wiped before the paper is actually printed)"
"$HERE/tests/test-cups-print-before-purge.sh" || suite_failed "test-cups-print-before-purge.sh"

say "CUPS print-before-purge with a failing sibling job (purge waits for drain even on failure)"
"$HERE/tests/test-cups-print-sibling-fail.sh" || suite_failed "test-cups-print-sibling-fail.sh"

say "CEREMONY ssss reconstruct-verify + input guards (no unverified / truncated backups)"
"$HERE/tests/test-ceremony-shamir-verify.sh" || suite_failed "test-ceremony-shamir-verify.sh"

say "PROVE-CEREMONY SLIP-39 proof (PROOF 3: the 4-of-6 SLIP-0039 backup really recovers)"
"$HERE/tests/test-prove-ceremony-slip39.sh" || suite_failed "test-prove-ceremony-slip39.sh"

say "CEREMONY pick_printer USB-only gate (network device-uri must not print a plaintext share over the wire)"
"$HERE/tests/test-ceremony-pick-printer-uri.sh" || suite_failed "test-ceremony-pick-printer-uri.sh"

say "PRINTER network-uri fail-closed gate (ANY non-local device-uri refused, not just a blocklist)"
"$HERE/tests/test-printer-network-uri.sh" || suite_failed "test-printer-network-uri.sh"

say "CEREMONY HSM funding-key aborts + DKEK-backup RESTORE-VERIFY (no unverifiable born-in-HSM backup)"
"$HERE/tests/test-hsm-funding-abort.sh" || suite_failed "test-hsm-funding-abort.sh"

say "CEREMONY HSM two-device clone (cross-device DKEK restore proof; never wipe a card that holds a key)"
"$HERE/tests/test-hsm-two-device-clone.sh" || suite_failed "test-hsm-two-device-clone.sh"

say "EMULATOR shim two-device model (a clone target must never answer with the primary card's key)"
"$HERE/tests/test-emu-shim-two-device.sh" || suite_failed "test-emu-shim-two-device.sh"

say "YUBIKEY two-device identity isolation (a standby ceremony must not overwrite the primary)"
"$HERE/tests/test-yubikey-two-device.sh" || suite_failed "test-yubikey-two-device.sh"

say "CEREMONY two-YubiKey registration (running the real wizard step twice preserves both identities)"
"$HERE/tests/test-ceremony-two-yubikey.sh" || suite_failed "test-ceremony-two-yubikey.sh"

say "CEREMONY Tier-0 payload step (encrypt + archival QR; never print an unproven or empty payload)"
"$HERE/tests/test-payload-step.sh" || suite_failed "test-payload-step.sh"

say "CEREMONY chip-card step (SLE-4442: never write to a near-locked card, never echo the share)"
"$HERE/tests/test-chipcard-step.sh" || suite_failed "test-chipcard-step.sh"

say "CEREMONY HSM import step (seed-derived key: the card must hold EXACTLY the seed's key)"
"$HERE/tests/test-hsm-import-step.sh" || suite_failed "test-hsm-import-step.sh"

say "HSM IMPORT DRILL end-to-end (the one-shot hardware proof; every branch before the device arrives)"
"$HERE/tests/test-hsm-import-drill.sh" || suite_failed "test-hsm-import-drill.sh"

say "HSM RECOVERY DRILL evidence (an accepted wrong DKEK share keeps the tool output, hex elided)"
"$HERE/tests/test-hsm-recovery-drill-evidence.sh" || suite_failed "test-hsm-recovery-drill-evidence.sh"

say "DRILL REPRO LOOP classifier (labels a failing iteration from the drill FAIL lines, never from prose every run prints)"
"$HERE/tests/test-repro-drill-loop-classifier.sh" || suite_failed "test-repro-drill-loop-classifier.sh"

say "HSM AUTO-IMPORT (unattended createDKEKKeyDomain path: guards, secret hygiene, API regressions)"
"$HERE/tests/test-hsm-auto-import.sh" || suite_failed "test-hsm-auto-import.sh"


say "DAY 0 — the DKEK rule bites, and one device really serves every role (B3, E1)"
"$HERE/tests/test-day0-dkek-rule-and-roles.sh" || suite_failed "test-day0-dkek-rule-and-roles.sh"

say "DAY 1 — one address across two sites, per-device custody, PKA cold-standby failover (A3, A5, A6, A7)"
"$HERE/tests/test-day1-fleet-pins-failover.sh" || suite_failed "test-day1-fleet-pins-failover.sh"

say "DAY 2 — a card can die and be replaced with no loss (A1, A2, A4, B4, C1)"
"$HERE/tests/test-day2-replaceability.sh" || suite_failed "test-day2-replaceability.sh"

say "FLEET DEVICE SELECTION — with two cards attached, a destructive write must never guess (A3, A5, A6)"
"$HERE/tests/test-fleet-device-selection.sh" || suite_failed "test-fleet-device-selection.sh"

say "PIN BINDING — the escrowed PIN must be the PIN the card answers to (PLAN.md 3.1)"
"$HERE/tests/test-pin-binding-proof.sh" || suite_failed "test-pin-binding-proof.sh"

say "RACK COMMISSIONING — cannot-evaluate must FAIL, and a swapped genuine card must be caught (B3, B6, B7)"
"$HERE/tests/test-commission-card.sh" || suite_failed "test-commission-card.sh"
"$HERE/tests/test-tool-helper-paths.sh" || suite_failed "test-tool-helper-paths.sh"
"$HERE/tests/test-dev-image-bootstrap.sh" || suite_failed "test-dev-image-bootstrap.sh"
"$HERE/tests/test-hsm-init-hardened.sh" || suite_failed "test-hsm-init-hardened.sh"
"$HERE/tests/test-hsm-unwrap-key.sh" || suite_failed "test-hsm-unwrap-key.sh"
"$HERE/tests/test-ceremony-python-resolver.sh" || suite_failed "test-ceremony-python-resolver.sh"
python3 "$HERE/tests/test_dkek_encode_key.py" || suite_failed "test_dkek_encode_key.py"

say "PKA THRESHOLD — 2-of-3, auth dies on power-off, a revoked custodian stops counting (B8, C5)"
"$HERE/tests/test-pka-threshold.sh" || suite_failed "test-pka-threshold.sh"

say "DOCUMENT MAP — the entry point must resolve, and no document may be unreachable"
"$HERE/tests/test-doc-map.sh" || suite_failed "test-doc-map.sh"

say "STAGING CI ORCHESTRATOR — the hardware battery must fail closed, never green-skip (no hardware needed)"
"$HERE/tests/test-hsm-staging-ci.sh" || suite_failed "test-hsm-staging-ci.sh"

say "STAGING BENCH LOCK — concurrent hardware jobs are serialized and stale locks fail closed"
"$HERE/tests/test-hsm-bench-lock.sh" || suite_failed "test-hsm-bench-lock.sh"

say "STAGING RESTORE — the posture restorer must aim INITIALIZE DEVICE at a PROVEN card (no hardware needed)"
"$HERE/tests/test-hsm-staging-restore.sh" || suite_failed "test-hsm-staging-restore.sh"

say "SCENARIOS TARGETING — an untargeted --initialize must be refused when two cards are attached"
"$HERE/tests/test-hsm-scenarios-targeting.sh" || suite_failed "test-hsm-scenarios-targeting.sh"

# THESE FOUR EXISTED AND WERE NEVER RUN. Nothing in this runner, and nothing in .github/workflows,
# referenced them — so they asserted nothing, in CI or anywhere else. Two of them guard the air-gap
# check, which their own headers call the single most important control of the whole ceremony. All
# four pass today; they were orphans, not exclusions. test-suite-wiring.sh below now fails if any
# test file goes unreferenced again, because "the test exists" and "the test runs" are different
# claims and only the second one protects anything.
say "CARD TARGETING — the reader/slot resolver must fail closed, and must not report failure on success"
"$HERE/tests/test-hsm-reader-select.sh" || suite_failed "test-hsm-reader-select.sh"

say "SWD ROLE GATE — flash tools must prove WHICH board and that it is staging, before programming"
"$HERE/tests/test-hsm-swd-role-gate.sh" || suite_failed "test-hsm-swd-role-gate.sh"

say "PREFLIGHT AIR-GAP — a missing route tool must never read as 'air-gapped'"
"$HERE/tests/test-preflight-airgap.sh" || suite_failed "test-preflight-airgap.sh"

say "PREFLIGHT LIVE INTERFACE — a routable address with no default route must FAIL, not WARN"
"$HERE/tests/test-preflight-live-iface.sh" || suite_failed "test-preflight-live-iface.sh"

say "FS SCAN — a dangling link must not crash or silently truncate the scan"
python3 "$HERE/tests/test_scan_dangling_link.py" || suite_failed "test_scan_dangling_link.py"

say "SUITE WIRING — every test file in tests/ must actually be run by this runner"
"$HERE/tests/test-suite-wiring.sh" || suite_failed "test-suite-wiring.sh"

# A TOOL NOBODY RUNS IS A COMMENT. tools/hsm-lint-predicates.sh was written after the
# `producer | grep -q` inversion cost a bench night, and then nothing invoked it — not this runner,
# not a workflow. It also had a false positive (`||` read as a pipe) and a blind spot (it skipped
# files that set no pipefail, i.e. the sourced libraries that INHERIT it), so the one line it
# reported could never invert while the real defect sat in a file it never scanned. Wired here
# because it needs no hardware and takes a second.
# The wording below deliberately avoids writing the offending construction literally: the linter
# matches text, and its own announcement containing the pattern made it flag this runner. Comment
# lines are already excluded; a string literal is not a comment.
say "SELF-INVERTING PREDICATES — no early-exiting consumer on a pipeline under pipefail"
_LINT="$HERE/../../tools/hsm-lint-predicates.sh"
if [ -x "$_LINT" ]; then
  # Run it once and KEEP the output. Running it twice — quietly, then again to show the failure —
  # would scan a tree that could have changed between the two runs, and would report a result the
  # reader never saw produced.
  _lint_out="$("$_LINT" 2>&1)"; _lint_rc=$?
  if [ "$_lint_rc" -ne 0 ]; then printf '%s\n' "$_lint_out" | tail -24; suite_failed "tools/hsm-lint-predicates.sh"
  else printf '%s\n' "$_lint_out" | tail -2; fi
else
  # NOT a silent pass: a missing linter means the check did not run.
  printf '  \033[31mFAIL\033[0m the predicate linter is missing at %s — the check did not run\n' "$_LINT"; suite_failed "tools/hsm-lint-predicates.sh (missing)"
fi

say "TRANSCRIPT REDACTOR — every uploaded surface is born redacted (#185)"
"$HERE/tests/test-transcript-redact.sh" || suite_failed "test-transcript-redact.sh"

say "KMS E2E ORCHESTRATOR — reuse existing Docker/Pico batteries; destructive mode needs interlocks"
"$HERE/tests/test-kms-e2e-orchestrator.sh" || suite_failed "test-kms-e2e-orchestrator.sh"

# NOTE: the group_vars-resolver and spend-guard-deploy-gate suites are NOT here. They test
# `infra/ansible/*`, which belongs to the CONSUMER repo (example-service), and they live and run
# there — 10 and 11 assertions respectively. Their copies here came across with the history
# extraction and had no subject to test: one failed outright, the other reported a clean rc=0
# while silently skipping every assertion. The second is the more dangerous of the two, and is
# the same shape as the CI gate that skipped every staging deploy for four days.

say "M-DISC offline-recovery wheels (clean-machine/Tails path is self-contained, no network)"
"$HERE/tests/test-archive-offline-wheels.sh" || suite_failed "test-archive-offline-wheels.sh"

say "M-DISC no-plaintext-shares (the burn set must carry only encrypted/public artifacts)"
"$HERE/tests/test-archive-no-plaintext-shares.sh" || suite_failed "test-archive-no-plaintext-shares.sh"

say "M-DISC recovery-doc paths (the disc must be self-consistent with the runbook it carries)"
"$HERE/tests/test-archive-recovery-doc-paths.sh" || suite_failed "test-archive-recovery-doc-paths.sh"

say "M-DISC cross-drive verify (the printed verify command must checksum the burned files)"
"$HERE/tests/test-optical-cross-drive-verify.sh" || suite_failed "test-optical-cross-drive-verify.sh"

say "OPTICAL fault injection (optical-verify --fault must go red on a corrupted burn)"
"$HERE/tests/test-optical-fault-injection.sh" || suite_failed "test-optical-fault-injection.sh"

say "GO/NO-GO false-GO guard (a typo'd --need device must not skip a check)"
"$HERE/tests/test-go-nogo-guard.sh" || suite_failed "test-go-nogo-guard.sh"

say "GO/NO-GO HSM-token guard (--need hsm must require the SmartCard-HSM, not any PKCS#11 token)"
"$HERE/tests/test-go-nogo-hsm-token.sh" || suite_failed "test-go-nogo-hsm-token.sh"

say "GO/NO-GO SLE-4442 counter guard (near-lock STOP must survive a real per-session reader)"
"$HERE/tests/test-go-nogo-sle4442-counter.sh" || suite_failed "test-go-nogo-sle4442-counter.sh"

say "GO/NO-GO HSM PIN-retry guard (--need hsm must STOP a near-locked HSM before keygen bricks it)"
"$HERE/tests/test-go-nogo-hsm-pin-retry.sh" || suite_failed "test-go-nogo-hsm-pin-retry.sh"

say "GO/NO-GO optical write-capability guard (--need drives must STOP a read-only DVD-ROM pair)"
"$HERE/tests/test-go-nogo-drives-writer.sh" || suite_failed "test-go-nogo-drives-writer.sh"

say "GO/NO-GO preflight warn-surface (a pass-with-warnings must show the WARNs in the GO summary)"
"$HERE/tests/test-go-nogo-preflight-warn-surface.sh" || suite_failed "test-go-nogo-preflight-warn-surface.sh"

say "PREFLIGHT runtime deps (BIP39 'mnemonic' + shamir_mnemonic must be importable, not just python3 on PATH)"
"$HERE/tests/test-preflight-runtime-deps.sh" || suite_failed "test-preflight-runtime-deps.sh"

say "PREFLIGHT dom0-orchestration (dom0 must REFUSE a vault with netvm/ballooning/dom0-swap; mock qvm-prefs)"
"$HERE/tests/test-preflight-dom0.sh" || suite_failed "test-preflight-dom0.sh"

say "PREFLIGHT execution profiles (Qubes disposable/vault and Debian live; full negative matrix)"
python3 "$HERE/tests/test_preflight_environment.py" || suite_failed "test_preflight_environment.py"

say "TEARDOWN residue proof (workdir removal, mount inventory, retained-artifact canary)"
python3 "$HERE/tests/test_ceremony_teardown.py" || suite_failed "test_ceremony_teardown.py"

say "OFFLINE BUNDLE metadata, complete hash coverage, and centralized release signature verification"
python3 "$HERE/../../debian/offline-bundle/test_bundle.py" || suite_failed "test_bundle.py"

IS_LINUX=0; [ "$(uname -s)" = "Linux" ] && IS_LINUX=1
if [ "$MODELS_ONLY" = 1 ] || [ "$IS_LINUX" = 0 ]; then
  [ "$IS_LINUX" = 0 ] && echo ">> non-Linux host: skipping daemon-backed suites (run on the Debian box / CI for those)."
  # still exercise the pure-logic model routes that work anywhere
  say "DKEK model + age round-trip (host)"
  W="$(mktemp -d)"; export EMU_SCHSM_STATE="$W/s" EMU_AGE_IDENTITY_DIR="$W/age"
  if out="$(sc-hsm-tool --create-dkek-share "$W/d.pbe" --pwd-shares-threshold 4 --pwd-shares-total 6 2>&1)" \
     && grep -qE '^Share ID +: 6$' <<< "$out"; then echo "  PASS DKEK share + 6 password shares"; else echo "  FAIL DKEK share"; suite_failed "DKEK model (host)"; fi
  rm -rf "$W"
  if [ "$rc" = 0 ]; then
    echo "OK (host suites)"
  else
    echo "host suites FAILED:"
    for f in "${FAILED_SUITES[@]}"; do echo "  - $f"; done
  fi
  exit "$rc"
fi

# ---------------------------------------------------------------------------------------
if [ "$(id -u)" != 0 ]; then
  echo ">> daemon-backed suites need root (pcscd/cups/mknod). Re-run with sudo, or pass --models-only."
  exit 1
fi

# The ceremony preflight (run by the dress-rehearsal + go/no-go suites) fails closed if
# swap is active — correct for a real vault qube, but CI runners/dev boxes have swap. In
# this TEST context turn it off so preflight genuinely passes (faithful, not faked).
swapoff -a 2>/dev/null || true

say "booting emulator daemons natively (pcscd + vpcd + SLE-4442 + SoftHSM2 + cups-pdf)"
# shellcheck disable=SC1090
source "$EMU_BIN/emu-boot.sh"
boot_all
trap 'stop_all' EXIT

# THE DAEMON-BACKED SUITES DRIVE REAL TOOLS. Without them, route-coverage.sh reports seven route
# FAILURES — "sle4442-manager info failed", "no PDF produced (cups-pdf)", "growisofs burn failed" —
# which read as defects in the ceremony and are nothing of the kind: the host simply does not have
# vsmartcard-vpcd, printer-driver-cups-pdf, xorriso or growisofs. Measured on the qualification box
# 2026-09-21. Name what is missing, and refuse the daemon-backed tier rather than producing results
# that describe the host. The suites that need no daemons have already run and reported honestly.
missing_tools=()
for t in vpcd-config cups-pdf xorriso growisofs; do
  case "$t" in
    cups-pdf)  [ -x /usr/lib/cups/backend/cups-pdf ] || command -v cups-pdf >/dev/null 2>&1 || missing_tools+=("printer-driver-cups-pdf");;
    vpcd-config) command -v vpcd-config >/dev/null 2>&1 || [ -x /usr/sbin/vpcd ] || missing_tools+=("vsmartcard-vpcd");;
    *) command -v "$t" >/dev/null 2>&1 || missing_tools+=("$t");;
  esac
done
if [ "${#missing_tools[@]}" -gt 0 ]; then
  printf '\n\033[1;31m========== REFUSING THE DAEMON-BACKED TIER ==========\033[0m\n' >&2
  printf 'These suites drive real tools, and this host is missing: %s\n\n' "${missing_tools[*]}" >&2
  printf '  Running them anyway reports route FAILURES that describe the host, not the ceremony.\n' >&2
  printf '  Install them and re-run:\n\n      sudo %s --install-deps\n\n' "$0" >&2
  printf '  or, for just these:      sudo apt-get install -y %s\n\n' "${missing_tools[*]}" >&2
  printf '  (The host-runnable suites above ran and their results stand.)\n' >&2
  # REFUSED, NOT FAILED — and exit 2, not 1. A suite that ran and disagreed with the code is a
  # different fact from a tier that never ran, and the repo already separates them this way
  # (assert-no-dkek.sh: 0 clean, 1 found, 2 cannot-evaluate). Calling this a failed suite would
  # put "SOME SUITES FAILED" on a host where nothing failed, and hide the real failures if any.
  # It stays NONZERO: a tier that could not be evaluated is not a pass.
  printf '\n\033[1;35m========== RESULT ==========\033[0m\n'
  if [ "${#FAILED_SUITES[@]}" -gt 0 ]; then
    printf 'SOME SUITES FAILED:\n'
    for s in "${FAILED_SUITES[@]}"; do printf '  - %s\n' "$s"; done
    printf 'AND the daemon-backed tier was REFUSED (missing: %s) — it did not run.\n' "${missing_tools[*]}"
    exit 1
  fi
  printf 'Every suite that could run PASSED.\n'
  printf 'The daemon-backed tier was REFUSED (missing: %s) — it did not run, so this is\n' "${missing_tools[*]}"
  printf 'INCONCLUSIVE, not a pass. Exit 2.\n'
  exit 2
fi

say "ROUTE COVERAGE — every hardware route vs the emulators"
"$HERE/tests/route-coverage.sh" || suite_failed "route-coverage.sh"

say "GO/NO-GO — the day-of hardware gate"
"$HERE/tests/test-go-nogo.sh" || suite_failed "test-go-nogo.sh"

say "DRESS REHEARSAL — drive the real ceremony.sh wizard end-to-end"
"$HERE/tests/dress-rehearsal.sh" || suite_failed "dress-rehearsal.sh"

say "RESULT"
if [ "$rc" = 0 ]; then
  echo "ALL EMULATOR TEST SUITES PASSED (native, no Docker)"
else
  echo "SOME SUITES FAILED:"
  for f in "${FAILED_SUITES[@]}"; do echo "  - $f"; done
  [ "${#FAILED_SUITES[@]}" -gt 0 ] || echo "  - (an inline check set rc=1; search the log for FAIL)"
fi
exit "$rc"
