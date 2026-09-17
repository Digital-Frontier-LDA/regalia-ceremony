#!/usr/bin/env bash
# hsm-staging-ci.sh — the staging HSM pipeline: one entry point that runs the whole battery
# against the attached Pico HSM and reports machine-readably, so a scheduler can own it.
#
#   hsm-staging-ci.sh --list                     # what each tier runs, and which steps bite
#   hsm-staging-ci.sh --tier gate                # NON-DESTRUCTIVE, ~5 min — safe on every push
#   hsm-staging-ci.sh --tier nightly             # DESTRUCTIVE full battery (wipes the card)
#   hsm-staging-ci.sh --tier soak                # nightly + the reliability cycle soak
#   hsm-staging-ci.sh --tier gate --junit out.xml
#
# WHY THIS EXISTS. Every hardware proof in this repo is a separate hand-run script with its own
# ad-hoc PASS/FAIL printing: hsm-staging-e2e.sh, tools/hsm-scenarios.sh, tools/hsm-cycle-test.sh,
# the three drills. Run by hand, by one person, on one machine, they prove things on the days
# somebody remembers to run them. Nothing aggregates them, nothing schedules them, and nothing
# emits a result a CI system can read. This does all three.
#
# THE PROPERTY THAT MATTERS MOST IS FAIL-CLOSED. The defect this project keeps shipping is a
# check that could not run reporting success — the CI gate that skipped every staging deploy for
# four days, the coverage suite that returned rc=0 while silently asserting nothing. So:
#
#   * no card attached                 -> FAIL, not skip
#   * wrong serial                     -> FAIL, and every destructive step is refused
#   * a child script missing           -> FAIL, not skip
#   * PIN counter unreadable           -> FAIL, not skip
#   * device identity unevaluatable    -> FAIL, not skip (no scsh is not an excuse)
#
# The ONLY way to get a green run without hardware is --allow-no-hardware, which marks every
# hardware step SKIPPED, says so on every line, refuses the destructive tiers outright, and puts
# NO-HARDWARE in the summary. A skip is never silent.
#
# PORTABILITY IS A REQUIREMENT, NOT A COURTESY. This runs on the macOS workstation the Pico is
# attached to today and on the Linux DL360 that will host it in CI. Nothing is hardcoded to
# either: the PKCS#11 module is discovered, uhubctl is optional, and every path takes an env
# override. The scripts in tools/ once pointed at a personal worktree and therefore ran for
# exactly one person on exactly one machine while reporting a clean skip for everyone else.
#
# WHAT A GREEN RUN DOES NOT MEAN. This is a Pico HSM — an open-source SmartCard-HSM
# reimplementation on a microcontroller, standing in for the production Nitrokey HSM 2.
# Requirement D1 (repeat on the production token) stays open no matter how green this is.
set -uo pipefail

# The ceremony's python dependencies (pycvc, shamir_mnemonic, mnemonic, pycryptodome) are
# hash-pinned and installed into a venv, NOT into the system interpreter. Prefer that venv so a
# bare `python3` resolves to it. MEASURED 2026-08-06: Homebrew moved python3 from 3.13 to 3.14 and
# orphaned the site-packages holding pycvc, which made the offline CVC check report the DEVICE
# certificate as unparseable when the real cause was a missing host library. Falls through to the
# system python3 when the venv is absent, so nothing breaks on a host that never made one.
CEREMONY_VENV="${CEREMONY_VENV:-$HOME/.local/share/akash-hsm-venv}"
[ -x "$CEREMONY_VENV/bin/python3" ] && PATH="$CEREMONY_VENV/bin:$PATH"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"     # …/qubes/scripts
QUBES="$(cd "$HERE/.." && pwd)"                          # …/qubes
REPO="$(cd "$QUBES/.." && pwd)"
# The committed staging registry is authoritative for board and probe routing. Test harnesses may
# disable this only when supplying synthetic identities; real runs fail closed if it is invalid.
if [ "${HSM_STAGING_REGISTRY_AUTOLOAD:-1}" != 0 ]; then
  . "$REPO/tools/hsm-staging-registry.sh"
  hsm_staging_registry_load || { echo "staging registry load failed" >&2; exit 2; }
fi
# #185 — the write-time redactor. Every capture of external output and the console tee pass
# through it; see the block at the `exec` redirect below for why it sits at write time.
REDACT="$REPO/tools/hsm-transcript-redact.sh"

TIER=""
JUNIT=""
LIST=0
ALLOW_NO_HW=0
SLOT="${HSM_SLOT:-0}"
# ESP2202E14A, not the older ESPICOHSMTR. ESPICOHSMTR was a HARDCODED FALLBACK CONSTANT in the
# firmware (cvc_configure_cert minted "ESPICOHSMTR00001" whenever dev_name was NULL), so every
# Pico on earth reported the same serial — see hardware/pico-hsm/UPSTREAM-DEVAUT-DEADLOCK.md. The
# fix bootstraps dev_name from the board's unique id as ESP + 8 hex + 00001, and OpenSC strips
# the trailing five digits to form the token serial. A device still reporting ESPICOHSMTR is
# running unpatched firmware and has no unique identity to pin, which tools/hsm-devaut-bootstrap-
# test.sh asserts against directly. Per-board, so override it for any other card.
EXPECT_SERIAL="${HSM_CI_SERIAL:-${HSM_E2E_SERIAL:-ESP2202E14A}}"
# ON PINNING THE ATR. hw_atr is a real check only when HSM_CI_EXPECT_ATR is set; unpinned, its
# one failure mode is "no ATR at all". It is honest about that in its own evidence line, so it is
# a weak check rather than a false one — and the fix belongs in the RUN environment, not here.
# A default baked in would be bench-specific and, measured 2026-09-03, breaks the hardware-free
# contract tests that drive a stubbed opensc-tool with a different ATR.
#
# Set it per bench, e.g. in the runner .env:
#   HSM_CI_EXPECT_ATR=3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:fa
# Note it pins the card MODEL and firmware, not the device: both Pico HSMs here return the same
# ATR. Device identity is hw_serial's and hw_devaut's job.
SOAK_CYCLES="${HSM_CI_SOAK_CYCLES:-10}"
MIN_PIN_TRIES="${HSM_CI_MIN_PIN_TRIES:-2}"
STAGING="${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}"
# ONE EFFECTIVE PIN, VISIBLE TO THE WHOLE PROCESS TREE (#185). Exported so the redactor and every
# child agree on the value without it ever travelling in an argument list (ps) or a file (disk).
# Children that need it already received it per-invocation; this only extends the same value to
# the rest of the tree, where the redactor can be relied on to catch anything that prints it.
# The export MUST carry the EFFECTIVE value, default included: `USER_PIN="${HSM_USER_PIN:-…}"` +
# `export HSM_USER_PIN` exports a variable that is still UNSET on the default path, the redactor
# skips a value it never receives, and the PIN the tools are actually handed — the published
# default — goes unredacted on exactly the path an unattended nightly takes (caught on #211).
export HSM_USER_PIN="${HSM_USER_PIN:-648219}"
USER_PIN="$HSM_USER_PIN"

# BENCH RECOVERY, ON BY DEFAULT. This board intermittently stops re-enumerating after an
# INITIALIZE, and a single wedge used to cost the whole battery — measured 2026-08-06, where a
# wedge during the recovery drill's break-glass setup failed an otherwise-complete nightly.
#
# tools/hsm-swd-powman-recover.sh recovers it without hands: warm reset / POWMAN cycle over SWD,
# escalating to a real VBUS cut via uhubctl when the device sits on a switchable port. This
# defaults ON rather than staying opt-in, because a scheduled nightly is exactly the situation
# where nobody is present to remember an env var, and an unattended battery that stops at the
# first wedge is not unattended.
#
# IT CANNOT MANUFACTURE GREEN, which is the only reason defaulting it on is acceptable:
#   * scenario S5 still FAILS and says it was recovered only via the hook — the reboot either
#     returned the card by itself or it did not, and recovery does not change that verdict;
#   * the recovery drill prints a NOTE in its RESULT block saying the run did not demonstrate
#     unattended re-provisioning.
# So a run that needed out-of-band help can never be mistaken for one that did not. Its only job
# is to stop one USB wedge from cascading into every step after it.
#
# Set HSM_CI_RECOVER_CMD to override, or to "" to disable recovery entirely.
if [ -z "${HSM_CI_RECOVER_CMD+set}" ] && [ -x "$REPO/tools/hsm-swd-powman-recover.sh" ]; then
  HSM_CI_RECOVER_CMD="$REPO/tools/hsm-swd-powman-recover.sh"
fi
if [ -n "${HSM_CI_RECOVER_CMD:-}" ]; then
  export HSM_REENUM_RECOVER_CMD="$HSM_CI_RECOVER_CMD"   # hsm-recovery-drill.sh
  export HSM_SCEN_RECOVER_CMD="$HSM_CI_RECOVER_CMD"     # tools/hsm-scenarios.sh (S5)
  # The ladder needs to know WHICH probe and WHICH board, or with two probes attached it binds to
  # whichever OpenOCD finds first and aims resets, POWMAN power cycles and rescue-DP resets at a
  # card nobody asked it to touch. HSM_CI_PROBE_A is the probe on the pinned card; the board id is
  # the OTP chip id it must find there, and the ladder refuses on mismatch.
  [ -n "${HSM_CI_PROBE_A:-}" ] && export HSM_RECOVER_PROBE="$HSM_CI_PROBE_A"
  [ -n "${HSM_CI_BOARD_A:-}" ] && export HSM_RECOVER_BOARD="$HSM_CI_BOARD_A"
# The destructive children each wipe the card and finish in their own posture. This battery already
# restores it once, as its final reported step, so tell them not to each pay for a restore of their
# own — three restores in one nightly is ~90s of nothing. A STANDALONE run of any of them still
# cleans up after itself, because then there is no parent to do it.
export HSM_SUITE_NO_RESTORE=1
fi

# WHICH PHYSICAL BOARD IS THIS TOKEN? The token serial carries only the LAST FOUR BYTES of the
# board's OTP id, so it cannot establish identity on its own, and tools/hsm-reader-select.sh now
# refuses to guess from it: on 2026-09-03 a unique four-byte suffix match returned the WRONG board
# with rc=0 while the real one was off the bus. Identity is therefore SUPPLIED here as
# "token:fullboardid" pairs. Unmapped means "no SWD recovery path for this token" — a refusal,
# which is the correct outcome, because the alternative is resetting a healthy device.
if [ -z "${HSM_BOARD_MAP:-}" ]; then
  _bmap="${HSM_CI_BOARD_MAP:-}"
  if [ -z "$_bmap" ]; then
    # Derived from the config the bench already carries, rather than asking for it twice.
    [ -n "${HSM_CI_BOARD_A:-}" ] && _bmap="$_bmap $EXPECT_SERIAL:$HSM_CI_BOARD_A"
    [ -n "${HSM_CI_SERIAL_B:-}" ] && [ -n "${HSM_CI_BOARD_B:-}" ] && _bmap="$_bmap $HSM_CI_SERIAL_B:$HSM_CI_BOARD_B"
  fi
  [ -n "$_bmap" ] && export HSM_BOARD_MAP="${_bmap# }"
fi

while [ $# -gt 0 ]; do case "$1" in
  --tier)              TIER="${2:-}"; shift 2;;
  --junit)             JUNIT="${2:-}"; shift 2;;
  --slot)              SLOT="${2:-}"; shift 2;;
  --serial)            EXPECT_SERIAL="${2:-}"; shift 2;;
  --soak-cycles)       SOAK_CYCLES="${2:-}"; shift 2;;
  --allow-no-hardware) ALLOW_NO_HW=1; shift;;
  --list)              LIST=1; shift;;
  -h|--help)           sed -n '2,40p' "$0"; exit 0;;
  *) printf 'unknown argument: %s (try --help)\n' "$1" >&2; exit 2;;
esac; done

if [ "$LIST" -eq 0 ]; then
  . "$REPO/tools/hsm-bench-lock.sh"
  HSM_BENCH_LOCK_LABEL="staging-ci:${GITHUB_RUN_ID:-$$}" hsm_bench_lock_acquire failfast || exit $?
fi

# ONE $SLOT CANNOT ADDRESS TWO CARDS. It was passed to pkcs11-tool as a PKCS#11 slot *id* and to
# sc-hsm-tool as a PC/SC reader *index* — the same number for two different namespaces. That held
# while exactly one Pico HSM was ever attached. From 2026-09-02 there are two, and the indices are
# not stable: measured that day, a firmware reset moved the provisioned card from reader 0 to
# reader 1 while the other board took 0. Since this battery spends PINs and runs destructive steps
# in the nightly tier, addressing the wrong card is a wipe of the wrong device.
#
# So resolve BOTH handles from the token serial we already require, and keep them separate.
# Falls back to the historical single-card behaviour when only one reader is present or the
# resolver cannot answer, so nothing changes on a one-card host.
READER="$SLOT"
SLOTIX="$SLOT"
SLOTID="$SLOT"
TARGETED=0
if [ -z "${HSM_CI_NO_AUTOTARGET:-}" ] && [ -n "$EXPECT_SERIAL" ]; then
  # HSM_READER_SELECT is a path seam, not a feature. Both fallbacks below are relative to $HERE, and
  # $HERE is derived from $0 — so when this script is reached through a SYMLINK (which is how
  # test-hsm-staging-ci.sh drives it) neither path resolves, the resolver is silently not sourced, and
  # every two-card code path below becomes unreachable while still reporting a clean run. The
  # single-card defaults then look like successful targeting. Same shape as the repo's other seams
  # (internal/backend/yubikey's pivCards, entropyReader): a var that production never sets.
  _rs="${HSM_READER_SELECT:-$HERE/../../../tools/hsm-reader-select.sh}"
  [ -f "$_rs" ] || _rs="$(cd "$HERE/../../.." 2>/dev/null && pwd)/tools/hsm-reader-select.sh"
  if [ -f "$_rs" ]; then
    # shellcheck source=/dev/null
    . "$_rs"
    _n="$(hsm_reader_indices 2>/dev/null | wc -l | tr -d ' ')"
    if [ "${_n:-0}" -gt 1 ]; then
      _r="$(hsm_reader_for "$EXPECT_SERIAL" 2>/dev/null)" || _r=""
      _s="$(hsm_slot_index_for "$EXPECT_SERIAL" 2>/dev/null)" || _s=""
      _i="$(hsm_slot_id_for "$EXPECT_SERIAL" 2>/dev/null)" || _i=""
      if [ -n "$_r" ] && [ -n "$_s" ] && [ -n "$_i" ]; then
        READER="$_r"; SLOTIX="$_s"; SLOTID="$_i"; TARGETED=1
        printf '%s readers present — targeting %s at PC/SC reader %s, PKCS#11 slot id %s\n' \
               "$_n" "$EXPECT_SERIAL" "$READER" "$SLOTID"
        # Children get the pinned card too. run_child passes no reader arguments, so without
        # this the child suites fall back to PC/SC reader 0 — which is the OTHER card whenever
        # enumeration order puts it first, and several of them wipe what they talk to.
        # Two variables because they are two things: an index for `sc-hsm-tool -r`, a NAME for
        # scsh's `new Card()`.
        export HSM_TARGET_SERIAL="$EXPECT_SERIAL"
        export HSM_PCSC_INDEX="$READER"
        export HSM_SLOT_INDEX="$SLOTIX"
        export HSM_SLOT_ID="$SLOTID"
        # Assign, THEN export. `export X="$(cmd)"` masks the command's exit status, and an empty
        # HSM_READER is not a harmless default here: scsh matches reader names by PREFIX, so an
        # empty name matches the FIRST reader — which is how a run reaches the wrong card.
        _rn="$(hsm_reader_name "$READER" 2>/dev/null)" || _rn=""
        if [ -n "$_rn" ]; then export HSM_READER="$_rn"; else
          printf 'WARNING: could not read the name of reader %s; leaving HSM_READER unset rather than empty\n' "$READER" >&2
        fi
      else
        printf 'WARNING: %s readers present but could not resolve %s; using reader/slot %s\n' \
               "$_n" "$EXPECT_SERIAL" "$SLOT" >&2
      fi
    fi
  fi
fi

# =================================================================================================
# The step registry. Declared as data so --list can print the battery without running it, and so
# a reader can see at a glance which steps are destructive and which tier admits them.
#   id | tiers | destructive | description
STEP_TABLE='
unit_models    | gate nightly soak | no  | host unit suites — each model/parser test, reported individually
unit_emulator  | nightly soak      | no  | the full emulator route/wizard/go-nogo suite (Linux + root)
unit_cvc       | gate nightly soak | no  | C.DevAut CVC offline parse + chain verification (pycvc)
hw_present     | gate nightly soak | no  | a SmartCard-HSM is on the bus and answers PKCS#11
hw_serial      | gate nightly soak | no  | the attached card is the pinned staging serial
hw_atr         | gate nightly soak | no  | ATR fingerprint recorded, and pinned if HSM_CI_EXPECT_ATR is set
hw_rrc         | gate nightly soak | no  | sc-hsm-tool does NOT report the vulnerable RRC configuration
hw_pin_health  | gate nightly soak | no  | the user-PIN retry counter is readable and not near-locked
hw_bench_pins  | gate nightly soak | no  | every attached card has its retry counter recorded, not just the pinned one
hw_devaut      | gate nightly soak | no  | device identity: C.DevAut read from the card and parsed offline
hw_sign        | gate nightly soak | no  | the card still signs for the pinned public key
hw_yubikey_piv | gate nightly soak | no  | the pinned YubiKey PIV 9A slot is read-only qualified: identity, PIN-once/touch-never, retries, public key — no PIN presented
e2e_phases     | nightly soak      | YES | hsm-staging-e2e.sh — hardened init, RRC behaviour, posture, PKA, recovery
e2e_scenarios  | nightly soak      | YES | tools/hsm-scenarios.sh — DKEK isolation, canonicality, wrong PIN, persistence
e2e_recovery   | nightly soak      | YES | hsm-recovery-drill.sh --auto — break-glass DKEK, SLIP-39, re-provision
e2e_fleet      | nightly soak      | YES | hsm-fleet-drill.sh — two-device fleet properties (needs a second card)
hw_wedge_recov | nightly soak      | no  | induce a real wedge over SWD and prove the ladder clears it unattended
soak_cycles    | soak              | YES | tools/hsm-cycle-test.sh — re-provisioning reliability soak
posture_restore| nightly soak      | YES | tools/hsm-staging-restore.sh — leave the card in the posture the gate expects
recover_budget | nightly soak      | no  | how many unscheduled SWD recoveries this run needed, and which rung cleared each
'

# CAPTURE, THEN MATCH. These two decide WHICH STEPS RUN and WHICH ONES WIPE THE CARD, so they are
# the last place to leave a predicate that can invert. Under `pipefail`, `awk ... | grep -q` can
# report 141 instead of the match (grep -q quits, awk takes SIGPIPE) — and an inverted
# step_is_destructive would classify a destructive step as harmless, letting it past the gate that
# exists to keep it away from a card that matters. Measured inverting 5/5 elsewhere on this bench.
tier_admits(){ # $1=step-id — does the selected tier run this step?
  local row tiers
  row="$(awk -F'|' -v id="$1" '$1 ~ "^ *"id" *$"' <<< "$STEP_TABLE")"
  [ -n "$row" ] || return 1
  tiers="$(awk -F'|' '{print $2}' <<< "$row")"
  grep -qw "$TIER" <<< "$tiers"
}
step_is_destructive(){
  local flag
  flag="$(awk -F'|' -v id="$1" '$1 ~ "^ *"id" *$" {print $3}' <<< "$STEP_TABLE")"
  grep -qi yes <<< "$flag"
}
step_desc(){
  printf '%s\n' "$STEP_TABLE" | awk -F'|' -v id="$1" '$1 ~ "^ *"id" *$" {print $4}' | sed 's/^ *//;s/ *$//'
}

if [ "$LIST" = 1 ]; then
  printf '\n\033[1mhsm-staging-ci.sh — the staging HSM battery\033[0m\n\n'
  printf '  %-15s %-18s %-12s %s\n' "step" "tiers" "destructive" "what it proves"
  printf '  %-15s %-18s %-12s %s\n' "----" "-----" "-----------" "--------------"
  printf '%s\n' "$STEP_TABLE" | while IFS='|' read -r id tiers d desc; do
    [ -n "${id// /}" ] || continue
    printf '  %-15s %-18s %-12s %s\n' "${id// /}" "$(echo "$tiers" | sed 's/^ *//;s/ *$//')" \
      "$(echo "$d" | sed 's/^ *//;s/ *$//')" "$(echo "$desc" | sed 's/^ *//;s/ *$//')"
  done
  printf '\n  Destructive steps WIPE the card. They run only in --tier nightly and --tier soak,\n'
  printf '  only after the serial pin matches, and never under --allow-no-hardware.\n\n'
  exit 0
fi

case "$TIER" in
  gate|nightly|soak) ;;
  "") printf 'no --tier given. Choose one of: gate (non-destructive) | nightly | soak. --list shows the battery.\n' >&2; exit 2;;
  *)  printf 'unknown tier "%s" — expected gate | nightly | soak\n' "$TIER" >&2; exit 2;;
esac

if [ "$ALLOW_NO_HW" = 1 ] && [ "$TIER" != gate ]; then
  printf '\033[31mREFUSING\033[0m: --allow-no-hardware is only meaningful for --tier gate.\n' >&2
  printf 'The %s tier exists to exercise the physical card; running it with the hardware\n' "$TIER" >&2
  printf 'steps skipped would report a green destructive battery that never touched a device.\n' >&2
  exit 2
fi

# THE PIN FILE MUST NOT LIVE IN THE UPLOADED TREE (#185). hsm-auto-import.sh writes the PIN to a
# file under HSM_STAGING_DIR (HSM_AUTO_DIR defaults under it). That directory sits outside the
# uploaded run tree TODAY by configuration only — the tidy-up that moves CI working files under
# the run directory would put the PIN in a 90-day artifact with no diff showing it, which is the
# kind of move nobody reviews as a security change. Refuse the configuration outright: the run
# tree is an export surface, and the guard costs nothing in the correct setup.
_ci_root="${HSM_CI_DIR:-${TMPDIR:-/tmp}/hsm-staging-ci}"
# Resolve through the deepest EXISTING ancestor, then append the missing remainder. A plain
# `cd && pwd -P` on a not-yet-created staging dir falls back to the literal path, and on macOS
# that literal still carries the /tmp symlink the existing side has resolved to /private/tmp —
# the exact configuration this guard exists to catch would then compare unequal prefixes and pass.
_canon(){
  local p="$1" out="" rest=""
  # "/" is its own canonical form, and the loop below would return "" for it — a value that
  # makes the prefix comparison meaningless. No reachable configuration behaves differently
  # because of this (both degenerate setups resolve fail-closed either way), but a canonicaliser
  # that returns nothing for the filesystem root is wrong on its own terms.
  [ "$p" = "/" ] && { printf '/'; return 0; }
  while [ "$p" != "/" ]; do
    if out="$(cd "$p" 2>/dev/null && pwd -P)"; then printf '%s' "$out$rest"; return 0; fi
    rest="/$(basename "$p")$rest"; p="$(dirname "$p")"
  done
  printf '%s' "$rest"
}
for _pinhome in "$STAGING" "${HSM_AUTO_DIR:-}"; do
  [ -n "$_pinhome" ] || continue
  case "$(_canon "$_pinhome")/" in
    "$(_canon "$_ci_root")"/*)
      printf '\033[31mREFUSING\033[0m: %s is inside the CI run directory %s, which is uploaded as a 90-day artifact.\n' "$_pinhome" "$_ci_root" >&2
      printf 'hsm-auto-import.sh writes the PIN to a file under the staging directory; move HSM_STAGING_DIR\n' >&2
      printf '(and HSM_AUTO_DIR, if set) outside the uploaded run tree.\n' >&2
      exit 2;;
  esac
done
unset _pinhome _ci_root

# =================================================================================================
# Platform + toolchain discovery. Both hosts this must run on are supported first-class.
OS="$(uname -s)"
detect_p11(){
  local c
  for c in "${HSM_PKCS11_MODULE:-}" \
           /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
           /usr/lib/aarch64-linux-gnu/opensc-pkcs11.so \
           /usr/lib64/opensc-pkcs11.so \
           /usr/lib/opensc-pkcs11.so \
           /opt/homebrew/lib/opensc-pkcs11.so \
           /usr/local/lib/opensc-pkcs11.so; do
    [ -n "$c" ] && [ -f "$c" ] && { printf '%s' "$c"; return 0; }
  done
  # last resort: ask the loader's search path rather than guessing another literal
  c="$(ls /usr/lib/*/opensc-pkcs11.so 2>/dev/null | head -1)"
  [ -n "$c" ] && { printf '%s' "$c"; return 0; }
  return 1
}
P11="$(detect_p11 || true)"

# $$ in the name because two runs started in the same second would otherwise share a directory
# and interleave their logs — which is exactly what a test harness does.
RUN_DIR="${HSM_CI_DIR:-${TMPDIR:-/tmp}/hsm-staging-ci}/$(date +%Y%m%d-%H%M%S)-$TIER-$$"
mkdir -p "$RUN_DIR"; chmod 700 "$RUN_DIR"
TRANSCRIPT="$RUN_DIR/transcript.log"
# REDACTION AT WRITE TIME, NOT AT UPLOAD TIME (#185). The redactor sits between the battery and
# BOTH of its output surfaces — the console (which GitHub retains as the job log) and the
# transcript (which ships in a 90-day artifact) — so a tool that starts echoing what it was
# handed leaves markers, not credentials, in either. Filtering at the tee alone would be too
# late for everything else in the run dir, so every raw capture of external output below is
# filtered at its own write point too; the tee covers what the orchestrator prints itself.
# GitHub masks `secrets.*` in the job log only — the artifact has no masking, which is the gap
# this closes. The secrets reach the redactor through the environment (never argv, never a
# file); see tools/hsm-transcript-redact.sh for the shapes and the stated limits.
exec > >("$REDACT" -o "$TRANSCRIPT") 2>&1
# Bash does NOT wait for a process substitution to drain before the shell exits, so the last
# lines written — which is to say the SUMMARY TABLE — can be lost. MEASURED: the orchestrator's
# own unit suite failed roughly one run in five because `hw_sign` was missing from the captured
# output, and a report that intermittently truncates is precisely the untrustworthy artifact this
# battery exists to avoid. Keep the tee's pid and reap it in flush_output() at the very end.
# (The redactor in -o mode is that tee: one process, so $! stays waitable on bash 3.2 — a
# pipeline inside >( ) is not, which would reintroduce exactly this race.)
TEE_PID=$!
flush_output(){
  exec 1>&- 2>&-
  [ -n "${TEE_PID:-}" ] && wait "$TEE_PID" 2>/dev/null
  return 0
}

RESULTS="$RUN_DIR/results.psv"   # id|status|seconds|message
: > "$RESULTS"

# Defined and armed HERE, before the battery runs: if this script dies mid-run, CI must still get
# a report of what had executed rather than no report at all. The definition has to precede the
# trap — a trap body is only resolved at signal time, but the function does not EXIST until
# execution reaches its definition, so a handler declared before a bottom-of-file definition dies
# with "emit_junit: command not found" and writes nothing. (Measured, not theorised.)
#
# INT and TERM are trapped explicitly, not just EXIT: a bash script killed by an untrapped signal
# does NOT run its EXIT trap, and the soak tier runs long enough that a cancelled GitHub Actions
# job (which cancels with SIGTERM) is a routine event rather than an edge case. Losing the report
# is precisely how a run that found something ends up looking like a run that found nothing.
xml_esc(){ printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"; }
emit_junit(){
  [ -n "$JUNIT" ] || return 0
  local nt=0 nf=0 ns=0 tot=0
  while IFS='|' read -r id st secs msg desc; do
    [ -n "$id" ] || continue
    nt=$((nt+1)); tot=$((tot+${secs:-0}))
    case "$st" in FAIL) nf=$((nf+1));; SKIP) ns=$((ns+1));; esac
  done < "$RESULTS"
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<testsuites name="hsm-staging-ci" tests="%d" failures="%d" skipped="%d" time="%d">\n' "$nt" "$nf" "$ns" "$tot"
    printf '  <testsuite name="hsm-staging-ci.%s" tests="%d" failures="%d" skipped="%d" time="%d" hostname="%s">\n' \
      "$TIER" "$nt" "$nf" "$ns" "$tot" "$(xml_esc "$(hostname 2>/dev/null || echo unknown)")"
    printf '    <properties>\n'
    printf '      <property name="tier" value="%s"/>\n' "$(xml_esc "$TIER")"
    printf '      <property name="os" value="%s"/>\n' "$(xml_esc "$OS $(uname -m)")"
    printf '      <property name="serial" value="%s"/>\n' "$(xml_esc "${SERIAL:-none}")"
    printf '      <property name="pkcs11" value="%s"/>\n' "$(xml_esc "${P11:-none}")"
    printf '      <property name="no_hardware" value="%s"/>\n' "$([ "$ALLOW_NO_HW" = 1 ] && echo true || echo false)"
    printf '      <property name="transcript" value="%s"/>\n' "$(xml_esc "$TRANSCRIPT")"
    # I2/I5: the recovery history is trended over time, so it must survive as machine-readable
    # properties, not only as prose in a step's evidence column.
    printf '      <property name="unscheduled_recoveries" value="%s"/>\n' "$(xml_esc "${RECOVER_COUNT:-0}")"
    printf '      <property name="recovery_rungs" value="%s"/>\n' "$(xml_esc "${RECOVER_RUNGS:-none}")"
    printf '      <property name="recovery_budget" value="%s"/>\n' "$(xml_esc "${RECOVER_BUDGET:-2}")"
    printf '      <property name="failed_recoveries" value="%s"/>\n' "$(xml_esc "${RECOVER_FAILED:-0}")"
    printf '    </properties>\n'
    while IFS='|' read -r id st secs msg desc; do
      [ -n "$id" ] || continue
      printf '    <testcase classname="hsm-staging-ci.%s" name="%s" time="%d">' \
        "$(xml_esc "$TIER")" "$(xml_esc "$id — ${desc:-$(step_desc "$id")}")" "${secs:-0}"
      case "$st" in
        FAIL) printf '\n      <failure message="%s"/>\n    ' "$(xml_esc "$msg")";;
        SKIP) printf '\n      <skipped message="%s"/>\n    ' "$(xml_esc "$msg")";;
      esac
      printf '</testcase>\n'
    done < "$RESULTS"
    printf '  </testsuite>\n</testsuites>\n'
  } > "$JUNIT"
  printf '  JUnit: %s\n' "$JUNIT"
}
# flush_output only on EXIT: the INT/TERM handlers below call exit, so the EXIT trap fires after
# them and drains the tee once, last, when nothing further will be printed.
trap 'emit_junit; flush_output; hsm_bench_lock_release' EXIT
trap 'emit_junit; hsm_bench_lock_release; exit 130' INT
trap 'emit_junit; hsm_bench_lock_release; exit 143' TERM

P(){   printf '  \033[32mPASS\033[0m %s\n' "$1"; }
F(){   printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
S(){   printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
note(){ printf '       %s\n' "$*"; }

now(){ date +%s; }
# The description travels WITH the result rather than being looked up later, so dynamically
# generated steps (one per host unit suite) are first-class in the JUnit report instead of
# collapsing into one opaque testcase. It also keeps this working on bash 3.2, which has no
# associative arrays — /bin/bash on macOS is still 3.2.
record(){ # $1=id $2=status $3=seconds $4=message $5=description(optional)
  local desc="${5:-$(step_desc "$1")}"
  printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" \
    "$(printf '%s' "$4" | tr '\n|' '  ' | cut -c1-300)" \
    "$(printf '%s' "$desc" | tr '\n|' '  ' | cut -c1-200)" >> "$RESULTS"
  case "$2" in PASS) P "$1 — $4";; FAIL) F "$1 — $4";; *) S "$1 — $4";; esac
}
pass(){ record "$1" PASS "${3:-0}" "$2" "${4:-}"; }
fail(){ record "$1" FAIL "${3:-0}" "$2" "${4:-}"; }
skip(){ record "$1" SKIP "${3:-0}" "$2" "${4:-}"; }

# D3: AUTO-RECOVERY IS COUNTED AND REPORTED, NEVER SILENT.
#
# ensure_card() clearing a wedge between steps is the difference between one explained failure and
# four cascading ones with wrong explanations. But a bench that silently repairs itself turns a
# degrading device into an invisible trend, so the repairs are counted and the count is a step with
# its own verdict.
#
# The threshold is derived, not chosen by taste: the measured per-reboot wedge rate is 6.62%
# (106/1600, doc/USB-DELAY-SWEEP-RESULTS.txt) and a nightly performs roughly fifteen reboots, so the
# binomial expectation is ~1 recovery per run. Three or more is about 3 sigma — a real signal.
#
# The DELIBERATE wedge (hw_wedge_recov) is excluded structurally: it is a non-destructive step, so
# run_child never calls ensure_card for it, and it recovers the card inside its own child process.
# The test therefore cannot poison the threshold it is measured against.
RECOVER_COUNT=0
RECOVER_FAILED=0
RECOVER_RUNGS=""
RECOVER_BUDGET="${HSM_CI_RECOVER_BUDGET:-2}"

# WHICH RUNG cleared the wedge (I6). The ladder announces its choice per pass as
# "pass N/M: <symptom> — <remedy>"; the last such line before the card returned is the rung that
# worked. Recording only a COUNT loses the mechanism, which is the part that says what is wrong.
recover_rung(){
    local log="${1:-}" last=""
    [ -r "$log" ] || { printf 'unknown\n'; return 0; }
    last="$(grep -a 'pass [0-9]*/' "$log" 2>/dev/null | tail -1)"
    case "$last" in
        *"debug bus is STALLED"*)   printf 'rescue_reset\n' ;;
        *"power switch"*)           printf 'cut_vbus\n' ;;
        *"warm reset"*)             printf 'warm_reset\n' ;;
        *"POWMAN power cycle"*)     printf 'powman_cycle\n' ;;
        "")                         printf 'came_back_unaided\n' ;;
        *)                          printf 'unknown\n' ;;
    esac
}

# run a child script as a step. A missing or non-executable child is a FAILURE: a battery that
# quietly drops a suite because the file moved is the same defect as a gate that skips silently.
# IS THE PINNED CARD STILL THERE — and if not, clear it before blaming the next suite.
#
# Measured 2026-09-03: the staging card wedged partway through a nightly. Everything after it
# failed, each with its own confident and WRONG explanation — "IMPORT_DKEK_SHARE not allowed",
# "no reader holds a card with serial ESP2202E14A", "DKEK import failed". Four failures, one
# cause, and none of the messages named it. A run that reports four independent defects when one
# card went quiet is worse than a run that reports nothing.
#
# So before each destructive child: confirm the card answers, and if it does not, run the SWD
# recovery ladder once and re-resolve the handles (recovery re-enumerates, which renumbers PC/SC
# and can move PKCS#11 slot ids). If it still will not answer, say THAT — one honest failure.
ensure_card(){ # $1 = step id, for the failure message
  [ "$TARGETED" = 1 ] || return 0
  command -v hsm_serial_at_slot_id >/dev/null 2>&1 || return 0
  [ "$(hsm_serial_at_slot_id "$SLOTID" 2>/dev/null)" = "$EXPECT_SERIAL" ] && return 0
  note "$EXPECT_SERIAL is not answering before $1"

  # IS SWD RECOVERY EVEN POSSIBLE FOR THIS TOKEN?
  #
  # Only on the Pico. The production token is a Nitrokey HSM 2 (USB 20a0:4230) with no debug port,
  # so a POWMAN cycle or rescue-DP reset is not a recovery there — it is a claim of a capability
  # this bench does not have. Detect the platform from USB (2e8a:10fd = RP-series silicon), which
  # still reads correctly on a WEDGED card because the wedge is "enumerated but mute".
  local _board=""
  if command -v hsm_board_for_token >/dev/null 2>&1; then
    _board="$(hsm_board_for_token "$EXPECT_SERIAL" 2>/dev/null)" || _board=""
  fi
  if [ -z "$_board" ]; then
    # Only ONE reason remains: the token is unmapped. Reporting that as "not an RP2350 Pico" is the
    # misdirection class this battery keeps removing — a correct refusal with a wrong reason sends
    # the next person to the wrong drawer.
    note "no HSM_BOARD_MAP entry for $EXPECT_SERIAL (set HSM_CI_BOARD_MAP=\"token:boardid ...\" or HSM_CI_BOARD_A) — refusing to guess which board to reset, so there is no SWD recovery path"
    RECOVER_FAILED=$((RECOVER_FAILED + 1))
    RECOVER_RUNGS="${RECOVER_RUNGS:+$RECOVER_RUNGS,}unavailable:unmapped"
    return 1
  fi
  # ABSENT FROM USB IS THE REASON TO RECOVER, NOT A REASON TO REFUSE. The probe reaches the chip
  # over SWD long after the USB device is gone, and this is the harder of the two wedge states.
  if command -v hsm_board_attached >/dev/null 2>&1 && ! hsm_board_attached "$_board"; then
    note "board $_board is not enumerated on USB at all — the harder wedge state; going to SWD"
  fi

  # PICK THE PROBE ATTACHED TO *THAT* BOARD. With two probes, "the probe" is not a thing, and a
  # ladder aimed at the wrong board resets a healthy card. HSM_CI_PROBE_MAP is explicit
  # "probeSerial:boardId" pairs; deriving it by reading OTP through each probe would work but
  # attaching to a healthy card is itself enough to mute it (measured 2026-09-02).
  local _probe="" _pair
  for _pair in ${HSM_CI_PROBE_MAP:-}; do
    case "$_pair" in "*:$_board"|*":$_board") _probe="${_pair%%:*}"; break ;; esac
  done
  [ -z "$_probe" ] && [ "${HSM_CI_BOARD_A:-}" = "$_board" ] && _probe="${HSM_CI_PROBE_A:-}"
  if [ -z "$_probe" ]; then
    note "no probe mapped to board $_board (set HSM_CI_PROBE_MAP=\"probe:board ...\") — cannot recover it over SWD"
    RECOVER_FAILED=$((RECOVER_FAILED + 1))
    RECOVER_RUNGS="${RECOVER_RUNGS:+$RECOVER_RUNGS,}unavailable:noprobe"
    return 1
  fi

  note "recovering board $_board via probe $_probe"
  # A LOG PER ATTEMPT, not one appended file. Which rung cleared a wedge is the diagnostic that
  # distinguishes failure modes — "always the rescue DP" and "always a warm reset" are different
  # illnesses — and that attribution is impossible if every attempt shares one log.
  local _rlog="$RUN_DIR/recover.$((RECOVER_COUNT + 1)).log"
  if [ -n "${HSM_CI_RECOVER_CMD:-}" ] && [ -x "${HSM_CI_RECOVER_CMD%% *}" ]; then
    HSM_RECOVER_PROBE="$_probe" HSM_RECOVER_BOARD="$_board" HSM_RECOVER_SERIAL="$EXPECT_SERIAL" \
      ${HSM_CI_RECOVER_CMD} 2>&1 | "$REDACT" > "$_rlog" || true
    cat "$_rlog" >> "$RUN_DIR/recover.log" 2>/dev/null || true
    sleep 8
  fi
  local _r _s _i
  _r="$(hsm_reader_for "$EXPECT_SERIAL" 2>/dev/null)" || _r=""
  _s="$(hsm_slot_index_for "$EXPECT_SERIAL" 2>/dev/null)" || _s=""
  _i="$(hsm_slot_id_for "$EXPECT_SERIAL" 2>/dev/null)" || _i=""
  if [ -n "$_r" ] && [ -n "$_i" ]; then
    READER="$_r"; SLOTIX="${_s:-$SLOTIX}"; SLOTID="$_i"
    export HSM_PCSC_INDEX="$READER" HSM_SLOT_INDEX="$SLOTIX" HSM_SLOT_ID="$SLOTID"
    if command -v hsm_reader_name >/dev/null 2>&1; then
      local _rn; _rn="$(hsm_reader_name "$READER" 2>/dev/null)" || _rn=""
      [ -n "$_rn" ] && export HSM_READER="$_rn"
    fi
    RECOVER_COUNT=$((RECOVER_COUNT + 1))
    local _rung; _rung="$(recover_rung "$_rlog")"
    RECOVER_RUNGS="${RECOVER_RUNGS:+$RECOVER_RUNGS,}$_rung"
    note "recovered via $_rung — $EXPECT_SERIAL is back at reader $READER, slot id $SLOTID (unscheduled recovery #$RECOVER_COUNT this run)"
    return 0
  fi
  # A FAILED recovery must be counted too. MEASURED 2026-09-03: a nightly ended with the card off
  # the bus, three steps correctly red — and recover_budget reported "no unscheduled recoveries, the
  # card stayed up on its own", because only SUCCESSES were counted. A counter that is silent about
  # the attempts that failed reports a broken bench as a healthy one, which is the exact
  # false-reassurance this step exists to prevent.
  RECOVER_FAILED=$((RECOVER_FAILED + 1))
  RECOVER_RUNGS="${RECOVER_RUNGS:+$RECOVER_RUNGS,}failed:$(recover_rung "$_rlog")"
  return 1
}

run_child(){ # $1=id $2=script $3... = args
  local id="$1" script="$2"; shift 2
  local log="$RUN_DIR/$id.log" t0 t1
  hdr "$id — $(step_desc "$id")"
  if ! ensure_card "$id"; then
    fail "$id" "the pinned card $EXPECT_SERIAL is not on the bus and the recovery ladder did not bring it back — this step was NOT run, and any later failure is a consequence of this, not an independent defect"
    return 1
  fi
  if [ ! -f "$script" ]; then
    fail "$id" "child script is MISSING: $script (a moved suite is a failure, not a skip)"
    return 1
  fi
  if [ ! -x "$script" ] && ! grep -q '^#!' <<< "$(head -1 "$script" 2>/dev/null)"; then
    fail "$id" "child script is not executable and has no interpreter line: $script"
    return 1
  fi
  note "running: $script $*"
  note "log:     $log"
  local rc
  t0="$(now)"
  # CHILD_SUDO is empty for everything except the emulator suite, which needs root for
  # pcscd/cups/mknod. -E because the whole battery is configured through the environment.
  # Through the redactor: children hold the PIN in their environment, and this log is uploaded.
  # pipefail (set at the top of the file) keeps rc=the child's rc, not the filter's.
  ( set -o pipefail; ${CHILD_SUDO:-} bash "$script" "$@" ) 2>&1 | "$REDACT" > "$log"
  rc=$?
  t1="$(now)"
  local last; last="$(grep -aE 'passed|failed|FAIL|PASS' "$log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g')"
  if [ "$rc" = 0 ]; then
    pass "$id" "${last:-completed} (rc=0)" "$((t1-t0))"
  else
    fail "$id" "rc=$rc — ${last:-see $log}" "$((t1-t0))"
  fi
  return $rc
}

# =================================================================================================
hdr "PREFLIGHT — host, toolchain, and the fail-closed contract"
printf '  tier:       %s%s\n' "$TIER" "$([ "$ALLOW_NO_HW" = 1 ] && printf ' (NO-HARDWARE)')"
printf '  host:       %s %s\n' "$OS" "$(uname -m)"
printf '  repo:       %s\n' "$REPO"
printf '  run dir:    %s\n' "$RUN_DIR"
printf '  transcript: %s\n' "$TRANSCRIPT"

# scdaemon grabs the reader and turns every card operation into an inexplicable failure. Killing
# it is the single most reliable preflight action there is; it costs nothing when it is not running.
pkill -f scdaemon 2>/dev/null && note "killed a running scdaemon (it holds the reader)" || true

HW_OK=1   # can we legitimately touch hardware at all?
if [ "$ALLOW_NO_HW" = 1 ]; then
  HW_OK=0
  printf '  \033[33mNO-HARDWARE MODE\033[0m — every hardware step will be SKIPPED and reported as such.\n'
  printf '  This run proves the host-side suites only. It is NOT evidence about any device.\n'
else
  for t in pkcs11-tool sc-hsm-tool openssl python3; do
    command -v "$t" >/dev/null || { printf '  \033[31mmissing required tool: %s\033[0m\n' "$t"; HW_OK=0; }
  done
  if [ -z "$P11" ]; then
    printf '  \033[31mno PKCS#11 module found\033[0m — set HSM_PKCS11_MODULE (searched the usual\n'
    printf '  Debian, RHEL, Homebrew and /usr/local locations)\n'
    HW_OK=0
  else
    printf '  pkcs11:     %s\n' "$P11"
  fi
  [ "$HW_OK" = 0 ] && printf '  \033[31mthe toolchain is incomplete — hardware steps will FAIL, not skip\033[0m\n'
fi

# =================================================================================================
# HOST SUITES — no hardware, run in every tier. These are the unit tests: models, parsers, guards.
#
# Each suite is its own step. Running them through run-tests.sh instead would collapse ~12
# independent results into one pass/fail — and run-tests.sh's --models-only does not do what its
# name suggests: it gates only the daemon-backed section at the bottom, so everything above it
# (the CUPS suites among them) still runs and hangs on a non-Linux host. The full emulator suite
# is a separate step below, admitted only where it can actually run.
HOST_SUITES="test_sle4442_model test_schsm_crypto test_derive_address test_slip39_mint
test_metal_stamp test_recovery_procedure test_payload_qr test_entropy_mix test_seed_to_pkcs12
test_verify_hsm_control test_recovery_card"

if tier_admits unit_models; then
  hdr "unit_models — $(step_desc unit_models)"
  for suite in $HOST_SUITES; do
    src="$QUBES/emulator/tests/$suite.py"
    t0="$(now)"
    if [ ! -f "$src" ]; then
      fail "unit_models.$suite" "suite file is MISSING at $src — a vanished test is a failure, not a skip" 0 \
        "host unit suite $suite"
      continue
    fi
    log="$RUN_DIR/unit_models.$suite.log"
    python3 "$src" 2>&1 | "$REDACT" > "$log"
    rc=$?
    ran="$(grep -aoE 'Ran [0-9]+ tests?|[0-9]+ passed' "$log" | tail -1)"
    if [ "$rc" = 0 ]; then
      pass "unit_models.$suite" "${ran:-passed}" "$(( $(now) - t0 ))" "host unit suite $suite"
    else
      fail "unit_models.$suite" "rc=$rc — $(grep -aE 'FAIL|Error|assert' "$log" | tail -1 | cut -c1-160)" \
        "$(( $(now) - t0 ))" "host unit suite $suite"
    fi
  done
fi

if tier_admits unit_emulator; then
  hdr "unit_emulator — $(step_desc unit_emulator)"
  if [ "$OS" != Linux ]; then
    # A real skip with a real reason: the suite boots pcscd, vpcd, SoftHSM2 and cups-pdf, which
    # exist only on Linux. run-tests.sh says the same thing about itself. This is the one place
    # in the battery where "not applicable here" is the honest answer — and the DL360 that will
    # host this CI is Linux, so the skip disappears the moment it matters.
    skip unit_emulator "host is $OS — the daemon-backed emulator suite is Linux-only (it runs in the ceremony-emulator workflow and will run here once the DL360 takes over)"
  elif [ "$(id -u)" = 0 ]; then
    run_child unit_emulator "$QUBES/emulator/run-tests.sh"
  elif sudo -n true 2>/dev/null; then
    # A self-hosted GitHub runner does not run as root. Passwordless sudo is the documented
    # provisioning for the CI box, so use it rather than failing a suite that can plainly run.
    # Set and cleared explicitly: bash does NOT reliably unwind `VAR=x somefunction` assignments.
    CHILD_SUDO="sudo -E"
    run_child unit_emulator "$QUBES/emulator/run-tests.sh"
    CHILD_SUDO=""
  else
    fail unit_emulator "the emulator suite needs root for pcscd/cups/mknod; this run is uid $(id -u) and passwordless sudo is unavailable — applicable but NOT evaluated, which is a failure. Provision the runner with NOPASSWD sudo or run the battery as root."
  fi
fi

if tier_admits unit_cvc; then
  hdr "unit_cvc — $(step_desc unit_cvc)"
  t0="$(now)"
  if ! python3 -c 'import cvc' 2>/dev/null; then
    fail unit_cvc "pycvc is not importable — the offline C.DevAut parse cannot be evaluated. Install: pip install --require-hashes -r $QUBES/requirements.txt"
  else
    log="$RUN_DIR/unit_cvc.log"
    CEREMONY_SCRIPTS="$HERE" python3 "$QUBES/emulator/tests/test_cvc_devaut_verify.py" 2>&1 | "$REDACT" > "$log"
    rc=$?
    ran="$(grep -aoE 'Ran [0-9]+ tests?' "$log" | tail -1)"
    [ "$rc" = 0 ] && pass unit_cvc "${ran:-tests passed}" "$(( $(now) - t0 ))" \
                  || fail unit_cvc "rc=$rc — ${ran:-see $log}" "$(( $(now) - t0 ))"
  fi
fi

# =================================================================================================
# HARDWARE, NON-DESTRUCTIVE.
#
# TWO GATES, NOT ONE, because "unsafe to write to" and "unsafe to read from" are different
# questions and conflating them costs diagnostics exactly when they matter most:
#
#   CARD_READABLE  a token answers at all -> the read-only checks may run. These spend no PIN and
#                  write nothing, so an unrecognised card is still worth interrogating: "wrong
#                  serial AND the vulnerable RRC config AND 1 PIN try left" is an actionable
#                  report, where four copies of "blocked, could not evaluate" is not.
#   CARD_PINNED    the card also proved WHICH card it is (serial, ATR, healthy PIN counter) ->
#                  the PIN-spending check and every destructive step may run. Signing against an
#                  unrecognised card would spend a retry on somebody else's counter.
SERIAL=""
CARD_READABLE=0
CARD_PINNED=0
# Set only when the user-PIN retry counter was READ and is above the floor. Any step that spends
# a retry must refuse to run without it — see hw_sign.
PIN_SPEND_OK=0

hw_guard(){ # emit the right non-pass for a read-only step that could not run at all
  local id="$1"
  if [ "$ALLOW_NO_HW" = 1 ]; then
    skip "$id" "NO-HARDWARE mode — this step was NOT evaluated and proves nothing"
  else
    fail "$id" "the toolchain or the card is unavailable — cannot-evaluate is a FAILURE"
  fi
}

if tier_admits hw_present; then
  hdr "hw_present — $(step_desc hw_present)"
  if [ "$HW_OK" != 1 ]; then hw_guard hw_present; else
    # BOUNDED RETRY, and only here. The Pico transiently leaves the USB bus and re-enumerates a
    # few seconds later — MEASURED twice on 2026-08-06, both times a gate run happened to probe
    # during the gap and failed a card that was fine moments later. A CI battery that goes red on
    # a two-second re-enumeration trains people to ignore it, which is the same end state as a
    # battery that never runs.
    #
    # This is NOT a softening of the fail-closed rule: the window is finite, exhausting it is
    # still a hard FAILURE, and the settle time is reported so a card that is degrading shows up
    # as a trend rather than hiding behind a retry. Nothing else in the battery retries.
    t0="$(now)"; tries=0; max="${HSM_CI_PRESENCE_TRIES:-10}"; slots=""
    while :; do
      slots="$(pkcs11-tool --module "$P11" --slot "$SLOTID" --list-slots 2>&1 | "$REDACT")"
      if [ "$TARGETED" = 1 ]; then
        # with two cards present, "a token answers" is not the question — ours must answer
        [ -n "$(hsm_serial_at_slot_id "$SLOTID")" ] && break
      else
        grep -q 'token label' <<< "$slots" && break
      fi
      tries=$((tries+1))
      [ "$tries" -ge "$max" ] && break
      [ "$tries" = 1 ] && note "no token yet — the Pico drops off the bus and re-enumerates; polling up to $((max*3))s"
      sleep 3
    done
    if grep -q 'token label' <<< "$slots"; then
      settle="$(( $(now) - t0 ))"
      CARD_READABLE=1
      if [ "$tries" = 0 ]; then
        pass hw_present "a token answers on slot id $SLOTID" "$settle"
      else
        pass hw_present "a token answers on slot id $SLOTID after a ${settle}s re-enumeration (${tries} polls) — transient USB drop, tracked not ignored" "$settle"
      fi
    else
      fail hw_present "no token on slot id $SLOTID after $((max*3))s of polling — $(printf '%s' "$slots" | tail -1)" "$(( $(now) - t0 ))"
    fi
  fi
fi

if tier_admits hw_serial; then
  hdr "hw_serial — $(step_desc hw_serial)"
  if [ "$CARD_READABLE" != 1 ]; then hw_guard hw_serial; else
    # `--list-slots` prints EVERY slot regardless of --slot/--slot-index, so `head -1` reads
    # whichever card is listed first. With two cards attached on 2026-09-03 that pinned the
    # battery to the WRONG device: it resolved the target correctly, then read the other card's
    # serial and refused to write — a correct refusal for an incorrect reason.
    if [ "$TARGETED" = 1 ]; then
      SERIAL="$(hsm_serial_at_slot_id "$SLOTID")"
    else
      SERIAL="$(pkcs11-tool --module "$P11" --slot "$SLOTID" --list-slots 2>/dev/null \
        | grep -oE 'serial num *: *[A-Za-z0-9]+' | head -1 | awk '{print $NF}')"
    fi
    if [ "$SERIAL" = "$EXPECT_SERIAL" ]; then
      # THE ROLE REGISTRY CROSS-CHECK. A matching pin proves the card is the one the OPERATOR
      # named; the registry proves that name is a scratch card. Without this, pointing
      # HSM_CI_SERIAL at a card that matters would satisfy the pin and unlock every destructive
      # tier below. Default-deny: unlisted, prod, unreadable registry — or no gate at all — all
      # leave the card unpinned. Absent function reads as protected, never as a skip.
      _role="protected"
      command -v hsm_role_of >/dev/null 2>&1 && _role="$(hsm_role_of "$EXPECT_SERIAL" 2>/dev/null)"
      if [ "$_role" != staging ]; then
        CARD_PINNED=0
        fail hw_serial "serial $SERIAL matches the pin, but the staging registry does not list it as staging (role: $_role) — the destructive tiers refuse any card that is not explicitly staging (default-deny; see tools/hsm-staging-registry.json)"
      else
        CARD_PINNED=1
        pass hw_serial "serial $SERIAL matches the pinned staging device (registered staging)"
      fi
    else
      fail hw_serial "serial '${SERIAL:-unreadable}' != pinned '$EXPECT_SERIAL' — REFUSING to write to this card (the read-only checks below still run, and their findings still count)"
    fi
  fi
fi

if tier_admits hw_atr; then
  hdr "hw_atr — $(step_desc hw_atr)"
  if [ "$CARD_READABLE" != 1 ]; then hw_guard hw_atr; else
    # -r: bare opensc-tool reads PC/SC reader 0, which is not necessarily the card this run is
    # pinned to. Measured 2026-09-03: with the other board deliberately off the bus, reader 0 had
    # no card and this reported "could not read an ATR" about a card that was answering fine.
    ATR="$(opensc-tool -r "$READER" --atr 2>/dev/null | tr -d ' \n' | tail -c 200)"
    if [ -z "$ATR" ]; then
      fail hw_atr "could not read an ATR (is opensc-tool installed and is pcscd running?)"
    elif [ -n "${HSM_CI_EXPECT_ATR:-}" ] && [ "$ATR" != "${HSM_CI_EXPECT_ATR//[[:space:]]/}" ]; then
      CARD_PINNED=0
      fail hw_atr "ATR MISMATCH — got $ATR, pinned ${HSM_CI_EXPECT_ATR}. Reader index is not evidence; the ATR is."
    else
      printf '%s\n' "$ATR" > "$RUN_DIR/atr.txt"
      pass hw_atr "ATR $ATR$([ -n "${HSM_CI_EXPECT_ATR:-}" ] && printf ' (matches the pin)' || printf ' (recorded; set HSM_CI_EXPECT_ATR to pin it)')"
    fi
  fi
fi

if tier_admits hw_rrc; then
  hdr "hw_rrc — $(step_desc hw_rrc)"
  if [ "$CARD_READABLE" != 1 ]; then hw_guard hw_rrc; else
    sct="$(sc-hsm-tool --reader "$READER" 2>&1 | "$REDACT")"; sct_rc=$?
    if [ "$sct_rc" != 0 ] && ! grep -q 'Version' <<< "$sct"; then
      fail hw_rrc "sc-hsm-tool could not read the card (rc=$sct_rc) — the RRC posture CANNOT BE EVALUATED"
    elif grep -q 'User PIN reset with SO-PIN enabled' <<< "$sct"; then
      fail hw_rrc "the card reports 'User PIN reset with SO-PIN enabled' — the D3 posture is NOT in force"
    else
      pass hw_rrc "no vulnerable-RRC tell in the card's config options"
    fi
  fi
fi

if tier_admits hw_pin_health; then
  hdr "hw_pin_health — $(step_desc hw_pin_health)"
  if [ "$CARD_READABLE" != 1 ]; then hw_guard hw_pin_health; else
    _sct_tries="$(sc-hsm-tool --reader "$READER" 2>&1 | "$REDACT")"
    TRIES="$(grep -oE 'User PIN tries left *: *[0-9]+' <<< "$_sct_tries" | grep -oE '[0-9]+$' | head -1)"
    # A LOCKED CARD SAYS SO IN WORDS, NOT IN A NUMBER. sc-hsm-tool prints "User PIN locked" instead
    # of "User PIN tries left : 0", so a parser looking only for digits finds nothing and calls a
    # card that stated its problem plainly "unreadable" — sending the next person to look for a bus
    # fault instead of a locked PIN. Measured on ESP2202E14A, 2026-09-03.
    if grep -qi 'User PIN locked' <<< "$_sct_tries"; then
      CARD_PINNED=0
      fail hw_pin_health "the user PIN is LOCKED (0 tries left) — the card cannot authenticate and must be unlocked with the SO-PIN or re-initialised before any step that needs the user PIN"
    elif [ -z "$TRIES" ]; then
      fail hw_pin_health "the retry counter is UNREADABLE — a near-locked card must never reach a destructive step"
    elif [ "$TRIES" -lt "$MIN_PIN_TRIES" ]; then
      CARD_PINNED=0
      fail hw_pin_health "only $TRIES user-PIN tries left (floor $MIN_PIN_TRIES) — halting before something bricks the card"
    else
      PIN_SPEND_OK=1
      pass hw_pin_health "$TRIES user-PIN tries left (floor $MIN_PIN_TRIES)"
    fi
  fi
fi

# A FLOOR ON ONE CARD IS NOT A SAFETY PROPERTY OF THE BENCH. hw_pin_health above reads only the
# PINNED card, and that is the card this battery is least likely to damage. Smart Card Shell selects
# readers by name PREFIX, so a destructive child can reach a card the battery never resolved:
# MEASURED 2026-09-11, e2e_phases.log:71 and e2e_recovery.log:5 both record serial ESP41D722E2
# while the battery was pinned to ESP2202E14A, and afterwards the non-pinned card stood at ONE
# user-PIN try. Nothing in the run could say whether the run had spent those retries, because no
# pre-run reading of that card existed — so the first job of this step is to BE that reading.
# Every probe here is PIN-free (a bare sc-hsm-tool config read and a pkcs15-tool dump); neither
# spends a retry, which is what makes a census of a near-locked card safe to take.
if tier_admits hw_bench_pins; then
  hdr "hw_bench_pins — $(step_desc hw_bench_pins)"
  # GUARD FIRST, like every sibling hw_ step. Without this the census FAILS under
  # --allow-no-hardware, where there is deliberately no card and the hardware steps must be SKIPPED
  # rather than red. It shipped that way in #396 and nothing caught it, because the battery finds its
  # reader resolver relative to $0 and the test harness drives it through a symlink — so
  # hsm_reader_indices was undefined in every test and this step always took the "resolver
  # unavailable" skip. A step whose only tested branch is its own bail-out is not a tested step.
  if [ "$CARD_READABLE" != 1 ]; then hw_guard hw_bench_pins
  elif ! command -v hsm_reader_indices >/dev/null 2>&1; then
    # NOT A PASS. Without the resolver this step enumerates nothing, and "no card was found to be
    # low" is indistinguishable from "no card was looked at" — the silent-instrument failure that
    # reports clean precisely when it is broken.
    skip hw_bench_pins "the reader resolver is unavailable, so no bench-wide census was taken"
  else
    _bp_seen=0; _bp_risk=""
    for _bp_i in $(hsm_reader_indices); do
      _bp_seen=$((_bp_seen + 1))
      # CAPTURE, THEN TEST THE VALUE — never discard it on the callee's status. `x="$(f)" || x=""`
      # throws away a correctly-read serial whenever f returns non-zero, and under the pipefail this
      # script sets, a resolver reading a slow card tool returned 141 on SUCCESS (fixed in
      # hsm-reader-select.sh, but the caller should not depend on that). This printed
      # "serial UNREADABLE" for both cards while the step PASSED.
      _bp_ser="$(hsm_serial_at_reader "$_bp_i" 2>/dev/null || true)"
      _bp_info="$(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool --reader "$_bp_i" 2>&1 | "$REDACT")"
      if grep -qi 'User PIN locked' <<< "$_bp_info"; then
        _bp_t="locked"
      else
        _bp_t="$(grep -oE 'User PIN tries left *: *[0-9]+' <<< "$_bp_info" | grep -oE '[0-9]+$' | head -1)"
      fi
      _bp_tag=""
      [ -n "$_bp_ser" ] && [ "$_bp_ser" = "$EXPECT_SERIAL" ] && _bp_tag=" <- pinned"
      note "reader $_bp_i  serial ${_bp_ser:-UNREADABLE}  user-PIN tries: ${_bp_t:-UNREADABLE}$_bp_tag"
      case "$_bp_t" in
        locked)        _bp_risk="$_bp_risk reader$_bp_i=${_bp_ser:-?}:locked" ;;
        ''|*[!0-9]*)   _bp_risk="$_bp_risk reader$_bp_i=${_bp_ser:-?}:unreadable" ;;
        *) [ "$_bp_t" -lt "$MIN_PIN_TRIES" ] && _bp_risk="$_bp_risk reader$_bp_i=${_bp_ser:-?}:$_bp_t" ;;
      esac
    done
    if [ "$_bp_seen" -eq 0 ]; then
      fail hw_bench_pins "no PC/SC readers were enumerated, so no card's retry counter was recorded"
    elif [ -z "$_bp_risk" ]; then
      pass hw_bench_pins "$_bp_seen card(s) censused, all at or above the floor of $MIN_PIN_TRIES"
    elif [ "$TIER" = gate ]; then
      # The gate spends no PINs and runs no scsh child, so it cannot reach the card at risk. Record
      # the reading and stay green: failing here would block every non-destructive run on the state
      # of a card this tier never touches.
      pass hw_bench_pins "$_bp_seen card(s) censused; at or below the floor:$_bp_risk (recorded — the gate spends no PINs)"
      note "a destructive tier WILL refuse on this, because its scsh children can reach that card"
    else
      CARD_PINNED=0
      fail hw_bench_pins "a card on this bench is at or below the PIN floor of $MIN_PIN_TRIES:$_bp_risk. A destructive tier selects readers through scsh, which matches by name PREFIX and can reach a card this battery is not pinned to, so the floor must hold for EVERY attached card before anything spends a PIN."
    fi
  fi
fi

if tier_admits hw_devaut; then
  hdr "hw_devaut — $(step_desc hw_devaut)"
  if [ "$CARD_READABLE" != 1 ]; then hw_guard hw_devaut; else
    # ACQUIRE C.DevAut FROM THE CARD WE ARE PINNED TO.
    #
    # This used the Smart Card Shell, which selects a reader by NAME and matches by prefix. With
    # two cards attached the provisioned card's reader name ("...Pico Key CCID Interface") is a
    # strict PREFIX of the other's ("...Pico Key CCID Interface 01"), so every name that matches
    # the one we want also matches the one we do not, and the other is enumerated first.
    # Measured 2026-09-03: passing the exact full name of the target still returned the OTHER
    # card's certificate. scsh cannot address this card while both are attached — it is not a
    # matter of passing the right string.
    #
    # opensc-explorer takes -r <index> and was measured the same day to return genuinely
    # different blobs per reader (sha 31603958… vs 4dcddb97…). So read it there, and keep scsh
    # only as the fallback for hosts where opensc-explorer is missing.
    dlog="$RUN_DIR/devaut.txt"
    DHEX=""; DSHA=""
    _devaut_src=""
    if command -v opensc-explorer >/dev/null 2>&1; then
      _bin="$RUN_DIR/devaut.bin"
      printf 'get 2F02 %s\nquit\n' "$_bin" > "$RUN_DIR/devaut.explorer.in"
      opensc-explorer -r "$READER" < "$RUN_DIR/devaut.explorer.in" 2>&1 | "$REDACT" > "$dlog"
      if [ -s "$_bin" ]; then
        DHEX="$(xxd -p "$_bin" | tr -d '\n' | tr 'a-f' 'A-F')"
        DSHA="$(shasum -a 256 "$_bin" | awk '{print $1}')"
        _devaut_src="opensc-explorer -r $READER"
      fi
    fi
    if [ -z "$DHEX" ]; then
      SCSH="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}"
      if [ ! -x "$SCSH/scriptrunner" ]; then
        fail hw_devaut "opensc-explorer could not read EF 2F02 and there is no Smart Card Shell at $SCSH — device identity CANNOT BE EVALUATED"
        _devaut_done=1
      else
        _scsh_reader=""
        [ "$TARGETED" = 1 ] && _scsh_reader="$(hsm_reader_name "$READER")"
        ( cd "$SCSH" && HSM_SCSH_READER="$_scsh_reader" ./scriptrunner "$HERE/hsm-devaut-id.js" ) 2>&1 | "$REDACT" >> "$dlog"
        _devaut_src="scsh (fallback — reader selection is prefix-matched and may be wrong)"
      fi
    fi
    if [ "${_devaut_done:-0}" = 1 ]; then :; else
      [ -n "$DHEX" ] || DHEX="$(grep -a '^DEVAUT_HEX=' "$dlog" | head -1 | cut -d= -f2-)"
      [ -n "$DSHA" ] || DSHA="$(grep -a '^DEVAUT_SHA256=' "$dlog" | head -1 | cut -d= -f2-)"
      DSHA="$(printf '%s' "$DSHA" | tr 'A-F' 'a-f')"
      if [ -z "$DHEX" ]; then
        fail hw_devaut "no DEVAUT_HEX in the scsh readout — $(tail -1 "$dlog")"
      else
        printf '%s' "$DHEX" > "$RUN_DIR/devaut.hex"
        # The AUTHORITATIVE parse: a real TR-03110 decode, not the tag-substring search in the
        # .js. --require-external-car is deliberately NOT passed: the Pico is self-signed and
        # that is a known, documented staging fact, asserted below rather than treated as a bug.
        cvcargs=(--hex "$RUN_DIR/devaut.hex")
        [ -n "${HSM_CI_TRUST_DIR:-}" ] && cvcargs+=(--trust-dir "$HSM_CI_TRUST_DIR")
        if [ -n "${HSM_CI_EXPECT_CHR:-}" ]; then
          cvcargs+=(--expect-chr "$HSM_CI_EXPECT_CHR")
        elif [ "$TARGETED" = 1 ] && [ -n "$EXPECT_SERIAL" ]; then
          # Derived, not configured: a certificate from the other card cannot satisfy this.
          cvcargs+=(--expect-chr "${EXPECT_SERIAL}00001")
        fi
        [ -n "${HSM_CI_EXPECT_DEVAUT_SHA:-}" ] && cvcargs+=(--expect-sha256 "$HSM_CI_EXPECT_DEVAUT_SHA")
        cvcout="$(python3 "$HERE/cvc-devaut-verify.py" "${cvcargs[@]}" 2>&1)"; cvcrc=$?
        printf '%s\n' "$cvcout" > "$RUN_DIR/cvc-verify.log"
        if [ "$cvcrc" = 0 ]; then
          chr="$(printf '%s' "$cvcout" | grep -a '^CVC_CHR=' | cut -d= -f2-)"
          car="$(printf '%s' "$cvcout" | grep -a '^CVC_CAR=' | cut -d= -f2-)"
          chain="$(printf '%s' "$cvcout" | grep -a '^CVC_CHAIN=' | cut -d= -f2-)"
          pass hw_devaut "CHR=$chr CAR=$car chain=$chain sha256=${DSHA:0:16}…"
        else
          # Prefer the verifier's own "FAILED:" line over `tail -1`. stdout and stderr interleave
          # unpredictably in a command substitution, so tail picked up whichever CVC_* line
          # happened to land last — reporting "CVC_SHA256=475ae1…" where the actual reason was
          # "DIGEST MISMATCH". The evidence column has to carry the reason, not a bystander.
          # rc=2 is the verifier's documented "operator/input error" — missing file, bad flags,
          # pycvc not installed. That is NOT the same claim as "this certificate is bad", and
          # saying so sends whoever reads the gate hunting a device problem that does not exist.
          # The gate still FAILS (it is fail-closed and an unverified cert must not pass), but
          # the reason has to name the real cause. Seen for real on 2026-08-06, when Homebrew
          # moved python3 to 3.14 and orphaned the site-packages that held pycvc.
          if [ "$cvcrc" = 2 ]; then
            why="$(printf '%s' "$cvcout" | grep -aiE 'ERROR|not importable' | head -1)"
            fail hw_devaut "the offline CVC verifier could NOT RUN (rc=2, host/tooling problem — the certificate was never evaluated) — ${why:-$(printf '%s' "$cvcout" | tail -1)}"
          else
            why="$(printf '%s' "$cvcout" | grep -a 'FAILED:' | head -1)"
            fail hw_devaut "offline CVC verification failed (rc=$cvcrc) — ${why:-$(printf '%s' "$cvcout" | tail -1)}"
          fi
        fi
      fi
    fi   # end of the acquisition guard
  fi
fi

if tier_admits hw_sign; then
  hdr "hw_sign — $(step_desc hw_sign)"
  if [ "$CARD_READABLE" != 1 ]; then hw_guard hw_sign
  elif [ "$CARD_PINNED" != 1 ]; then
    fail hw_sign "the card has not proven which device it is — refusing to spend a PIN attempt on its retry counter"
  else
    PUB="${HSM_CI_EXPECT_PUB:-$STAGING/expected-pub.der}"
    VERIFY="$HERE/verify-hsm-control.py"
    if [ ! -f "$PUB" ]; then
      # Not a skip. The gate's whole job is to notice that the card stopped holding the key it
      # was provisioned with; with nothing pinned it cannot notice anything.
      fail hw_sign "no pinned public key at $PUB — the gate cannot prove the card still holds its key (set HSM_CI_EXPECT_PUB, or run --tier nightly to provision)"
    else
      w="$(mktemp -d)"; chmod 700 "$w"
      head -c 32 /dev/urandom > "$w/d.bin"
      t0="$(now)"
      # A DIAGNOSTIC MUST NOT BE ABLE TO LOCK THE CARD.
      #
      # This login SPENDS a user-PIN retry whenever the PIN is wrong, and the card ships with a
      # floor of 3. MEASURED 2026-08-08: a nightly ran with hw_pin_health already FAILED ("the
      # retry counter is UNREADABLE") and this step logged in anyway, returning CKR_PIN_LOCKED —
      # the monitoring job walking the card toward the state it exists to detect. The warning
      # below said so in words while the code did it anyway.
      #
      # So gate on the counter having been READ and found above the floor. Without that, skip:
      # not knowing how many tries remain is precisely when you must not spend one.
      if [ "$PIN_SPEND_OK" != 1 ]; then
        skip hw_sign "the user-PIN retry counter is not known-healthy (see hw_pin_health) — refusing to spend a retry to find out"
      elif pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$USER_PIN" --sign \
           --mechanism ECDSA --id "${HSM_CI_KEY_ID:-31}" \
           --input-file "$w/d.bin" --output-file "$w/s.bin" 2>&1 | "$REDACT" >"$w/sign.log" \
         && python3 "$VERIFY" --der "$PUB" --digest "$w/d.bin" --sig "$w/s.bin" 2>&1 | "$REDACT" >>"$w/sign.log"; then
        pass hw_sign "signed a fresh random digest; it verifies against the pinned public key" "$(( $(now) - t0 ))"
      else
        cp "$w/sign.log" "$RUN_DIR/hw_sign.log" 2>/dev/null
        # `tail -1` reports pkcs11-tool's "Aborting." and buries the line that says why — seen for
        # real on 2026-08-06, where the actual cause (CKR_PIN_INCORRECT) sat one line above it.
        # Prefer the line naming the failure, the same way the CVC branch prefers FAILED:.
        why="$(grep -aiE 'CKR_[A-Z_]+|error:|FAILED:' "$w/sign.log" | head -1)"
        why="${why:-$(tail -1 "$w/sign.log")}"
        # A wrong PIN is not just a failed step: it SPENDS a retry, every run. At the default floor
        # of 3 tries a handful of gate runs would lock the user PIN and take the card out of
        # service — a monitoring job destroying the thing it monitors. Say so where it will be read.
        if grep -qa 'CKR_PIN_INCORRECT' "$w/sign.log"; then
          fail hw_sign "the configured user PIN is WRONG for this card — this run SPENT a PIN retry; fix HSM_USER_PIN before re-running or the gate will lock the card ($why)" "$(( $(now) - t0 ))"
        else
          fail hw_sign "sign-or-verify FAILED against the pinned key — $why" "$(( $(now) - t0 ))"
        fi
      fi
      rm -rf "$w"
    fi
  fi
fi
# THE YUBIKEY HALF OF THE BENCH (#30: scheduled hardware jobs cover the pinned Nitrokey AND YubiKey
# models). Until this step the battery exercised only the Picos, while a YubiKey 5C NFC sat on the same
# bus with nothing scheduled against it. It runs the repository's own read-only physical qualification
# (kms/internal/backend/yubikey/piv_physical_test.go) against HSM_CI_YUBIKEY_SERIAL: identity, 9A
# policy, the retry counter (an empty VERIFY, which spends no attempt) and a parseable public key.
#
# IT NEVER PRESENTS A PIN. That test logs in and signs only when REGALIA_PIV_PIN is set, so the child
# runs with it removed from its environment whatever the job's environment holds. A gate that could
# spend a YubiKey PIN attempt on every push would be the #442 hazard scheduled.
#
# PASS REQUIRES THE TEST TO HAVE RUN. The test SKIPs itself when its serial is unset, and a skipped Go
# test exits 0. Reading the exit code alone would turn "nothing was checked" into PASS, so this also
# requires the literal `--- PASS: TestPIVPhysicalReadOnlyQualification` line.
if tier_admits hw_yubikey_piv; then
  hdr "hw_yubikey_piv — $(step_desc hw_yubikey_piv)"
  _yk_serial="${HSM_CI_YUBIKEY_SERIAL:-}"
  if [ "$ALLOW_NO_HW" = 1 ]; then
    skip hw_yubikey_piv "NO-HARDWARE: --allow-no-hardware — the YubiKey PIV qualification was not run"
  elif [ -z "$_yk_serial" ]; then
    skip hw_yubikey_piv "no YubiKey is pinned — set HSM_CI_YUBIKEY_SERIAL to the staging YubiKey's serial to schedule its PIV qualification"
  elif ! command -v go >/dev/null 2>&1; then
    fail hw_yubikey_piv "a YubiKey is pinned ($_yk_serial) but go is not on PATH — the PIV qualification CANNOT BE EVALUATED"
  elif [ ! -f "${HSM_CI_KMS_DIR:-$REPO/kms}/go.mod" ]; then
    # A seam for the same reason HSM_READER_SELECT has one: the harness runs this file from a copied
    # tree. Without the explicit check a missing module dir surfaced as "rc=1" with no reason at all.
    fail hw_yubikey_piv "a YubiKey is pinned ($_yk_serial) but no Go module at ${HSM_CI_KMS_DIR:-$REPO/kms} — the PIV qualification CANNOT BE EVALUATED"
  else
    _yk_out="$( (cd "${HSM_CI_KMS_DIR:-$REPO/kms}" && env -u REGALIA_PIV_PIN REGALIA_PIV_SERIAL="$_yk_serial" \
                  go test -count=1 -tags piv -v -run '^TestPIVPhysicalReadOnlyQualification$' ./internal/backend/yubikey/) 2>&1 | "$REDACT")"
    _yk_rc=$?
    if [ "$_yk_rc" = 0 ] && grep -qE '^--- PASS: TestPIVPhysicalReadOnlyQualification( |$)' <<< "$_yk_out"; then
      pass hw_yubikey_piv "YubiKey $_yk_serial: 9A is PIN-once/touch-never, the retry counter reads, the public key parses (no PIN presented)"
    elif grep -qE '^--- SKIP: TestPIVPhysicalReadOnlyQualification' <<< "$_yk_out"; then
      fail hw_yubikey_piv "the PIV qualification SKIPPED itself although $_yk_serial is pinned — nothing was checked, and that is not a pass"
    else
      fail hw_yubikey_piv "YubiKey $_yk_serial failed the read-only PIV qualification (rc=$_yk_rc): $(grep -m1 -E 'piv_physical_test\.go:[0-9]+:|cannot|no such|unavailable' <<< "$_yk_out" | sed 's/^[[:space:]]*//' | cut -c1-200)"
    fi
  fi
fi

# =================================================================================================
# DESTRUCTIVE. Gated on the card having proven it is the pinned staging device. This is the
# single most important conditional in the file: a serial mismatch, an ATR mismatch, or a
# near-locked PIN counter all leave CARD_PINNED clear, and nothing below may write to the card.
DESTRUCTIVE_ADMITTED=0
if [ "$TIER" = nightly ] || [ "$TIER" = soak ]; then
  hdr "DESTRUCTIVE GATE"
  if [ "$CARD_PINNED" = 1 ]; then
    DESTRUCTIVE_ADMITTED=1
    printf '  the attached card proved it is the pinned staging device (%s).\n' "$SERIAL"
    printf '  \033[33mEVERYTHING BELOW WIPES IT.\033[0m Staging material only — never point this at a card that matters.\n'
  else
    printf '  \033[31mthe card did not prove it is the pinned staging device — every destructive\n'
    printf '  step below is FAILED, not skipped. A destructive battery that did not run is not a pass.\033[0m\n'
  fi
fi

destructive_blocked(){ # $1=id
  fail "$1" "blocked by the destructive gate — the card is not the proven pinned staging device"
}

if tier_admits e2e_phases; then
  if [ "$DESTRUCTIVE_ADMITTED" = 1 ]; then
    HSM_PKCS11_MODULE="$P11" HSM_E2E_SERIAL="$EXPECT_SERIAL" HSM_SLOT="$SLOT" \
      run_child e2e_phases "$HERE/hsm-staging-e2e.sh"
  else destructive_blocked e2e_phases; fi
fi

if tier_admits e2e_scenarios; then
  if [ "$DESTRUCTIVE_ADMITTED" = 1 ]; then
    HSM_PKCS11_MODULE="$P11" HSM_USER_PIN="$USER_PIN" HSM_STAGING_DIR="$STAGING" \
      run_child e2e_scenarios "$REPO/tools/hsm-scenarios.sh"
  else destructive_blocked e2e_scenarios; fi
fi

if tier_admits e2e_recovery; then
  if [ "$DESTRUCTIVE_ADMITTED" = 1 ]; then
    # OFFER THE SECOND CARD WHEN IT CAN ACTUALLY BE USED. Without --cust the drill's STEP 2
    # (custodian-rotation rehearsal, requirement C5's open Verify step) records UNVERIFIED on every
    # run — a permanently unevaluated arm inside a suite that reports 26 passed. A bench with two
    # cards attached can perform it, so not passing the flag is a gap, not a property of the bench.
    #
    # But only when the custodian reader is scsh-ADDRESSABLE. The drill's custodian key import goes
    # through hsm-import-key.sh, which matches reader names by prefix, so handing it the prefix-named
    # card would aim the import at the WRONG device (#398). The drill refuses that early now; the
    # battery simply does not offer it, so the arm stays a truthful skip instead of a red step on a
    # topology limit nothing here can change.
    _rc_cust_slot=""; _rc_cust_reader=""
    if command -v hsm_reader_indices >/dev/null 2>&1; then
      for _rc_i in $(hsm_reader_indices 2>/dev/null); do
        [ "$_rc_i" = "$READER" ] && continue
        command -v hsm_reader_scsh_addressable >/dev/null 2>&1 \
          && ! hsm_reader_scsh_addressable "$_rc_i" && continue
        _rc_ser="$(hsm_serial_at_reader "$_rc_i" 2>/dev/null || true)"
        [ -n "$_rc_ser" ] || continue                 # an unreadable reader is not a usable custodian
        [ "$_rc_ser" = "$EXPECT_SERIAL" ] && continue # never nominate the pinned card as its own custodian
        _rc_id="$(hsm_slot_id_for "$_rc_ser" 2>/dev/null || true)"
        [ -n "$_rc_id" ] || continue
        _rc_cust_slot="$_rc_id"; _rc_cust_reader="$_rc_i"
        note "custodian stand-in: $_rc_ser at PC/SC reader $_rc_i, PKCS#11 slot id $_rc_id — STEP 2 will be PERFORMED"
        break
      done
    fi
    HSM_PKCS11_MODULE="$P11" HSM_CUST_PCSC_INDEX="$_rc_cust_reader" \
      run_child e2e_recovery "$HERE/hsm-recovery-drill.sh" --run --slot "$SLOTID" --reader "$READER" --auto \
        ${_rc_cust_slot:+--cust "$_rc_cust_slot"}
  else destructive_blocked e2e_recovery; fi
fi

if tier_admits e2e_fleet; then
  hdr "e2e_fleet — $(step_desc e2e_fleet)"
  if [ "$DESTRUCTIVE_ADMITTED" != 1 ]; then
    destructive_blocked e2e_fleet
  elif [ -z "${HSM_CI_SERIAL_B:-}" ]; then
    # A loud, reasoned skip: the two-device properties genuinely need two devices, and faking
    # them on one card is exactly what the fleet drill's own header refuses to do.
    skip e2e_fleet "no second card (set HSM_CI_SERIAL_B) — A3/A5/A6/A7 stay MODELLED, not performed"
  elif [ -z "${HSM_CI_PROBE_A:-}" ] || [ -z "${HSM_CI_PROBE_B:-}" ]; then
    # NOT a soft skip: with two cards attached, the drill's scsh steps CANNOT address a card whose
    # PC/SC reader name is a prefix of the other's, and one always is ("…CCID Interface" vs
    # "…CCID Interface 01"). The drill works around that by holding the other card in reset over
    # SWD, which needs a probe per board. Without them it would run and quietly operate on the
    # wrong device — so refuse rather than produce a result nobody can trust.
    fail e2e_fleet "two cards are present but HSM_CI_PROBE_A/HSM_CI_PROBE_B are unset — the drill cannot address a specific card without them, and would target the wrong one"
  else
    # Cards named by SERIAL, not by index: taking one off the bus renumbers PC/SC and can move
    # PKCS#11 slot ids, so any index captured beforehand is stale by the time it is used.
    #
    # NOTE THE DELIBERATE CROSSOVER. The drill's "A" is the card it manipulates hardest (it is the
    # one initialised with PKA and registered against), so the SECOND card takes that role and the
    # pinned staging card takes "B". Hence a-serial=HSM_CI_SERIAL_B / b-serial=$EXPECT_SERIAL.
    # HSM_CI_PROBE_A is the probe on the PINNED card, HSM_CI_PROBE_B the probe on the second one.
    HSM_PKCS11_MODULE="$P11" \
      run_child e2e_fleet "$HERE/hsm-fleet-drill.sh" --run --auto \
        --a-serial "$HSM_CI_SERIAL_B" --a-probe "$HSM_CI_PROBE_B" \
        --b-serial "$EXPECT_SERIAL"   --b-probe "$HSM_CI_PROBE_A"
  fi
fi


if tier_admits soak_cycles; then
  if [ "$DESTRUCTIVE_ADMITTED" = 1 ]; then
    HSM_PKCS11_MODULE="$P11" HSM_USER_PIN="$USER_PIN" HSM_STAGING_DIR="$STAGING" \
      run_child soak_cycles "$REPO/tools/hsm-cycle-test.sh" --cycles "$SOAK_CYCLES" --full
  else destructive_blocked soak_cycles; fi
fi

if tier_admits hw_wedge_recov; then
  hdr "hw_wedge_recov — $(step_desc hw_wedge_recov)"
  # A RECOVERY PATH THAT HAS NEVER RUN IS NOT A CAPABILITY. ensure_card() clears a wedge between
  # steps, but on a healthy bench that branch never executes — it is untested code sitting on the
  # error path, which is the path least likely to work when it finally matters. This step wedges
  # the card ON PURPOSE and proves the whole chain: detect, confirm the token is RP-series silicon
  # (a Nitrokey HSM 2 has no debug port and must NOT be "recovered"), pick the probe bound to that
  # specific board, clear it, and see the card answer again.
  #
  # NIGHTLY AND SOAK, and placed LAST among the destructive steps — immediately before
  # posture_restore. Nightly is the tier CI actually runs, so leaving recovery unproven there left it
  # unproven where it matters most; every ensure_card() call in a nightly depends on this path.
  #
  # Three constraints make that safe, and they are the whole reason this can sit in nightly:
  #   * it has its OWN step id, so a deliberate wedge is never read as a spontaneous one;
  #   * it is EXCLUDED from RECOVER_COUNT, so the test cannot poison its own threshold (D3);
  #   * it runs immediately before posture_restore, so AT MOST ONE step can inherit a failed
  #     recovery — and that step's job is to prove the bench is healthy, so a red there is correct.
  #
  # It is still barred from the gate tier, which must stay read-only.
  if [ -z "${HSM_CI_PROBE_MAP:-}" ]; then
    skip hw_wedge_recov "no HSM_CI_PROBE_MAP — cannot prove unattended wedge recovery without a probe bound to this board"
  elif [ -z "${HSM_BOARD_MAP:-}" ]; then
    skip hw_wedge_recov "no HSM_BOARD_MAP — the token serial cannot name a board on its own, so there is nothing to aim the ladder at (set HSM_CI_BOARD_MAP or HSM_CI_BOARD_A)"
  else
    run_child hw_wedge_recov "$REPO/tools/hsm-wedge-recovery-test.sh" \
      --serial "$EXPECT_SERIAL" --probe-map "$HSM_CI_PROBE_MAP" --board-map "$HSM_BOARD_MAP"
  fi
fi

# LEAVE THE BENCH AS THE GATE EXPECTS TO FIND IT.
#
# Every destructive step above ends with the card in whatever state it finished in: a plain
# --initialize re-enables RRC, the user PIN is whatever that suite set, and the key may be at a
# different id or absent. MEASURED 2026-08-08: a full nightly finished 20/2/2 and the two failures
# were hw_rrc and hw_sign — then the NON-destructive gate, run straight afterwards on the same
# card, failed the identical two. A nightly was leaving the bench unable to pass its own gate.
#
# That is worse than it sounds. Both failures read like device problems: "the D3 posture is NOT in
# force" and "the card no longer signs for the pinned public key" are exactly what a real
# regression would look like, so the next person spends their time on the card instead of on the
# harness. And hw_sign spends a user-PIN retry every time it runs against the wrong PIN, so the
# state degrades with each attempt to diagnose it.
#
# Restoring the posture is a step, not a hidden side effect: it is reported in the summary like
# everything else, so a restore that fails is visible rather than leaving a silently broken bench.
if tier_admits posture_restore; then
  hdr "posture_restore — $(step_desc posture_restore)"
  if [ "$DESTRUCTIVE_ADMITTED" = 1 ]; then
    HSM_PKCS11_MODULE="$P11" HSM_USER_PIN="$USER_PIN" HSM_STAGING_DIR="$STAGING" \
      run_child posture_restore "$REPO/tools/hsm-staging-restore.sh"
  else destructive_blocked posture_restore; fi
fi


# =================================================================================================
if tier_admits recover_budget; then
  hdr "recover_budget — $(step_desc recover_budget)"
  # GREEN-WITH-WARN for 1-2, not a third CI state. CI reads green or red; an "unstable" state needs
  # dashboard support for no safety gain, since the warning is already in the result text and the
  # JUnit properties carry the rungs for trending.
  if [ "$RECOVER_FAILED" -gt 0 ]; then
    fail recover_budget "$RECOVER_FAILED recovery attempt(s) FAILED to bring $EXPECT_SERIAL back (rungs: ${RECOVER_RUNGS:-none}) — the bench needed recovery and did not get it, so any step after the first failure did not run against a working card"
  elif [ "$RECOVER_COUNT" -eq 0 ]; then
    pass recover_budget "no unscheduled recoveries — the card stayed up on its own"
  elif [ "$RECOVER_COUNT" -le "$RECOVER_BUDGET" ]; then
    pass recover_budget "WARN: $RECOVER_COUNT unscheduled recovery/recoveries (rungs: $RECOVER_RUNGS) — within the expected ~1/run at the measured 6.62% per-reboot wedge rate, but the card is NOT healthy in the sense of never wedging"
  else
    fail recover_budget "$RECOVER_COUNT unscheduled recoveries (rungs: $RECOVER_RUNGS) exceeds the budget of $RECOVER_BUDGET — at ~1 expected per run this is roughly a 3-sigma excess, so treat it as a degrading device, not noise"
  fi
fi

hdr "SUMMARY — tier $TIER"
npass=0; nfail=0; nskip=0
printf '\n  \033[1m%-32s %-7s %-6s %s\033[0m\n' "step" "result" "secs" "evidence"
printf '  %-32s %-7s %-6s %s\n' "----" "------" "----" "--------"
while IFS='|' read -r id st secs msg desc; do
  [ -n "$id" ] || continue
  case "$st" in PASS) npass=$((npass+1));; FAIL) nfail=$((nfail+1));; SKIP) nskip=$((nskip+1));; esac
  printf '  %-32s %-7s %-6s %s\n' "$id" "$st" "${secs:-0}" "$msg"
done < "$RESULTS"
printf '\n  %d passed, %d failed, %d skipped\n' "$npass" "$nfail" "$nskip"

if [ "$ALLOW_NO_HW" = 1 ]; then
  printf '\n  \033[33mNO-HARDWARE RUN.\033[0m %d hardware steps were skipped. This run is evidence about\n' "$nskip"
  printf '  the host-side suites and NOTHING ELSE. Do not record it as a staging attestation.\n'
fi
printf '\n  \033[1mD1 REMAINS OPEN.\033[0m This is a Pico standing in for the Nitrokey HSM 2; a green\n'
printf '  battery here says the PROCEDURE holds, not that the production token behaves the same.\n'
printf '  Transcript: %s\n' "$TRANSCRIPT"

[ "$nfail" -eq 0 ] || exit 1
exit 0
