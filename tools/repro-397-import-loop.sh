#!/usr/bin/env bash
# repro-397-import-loop.sh — N iterations of phase d (PKA init) then phase e (recovery drill
# --auto), with per-iteration evidence, for the 1-in-7 intermittent key-import failure (#397).
# 30 iterations on 2026-09-14 gave 0 import failures and 2 wrong DKEK shares accepted (#460).
#
# SAFETY: this loops INITIALIZE DEVICE on the staging card. It REFUSES to run without the bench
# mutex (tools/hsm-bench-lock.sh, #402) held, and restores bench posture on EVERY exit including
# abort. The pinned staging card is ESP41D722E2; any iteration where reader resolution names a
# different serial aborts the loop BEFORE the next destructive step, because an enumeration swap
# is both a finding and a safety hazard (a wipe aimed by index while another card holds the slot).
#
# EVIDENCE-FIRST: it never retries a failed import. One real failure's log is the assignment.
# The classifier below names its distinguishing lines up front, so a failure that matches none
# of them is itself the finding.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# THE CARD IS NAMED BY THE CALLER, NEVER DEFAULTED. A default here is how a loop that wipes and
# re-provisions ends up addressing somebody else's card: the serial must come from whoever
# knows which device is scratch. Registry role still gates the wipe; this is the layer above it.
# The card this harness was written against, overridable for another bench. The wipe is
# still gated by the registry's staging role; this only decides which card it addresses.
PINNED_SERIAL="${HSM_PINNED_SERIAL:-ESP41D722E2}"
ITER="${1:-30}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/repro397.XXXXXXXX")"
LEDGER="$WORK/ledger.tsv"
LOCK_TOOL="$REPO_ROOT/tools/hsm-bench-lock.sh"

log(){ printf '%s\n' "$*" >&2; }
die(){ log "repro397: $*"; exit 1; }

# ---- posture restore on every exit path, abort included — but only once the loop has
# actually touched the bench. A refusal before the lock runs no restore at all: restoring
# posture is itself a destructive act and belongs behind the same gate.
REPRO397_TOUCHED=""
restore_posture(){
  [ -n "$REPRO397_TOUCHED" ] || { log "repro397: refused before touching the bench; no restore needed"; return 0; }
  log "repro397: restoring bench posture (exit path) — log: $WORK/restore.log"
  # NAME THE CARD. Restore once defaulted to ESP2202E14A, and this exact call, made with nothing named,
  # aimed INITIALIZE DEVICE at that card on 2026-09-14 (refused only by the prefix-name guard).
  HSM_RESTORE_SERIAL="$PINNED_SERIAL" "$REPO_ROOT/tools/hsm-staging-restore.sh" > "$WORK/restore.log" 2>&1 || \
    log "repro397: WARNING restore returned non-zero; read $WORK/restore.log before walking away"
}
trap restore_posture EXIT

# ---- self-test the instrument before spending any card cycles --------------------------------
# An empty ledger is indistinguishable from a broken harness: prove the pipeline records a row
# and the classifier matches each declared signature before the first real iteration.
# The drill's own FAIL lines are the primary evidence; the import log is read for the signature of
# an import failure. NEVER match the whole drill log: every run, passing or not, prints an UNVERIFIED
# note that "the custodian key import would reach the WRONG card", and a case-insensitive match on
# that line labelled both wrong-share acceptances of 2026-09-14 "enumeration-swap" (#460).
drill_fail_lines(){ perl -pe 's/\e\[[0-9;]*m//g' "$1" 2>/dev/null | grep -aE '^[[:space:]]*FAIL ' || true; }
classify(){
  # $1=import log, $2=drill log. Prints the cause class; "unknown" is a finding, not a bucket.
  local fails evidence
  fails="$(drill_fail_lines "$2")"
  [ -n "$fails" ] || { echo "no-fail-line"; return; }
  if grep -qaE 'ACCEPTED a wrong DKEK share' <<< "$fails"; then echo "wrong-share-accepted"; return; fi
  evidence="$fails
$(cat "$1" 2>/dev/null || true)"
  if grep -qaE '6982|6985' <<< "$evidence"; then echo "pka-leftover"
  elif grep -qaiE 'no ATR|Failed to connect|no PC/SC reader at index|CKR_DEVICE' <<< "$evidence"; then echo "enumeration-race"
  elif grep -qaE 'CKR_GENERAL_ERROR' <<< "$evidence"; then echo "store-exhaustion"
  elif grep -qaE 'REFUSING: connected to the WRONG CARD' <<< "$evidence"; then echo "enumeration-swap"
  else echo "unknown"; fi
}
classify_selftest(){
  local d="$WORK/selftest" prose
  mkdir -p "$d"
  # The exact line that caused the misclassification, as the drill prints it on every run.
  prose="  UNVERIFIED step 2 skipped — a second card IS attached (reader(s) 1 2) but reader(s) 1 cannot be addressed by Smart Card Shell: the name is a strict PREFIX of another reader's, so the custodian key import would reach the WRONG card."
  expect(){ # $1=want $2=import log text $3=drill log text
    printf '%s\n' "$2" > "$d/i"; printf '%s\n' "$3" > "$d/o"
    local got; got="$(classify "$d/i" "$d/o")"
    [ "$got" = "$1" ] || die "classifier self-test: wanted $1, got $got"
  }
  expect wrong-share-accepted "" "$(printf '  \033[31mFAIL\033[0m the card ACCEPTED a wrong DKEK share — the break-glass path has no integrity check\n%s' "$prose")"
  expect pka-leftover     "GPError 0x6982" "  FAIL key import failed"
  expect enumeration-race "Failed to connect to card" "  FAIL key import failed"
  expect store-exhaustion "CKR_GENERAL_ERROR (0x5)" "  FAIL key import failed"
  expect enumeration-swap "" "  FAIL REFUSING: connected to the WRONG CARD. Expected ESP41D722E2"
  # Only the refusal's exact wording is a swap. Prose that mentions a wrong card is not, even on a FAIL line.
  expect unknown          "" "  FAIL the custodian key import would reach the WRONG card"
  expect unknown          "something entirely novel" "$(printf '  FAIL something novel\n%s' "$prose")"
  expect no-fail-line     "" "$prose"
  rm -rf "$d"
}
classify_selftest
# The serial is required to touch the bench, and only then: the classifier self-test above runs
# with no card at all, and refusing at parse time made a card-free check depend on naming a card.
if [ "${REPRO397_SELFTEST_ONLY:-}" != "1" ] && [ -z "$PINNED_SERIAL" ]; then
  echo "REFUSING: set HSM_PINNED_SERIAL to the scratch card this loop may use" >&2
  exit 2
fi
if [ "${REPRO397_SELFTEST_ONLY:-}" = "1" ]; then
  rm -rf "$WORK"
  log "repro397: classifier self-test passed (selftest-only mode; no bench touched)"
  exit 0
fi

# ---- the bench mutex is mandatory (#402) ------------------------------------------------------
[ -f "$LOCK_TOOL" ] || die "no bench mutex at $LOCK_TOOL — #402 has not landed; the sequencing rule says no destructive runs. NOT running."
# shellcheck source=hsm-bench-lock.sh
. "$LOCK_TOOL"
HSM_BENCH_LOCK_LABEL="repro397" hsm_bench_lock_acquire wait || die "could not take the bench mutex"
# Acquire installs its own EXIT/INT/TERM traps, which would REPLACE restore_posture above. Install one
# set that restores posture first and releases the lock last, while the lock is still held.
trap 'restore_posture; hsm_bench_lock_release' EXIT
trap 'restore_posture; hsm_bench_lock_release; exit 130' INT
trap 'restore_posture; hsm_bench_lock_release; exit 143' TERM
REPRO397_TOUCHED=1

# Resolve the pinned card's PC/SC reader and PKCS#11 slot BY SERIAL. A default of index 0 is only
# correct until enumeration order moves, which is the hazard this loop's per-iteration check exists for.
# shellcheck source=hsm-reader-select.sh
. "$REPO_ROOT/tools/hsm-reader-select.sh"
READER="${READER:-$(hsm_reader_for "$PINNED_SERIAL" || true)}"
SLOTID="${SLOTID:-$(hsm_slot_id_for "$PINNED_SERIAL" || true)}"
[ -n "$READER" ] && [ -n "$SLOTID" ] || die "cannot resolve $PINNED_SERIAL to a reader and slot — not running"
P11="${HSM_PKCS11_MODULE:-${P11:-}}"
[ -n "$P11" ] || die "HSM_PKCS11_MODULE (or P11) unset — the drill needs the PKCS#11 module path"

# The serial the reader at $READER actually answers with, checked before EVERY destructive step.
# An enumeration swap is a finding AND a stop condition, never a "carry on anyway".
observed_serial(){
  # The repo's resolver, not a private parse: pkcs15-tool prints "Serial number", and the pattern
  # this used ("serial num") never matched, so every iteration read 'none' and stopped the loop.
  hsm_serial_at_reader "$READER" 2>/dev/null || true
}
require_pinned_card(){
  local serial; serial="$(observed_serial)"
  [ "$serial" = "$PINNED_SERIAL" ] || die "reader $READER answers with serial '${serial:-none}', not the pinned $PINNED_SERIAL — enumeration order moved. Stop; this is evidence, and the next wipe must not aim anywhere."
  printf '%s' "$serial"
}

pka_status(){
  sc-hsm-tool --reader "$READER" --public-key-auth-status 2>/dev/null | tr '\n' ' ' | cut -c1-160 || true
}

printf 'iter\texit\tserial\tpka_before\tclass\twhy\tdrill_log\n' > "$LEDGER"

# Phase d's end state, exactly as staging-e2e leaves it (init --public-key-auth 3
# --required-pub-keys 2), so the import runs against the same prior state the nightly's
# failing iteration had. Source the drill's own env for pins/labels where possible.
phase_d_init(){
  sc-hsm-tool --reader "$READER" --initialize --so-pin "${HSM_SO_PIN:-3537363231383830}" \
    --pin "${HSM_USER_PIN:-123456}" --dkek-shares 1 --label pka-repro \
    --public-key-auth 3 --required-pub-keys 2 > "$1" 2>&1 || true
}

i=0
while [ "$i" -lt "$ITER" ]; do
  i=$((i+1))
  serial="$(require_pinned_card)"
  dlog="$WORK/iter-$i-phased.log"; phase_d_init "$dlog"
  pka="$(pka_status)"
  # Phase e, exactly as staging-e2e invokes it — including per-iteration IMPORT_LOG so no two
  # iterations can share the default /tmp log file (a shared log is how the failing run's
  # evidence was overwritten by a passing re-run when this was first diagnosed).
  ilog="$WORK/iter-$i-import.log"
  dout="$WORK/iter-$i-drill.log"
  set +e
  IMPORT_LOG="$ilog" HSM_PKCS11_MODULE="$P11" \
    "$REPO_ROOT/ceremony/qubes/scripts/hsm-recovery-drill.sh" --run --slot "$SLOTID" --reader "$READER" --auto \
    > "$dout" 2>&1
  rc=$?
  set -e
  cls="pass"; why=""
  if [ "$rc" -ne 0 ]; then
    cls="$(classify "$ilog" "$dout")"
    why="$(drill_fail_lines "$dout" | sed -E 's/^[[:space:]]*FAIL //' | tr '\n' ';' | cut -c1-200)"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$rc" "$serial" "$pka" "$cls" "$why" "$dout" >> "$LEDGER"
  log "repro397: iteration $i/$ITER exit=$rc class=$cls ${why:+why=[$why]}"
done

log "repro397: done. ledger: $LEDGER"
log "repro397: failure histogram:"
awk -F'\t' 'NR>1 && $2 != 0 {count[$5]++} END {for (c in count) printf "  %-20s %d\n", c, count[c]}' "$LEDGER" >&2 || true
