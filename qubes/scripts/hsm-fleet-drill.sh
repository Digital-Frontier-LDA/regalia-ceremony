#!/usr/bin/env bash
# hsm-fleet-drill.sh — drill the TWO-DEVICE fleet properties on real hardware.
#
# THE QUESTION IT ANSWERS. A1/A2/A4/B4 were drilled on ONE card on 2026-07-31: wipe it, re-import
# from the seed alone, same address. That proved replacement does not need the original device's
# STATE. It could not prove replacement works on a DIFFERENT PIECE OF HARDWARE, because the same
# physical card was wiped and reused — there was only one. Everything two-device (A3, A5, A6, A7)
# has been MODELLED in the emulator and never performed.
#
# This is that drill. It provisions two physically distinct cards INDEPENDENTLY from one seed and
# asserts the properties the fleet design rests on:
#
#   A3/A5  both devices reach the SAME address under DIFFERENT DKEKs — no shared DKEK domain
#   A6     each device has its OWN user PIN; B's PIN is REFUSED by A, and the retry counters
#          are independent (3 guesses per card against DIFFERENT secrets, not 6 against one)
#   A7     the failover is MEASURED, not estimated — seconds from "A is gone" to "B has signed"
#   A4     B is provisioned without consulting A's state at all
#   B4     the DKEK is disposable: two unrelated DKEKs, one address
#
# NOT THE CLONE PATH. ceremony.sh's HSM_B_* path rebuilds the SAME DKEK domain on device B from
# dkek.pbe. That is the OPTION A path, and it is correct when the key is born in the HSM and the
# wrapped blob is the only backup. Under OPTION B — seed-authoritative, which is what this project
# chose — cloning is unnecessary and strictly worse: it makes a DKEK share travel between sites,
# and PIN + DKEK together export every key on a token. Here each device imports from the seed
# under a DKEK it generates locally and never shares. Nothing sensitive moves between sites.
#
# WHAT IT CANNOT PROVE. These are Pico HSMs. They are an open-source SmartCard-HSM
# reimplementation on a microcontroller, used here as a STAND-IN for the production Nitrokey
# HSM 2. Passing this drill says the PROCEDURE is sound and the fleet properties hold for the
# SmartCard-HSM protocol. It says nothing about the Nitrokey's silicon, its key limits, its
# deletion semantics, or its throughput. Requirement D1 — repeat on the production token — stays
# open no matter how green this run is. Do not let a green fleet drill retire it.
#
#   hsm-fleet-drill.sh --check                     # what is attached; NO WRITES
#   hsm-fleet-drill.sh --run --a 0 --b 1           # the full drill (WIPES BOTH CARDS)
#   hsm-fleet-drill.sh --failover --a 0 --b 1      # just the A7 timing, on provisioned cards
#   hsm-fleet-drill.sh --pka --a 0 --b 1           # PLAN 1.4 completion: enrol 2-of-3 PKA on A,
#                                                  # power-cycle, RRC-vs-PKA, MEASURED re-auth time
#                                                  # (WIPES BOTH CARDS; B is the custodian stand-in)
#
# THE --pka MODE. The 2026-08-01 probe (PLAN.md 1.4) established the boundary: the Pico DOES
# implement PKA (`--public-key-auth 2 --required-pub-keys 1` initialised; `--public-key-auth-status`
# works), but with ZERO custodians registered the card was still fully usable by PIN, and
# registering a custodian key needs that key exported from ANOTHER SmartCard-HSM with an on-card
# CERTIFICATE (`--export-for-pub-key-auth -i <ref>` fails "Wrong key reference … File not found"
# without one). This mode closes 1.4 at the RATIFIED threshold — 2-of-3, NOT the probe's 1-of-2:
# enrol three custodians on card A (card B stands in as the custodian token, recorded as a
# limitation), then answer the three open questions BEHAVIOURALLY — (a) does PKA actually REPLACE
# the PIN once keys are enrolled, (b) does an SO-PIN RRC reset override PKA, (c) does power-off
# clear the authenticated set — and MEASURE the 2-of-3 re-auth wall-clock that feeds the A7 RTO
# (PLAN.md 4.6). Card A is initialised with sc-hsm-tool, which hardcodes RRC ON: question (b)
# NEEDS RRC functional to be meaningful. The production posture (PKA + RRC-off via
# hsm-init-hardened.js) stays UNVERIFIED — the hardened script does not set PKA today, and whether
# PKA can be set after initialisation is untested (RUNBOOK-CUSTODIAN-ROTATION.md, step 2).
#
# NO --self-test MODE, deliberately. The emulator's sc-hsm-tool stub models no PKA verbs at all,
# and this mode's content is FIRMWARE behaviour (does auth die on power-off, does RRC override
# PKA, what does re-auth cost in wall-clock) plus physical steps (reseating, custodian tokens). A
# stub asserting any of that would be inventing the answer — the exact failure test-pka-threshold.sh
# exists to avoid. The procedural half of PKA is already pinned there.
#
# NOTHING HERE TOUCHES A REAL SEED. The mnemonic is the published BIP39 test vector with no funds,
# and the drill refuses to run against anything else. Per the standing rule, a Pico never holds a
# real key — not in staging, not "just to test".
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/verify-hsm-control.py"
DERIVE="$HERE/derive-akash-address.py"

# The published BIP39 test vector. Deliberately hardcoded rather than parameterised: a --mnemonic
# flag on a script whose main verb is `--initialize` is an invitation to point it at a real seed.
DRILL_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
DRILL_LABEL="fleet-drill-throwaway"
P11="${HSM_PKCS11_MODULE:-/usr/lib/opensc-pkcs11.so}"

# CAPTURE, THEN MATCH — never `pkcs11-tool ... | grep -q` under `pipefail`.
# grep -q quits at the first match, pkcs11-tool takes SIGPIPE and exits 141, and pipefail reports
# 141 — so the predicate reads FALSE exactly when the token appeared. Measured on sc-hsm-tool
# 2026-08-08: inverted 5/5 with pipefail, correct 5/5 without. In an `until` loop that means
# spinning to the retry ceiling and then declaring the card missing when it was there all along.
_slot_has_token(){
  local _s
  _s="$(pkcs11-tool --module "$P11" --slot "${1:?slot required}" --list-slots 2>/dev/null)"
  grep -q 'token label' <<< "$_s"
}

SO_PIN="${HSM_SO_PIN:-3537363231383830}"
PIN_A="${HSM_PIN_A:-111111}"     # per-device PINs — the whole point of A6
PIN_B="${HSM_PIN_B:-999999}"

pass=0; fail=0; unv=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
U(){ printf '  \033[33mUNVERIFIED\033[0m %s\n' "$1"; unv=$((unv+1)); }
A(){ printf '  \033[1;36mANSWER\033[0m %s\n' "$1"; }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
err(){ printf '  \033[31m!!\033[0m %s\n' "$*" >&2; }

MODE=""; SLOT_A=""; SLOT_B=""; SERIAL_A=""; SERIAL_B=""; AUTO=0; PROBE_A=""; PROBE_B=""
while [ $# -gt 0 ]; do case "$1" in
  --check|--run|--failover|--pka) MODE="${1#--}";;
  --a) SLOT_A="${2:-}"; shift;;
  --b) SLOT_B="${2:-}"; shift;;
  # Prefer naming the cards by serial. --a/--b are PC/SC reader indices, and this drill also needs
  # a PKCS#11 slot ID for each card — two different numbers. Measured 2026-09-03 with both boards
  # attached: reader 0 -> slot id 0, but reader 1 -> slot id 4. One value cannot address both, and
  # this drill WIPES what it talks to.
  # Pre-authorise the wipe, for schedulers. Without this the drill asks for "WIPE BOTH" on stdin,
  # and the nightly runs it with no terminal — so e2e_fleet could never have completed unattended
  # even once a second card was attached. Same convention as hsm-recovery-drill.sh --auto.
  --auto) AUTO=1;;
  # SWD probe per card. scsh cannot address a reader whose name is a prefix of another's, and
  # with two Pico HSMs one name always is. Given probes, each scsh step runs with the OTHER card
  # held in reset, so there is exactly one card on the bus and nothing to mis-match.
  --a-probe) PROBE_A="${2:-}"; shift;;
  --b-probe) PROBE_B="${2:-}"; shift;;
  --a-serial) SERIAL_A="${2:-}"; shift;;
  --b-serial) SERIAL_B="${2:-}"; shift;;
  -h|--help) sed -n '2,63p' "$0"; exit 0;;
  *) err "unknown argument: $1"; exit 2;;
esac; shift; done
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-bench-lock.sh"
hsm_bench_lock_acquire wait || exit $?

# Resolve both handles per card. Serial wins; otherwise fall back to the index for both, which is
# correct only where the reader index and the slot id happen to coincide.
READER_A="$SLOT_A"; SLOTID_A="$SLOT_A"
READER_B="$SLOT_B"; SLOTID_B="$SLOT_B"
_fd_rs="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-reader-select.sh"
if [ -f "$_fd_rs" ]; then
  # shellcheck source=/dev/null
  . "$_fd_rs"
  if [ -n "$SERIAL_A" ]; then
    READER_A="$(hsm_reader_for "$SERIAL_A")"   || { echo "cannot resolve --a-serial $SERIAL_A" >&2; exit 2; }
    SLOTID_A="$(hsm_slot_id_for "$SERIAL_A")"  || { echo "cannot resolve --a-serial $SERIAL_A to a slot" >&2; exit 2; }
  fi
  if [ -n "$SERIAL_B" ]; then
    READER_B="$(hsm_reader_for "$SERIAL_B")"   || { echo "cannot resolve --b-serial $SERIAL_B" >&2; exit 2; }
    SLOTID_B="$(hsm_slot_id_for "$SERIAL_B")"  || { echo "cannot resolve --b-serial $SERIAL_B to a slot" >&2; exit 2; }
  fi
fi
[ "$READER_A" != "$READER_B" ] || { echo "A and B resolve to the same reader ($READER_A) — refusing" >&2; exit 2; }

# THE ROLE REGISTRY GATE for the cards this drill WIPES BY NAME. (Slot-addressed cards are gated
# inside assert_safe_to_wipe, via their serials.) Default-deny: only serials listed 'staging' in
# the committed registry (tools/hsm-staging-registry.json) may be initialized, and an unavailable gate is
# itself a refusal — a broken checkout must not turn a two-card wipe drill into an ungated one.
if ! command -v hsm_assert_staging >/dev/null 2>&1; then
  echo "the role registry gate (tools/hsm-reader-select.sh) is unavailable — refusing to run a two-card wipe drill without it" >&2; exit 2
fi
[ -z "$SERIAL_A" ] || hsm_assert_staging "$SERIAL_A" || exit 2
[ -z "$SERIAL_B" ] || hsm_assert_staging "$SERIAL_B" || exit 2
# Backfill the original handles so the existing numeric validation and any remaining uses of
# $SLOT_A/$SLOT_B still see a value when the cards were named by serial instead of by index.
SLOT_A="$SLOTID_A"; SLOT_B="$SLOTID_B"

# The helpers below take ONE handle (a PKCS#11 slot id) because that is what most of them need.
# The few that shell out to sc-hsm-tool need a PC/SC reader index instead, and the two numbers are
# not interchangeable — measured 2026-09-03, slot ids 0 and 4 against reader indices 0 and 1.
# reader_of() is the translation, so the single-argument helper signatures can stay.
QUIESCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-quiesce.sh"
_ISOLATED=""; _ISOLATED_BOARD=""

# Hold the OTHER card off the bus so scsh has only one candidate, then re-resolve THIS card's
# handles: taking a card off the bus renumbers PC/SC readers and can move PKCS#11 slot ids, so
# anything captured beforehand is stale by the time the isolated step runs.
isolate_begin(){ # $1 = serial of the card to KEEP
  local other_probe="" other_serial="" waited=0
  case "$1" in
    "$SERIAL_A") other_probe="$PROBE_B"; other_serial="$SERIAL_B" ;;
    "$SERIAL_B") other_probe="$PROBE_A"; other_serial="$SERIAL_A" ;;
  esac
  [ -n "$other_probe" ] && [ -x "$QUIESCE" ] || return 0

  # NAME THE BOARD WE ARE HALTING. hsm-quiesce.sh requires --expect-board and refuses without it:
  # halting a board without proving which one it is can take down the card we meant to KEEP. The id
  # is supplied by HSM_BOARD_MAP, never inferred from the serial.
  local other_board=""
  if command -v hsm_board_for_token >/dev/null 2>&1; then
    other_board="$(hsm_board_for_token "$other_serial" 2>/dev/null)" || other_board=""
  fi
  if [ -z "$other_board" ]; then
    printf '  cannot isolate: no HSM_BOARD_MAP entry for %s, so the board to hold is unproven\n' "$other_serial" >&2
    return 1
  fi
  "$QUIESCE" --probe "$other_probe" --expect-board "$other_board" hold >/dev/null 2>&1 || return 1
  _ISOLATED="$other_probe"; _ISOLATED_BOARD="$other_board"

  # VERIFY THE HOLD, NEVER ASSUME IT. hsm-quiesce.sh drives `reset halt` and announces "off the
  # bus", but a held RP2350 can stay ENUMERATED — the wedge state this bench calls "enumerated but
  # mute" — so the PC/SC reader remains listed and scsh's name-PREFIX matching still reaches the
  # wrong card. Measured 2026-09-03: this returned success while the other card was still present,
  # printed "alone on the bus", and the import then hit the WRONG CARD. The identity guard in
  # hsm-auto-import.js caught it, but the drill should not have needed catching.
  #
  # Isolation is a claim about the bus, so read the bus back — and count READERS, not answers.
  # "Does the other card still reply?" is the WRONG question: a held board goes mute while staying
  # enumerated, so that check passes while PC/SC still lists two readers, which is precisely the
  # condition scsh's name-PREFIX matching cannot survive. The invariant scsh needs is ONE reader.
  local n=99
  while [ "$waited" -lt 20 ]; do
    n="$(hsm_reader_indices 2>/dev/null | grep -c .)"
    [ "$n" -le 1 ] && break
    sleep 2; waited=$((waited + 2))
  done
  if [ "$n" -gt 1 ]; then
    printf '  isolation FAILED: %s PC/SC readers are still present %ss after holding %s'"'"'s board.\n' "$n" "$waited" "$other_serial" >&2
    printf '  A held RP2350 stays ENUMERATED (mute, not gone), so the reader remains and scsh would\n' >&2
    printf '  still address it by name prefix instead of %s. Refusing rather than writing blind.\n' "$1" >&2
    isolate_end
    return 1
  fi
  ISO_READER="$(hsm_reader_for "$1")" || return 1
  ISO_SLOTID="$(hsm_slot_id_for "$1")" || return 1
  return 0
}
isolate_end(){
  [ -n "$_ISOLATED" ] || return 0
  "$QUIESCE" --probe "$_ISOLATED" --expect-board "${_ISOLATED_BOARD:-}" release >/dev/null 2>&1
  _ISOLATED=""; _ISOLATED_BOARD=""
  sleep 6
}

# ALWAYS UNWIND THE HOLD. isolate_begin takes a card off the bus; if the run dies between that and
# isolate_end — a failure, a timeout, Ctrl-C, or a kill — that card stays in reset and looks
# exactly like a hardware wedge to whoever comes next. Measured 2026-09-03: a drill killed mid
# isolation left the other card mute, and it took a probe to establish it was merely held.
trap 'isolate_end >/dev/null 2>&1 || true; hsm_bench_lock_release' EXIT INT TERM

# Which on-card key references currently hold a wrappable key.
#
# The card assigns references ITSELF and ignores the PKCS#11 --id you asked for (measured
# 2026-08-06: keys created as id 02 and 04 landed at references 1 and 2), so "the key I just
# imported is reference 2" is a guess. --wrap-key does not modify the key, so probing with it is
# a safe way to ask.
#
# NEVER PROBE ON AN UNVERIFIED PIN. Each attempt costs a PIN verification; with the correct PIN
# that is free (a successful verify resets the counter), but with a wrong one it walks the counter
# to zero — six probes locked a card outright on 2026-08-06. So confirm the PIN once, cheaply,
# and refuse to probe at all if it does not work.
wrappable_refs_on(){ # $1=reader $2=pin -> echoes references, e.g. "1 2"
  local rdr="$1" pin="$2" slotid r tmp acc=""
  slotid="$(reader_slot_of "$rdr")"
  pkcs11-tool --module "$P11" --slot "$slotid" --login --pin "$pin" --list-objects >/dev/null 2>&1 \
    || { echo "" ; return 1; }
  tmp="$(mktemp)"
  for r in 1 2 3 4 5; do
    if sc-hsm-tool --reader "$rdr" --wrap-key "$tmp" --key-reference "$r" --pin "$pin" >/dev/null 2>&1 \
       && [ -s "$tmp" ]; then acc="$acc $r"; fi
    : > "$tmp"
  done
  rm -f "$tmp"
  printf '%s' "${acc# }"
}

# reader index -> PKCS#11 slot id (the inverse of reader_of)
reader_slot_of(){
  case "$1" in
    "$READER_A") printf '%s' "$SLOTID_A" ;;
    "$READER_B") printf '%s' "$SLOTID_B" ;;
    *) printf '%s' "$1" ;;
  esac
}

reader_of(){
  case "$1" in
    "$SLOTID_A") printf '%s' "$READER_A" ;;
    "$SLOTID_B") printf '%s' "$READER_B" ;;
    *) printf '%s' "$1" ;;          # single-card hosts, where the two coincide
  esac
}
printf 'card A: reader %s slot %s%s\ncard B: reader %s slot %s%s\n' \
  "$READER_A" "$SLOTID_A" "${SERIAL_A:+ ($SERIAL_A)}" "$READER_B" "$SLOTID_B" "${SERIAL_B:+ ($SERIAL_B)}"
[ -n "$MODE" ] || { sed -n '2,63p' "$0"; exit 2; }

# =================================================================================================
# GUARDS. The catastrophic operation in this script is `--initialize` aimed at the wrong reader.
# With two cards attached that is not a hypothetical: it is one transposed digit, and it destroys
# a card that may hold something. Every guard below exists because the cost of the mistake is not
# symmetric with the cost of the check.
# =================================================================================================
require_two_distinct_slots(){
  case "$SLOT_A" in ""|*[!0-9]*) err "--a must be a numeric slot (got: '${SLOT_A}')"; return 1;; esac
  case "$SLOT_B" in ""|*[!0-9]*) err "--b must be a numeric slot (got: '${SLOT_B}')"; return 1;; esac
  # No defaulting. A default of "slot 0" would silently target whichever card enumerated first.
  if [ "$SLOT_A" = "$SLOT_B" ]; then
    err "--a and --b are the same slot ($SLOT_A). This drill exists to prove TWO DEVICES agree;"
    err "running it against one card would pass while proving nothing."
    return 1
  fi
  return 0
}

# SLOT-AWARE. `--list-slots` prints EVERY slot regardless of --slot, so `head -1` returns
# whichever card is listed first — not the one asked for. This function feeds the DESTRUCTIVE
# confirmation ("THIS WILL WIPE ... serials X / Y"), so a wrong answer here means the operator
# confirms a wipe of a device they were not shown. Measured 2026-09-03 with two cards attached.
slot_serial(){
  if command -v hsm_serial_at_slot_id >/dev/null 2>&1; then hsm_serial_at_slot_id "$1"; return; fi
  pkcs11-tool --module "$P11" --slot "$1" --list-slots 2>/dev/null | grep -oE 'serial num *: *[A-Za-z0-9]+' | head -1 | awk '{print $NF}'
}

# A card is safe to wipe only if it is blank, or holds nothing but this drill's own throwaway key.
# Anything else — any label we do not recognise — stops the drill. "Probably fine" is not a state.
assert_safe_to_wipe(){ # $1=slot $2=name
  local slot="$1" name="$2" objs
  # THE ROLE REGISTRY GATE. A card that NAMES a token serial must be registered staging in the
  # committed registry (default-deny). A card with NO serial is blank, and blank stays governed
  # by the content rule below — the registry has jurisdiction only over cards with identity.
  local _ser=""
  command -v slot_serial >/dev/null 2>&1 && _ser="$(slot_serial "$slot")"
  if [ -n "$_ser" ] && command -v hsm_assert_staging >/dev/null 2>&1; then
    hsm_assert_staging "$_ser" || return 1
  fi
  objs="$(pkcs11-tool --module "$P11" --slot "$slot" --list-objects 2>/dev/null)" || {
    err "$name (slot $slot): could not enumerate objects."
    err "REFUSING. An enumeration that FAILED is not the same as a card that is EMPTY, and"
    err "treating the two alike is how a live card gets wiped."
    return 1
  }
  local labels; labels="$(printf '%s' "$objs" | grep -oE 'label: *.*' | sed 's/label: *//' | sort -u)"
  if [ -z "$labels" ]; then
    printf '  %s (slot %s): blank\n' "$name" "$slot"; return 0
  fi
  local bad=0
  while IFS= read -r l; do
    [ -z "$l" ] && continue
    [ "$l" = "$DRILL_LABEL" ] || { err "$name (slot $slot) holds an object labelled '$l'"; bad=1; }
  done <<<"$labels"
  if [ "$bad" = 1 ]; then
    err "REFUSING to wipe $name. It holds something that is not this drill's throwaway key."
    err "If that is genuinely disposable, remove it deliberately and re-run — do not make this"
    err "script guess which of your cards matters."
    return 1
  fi
  printf '  %s (slot %s): holds only %s (safe)\n' "$name" "$slot" "$DRILL_LABEL"; return 0
}

confirm(){
  printf '\n\033[1;31m  THIS WILL WIPE BOTH CARDS (slots %s and %s), serials %s / %s.\033[0m\n' \
    "$SLOT_A" "$SLOT_B" "$(slot_serial "$SLOT_A")" "$(slot_serial "$SLOT_B")"
  if [ "$AUTO" = 1 ]; then
    printf '  \033[1;31mAUTO: proceeding — pre-authorised by --auto, not prompting.\033[0m\n'
    return 0
  fi
  printf '  Type WIPE BOTH to proceed: '
  local ans; IFS= read -r ans
  [ "$ans" = "WIPE BOTH" ] || { err "not confirmed — nothing was written"; return 1; }
}

# =================================================================================================
hdr "Attached devices"
# A MISSING MODULE AND A MISSING CARD ARE DIFFERENT PROBLEMS, and this reported the second as the
# first. Under `pipefail` the grep returns 1 whenever no slot lines match — which is exactly what
# happens when the card is absent — so a wedged or unplugged device produced "no PKCS#11 module at
# /opt/homebrew/lib/opensc-pkcs11.so", sending the reader to check a library that was fine all
# along. Seen for real in the 2026-08-07 nightly, where e2e_recovery failed in 0 s with that
# message while the module was present and the card was simply off the bus.
# VALIDATE THE ARGUMENTS BEFORE PROBING THE ENVIRONMENT.
#
# `--a 1 --b 1` is wrong on its face and needs no hardware to detect, but the check for it lived
# behind the module probe below, so an invalid invocation reported "no PKCS#11 module" instead. Two
# costs: the message sends the reader to fix a library that is fine, and — the reason this matters —
# the guard that stops the drill running against ONE card, passing every assertion while proving
# nothing about two devices agreeing, was unreachable on any host without the module at that exact
# path. A safety check positioned behind an environment gate is not a safety check.
#
# Cheap checks that depend on nothing come first. Verified by
# qubes/emulator/tests/test-fleet-device-selection.sh, which had been failing on this.
if [ -n "$SLOT_A" ] && [ -n "$SLOT_B" ]; then
  require_two_distinct_slots || exit 1
fi

[ -f "$P11" ] || { err "no PKCS#11 module at $P11 — set HSM_PKCS11_MODULE"; exit 1; }
_slots="$(pkcs11-tool --module "$P11" --list-slots 2>/dev/null)"
grep -E 'Slot|serial|token label' <<< "$_slots" | sed 's/^/  /' || true
grep -q 'token label' <<< "$_slots" \
  || { err "the PKCS#11 module loaded but NO TOKEN is present — the card is not on the bus (module: $P11)"; exit 1; }

if [ "$MODE" = "check" ]; then
  hdr "Read-only check — nothing is written"
  if [ -n "$SLOT_A" ] && [ -n "$SLOT_B" ]; then
    require_two_distinct_slots || exit 1
    assert_safe_to_wipe "$SLOT_A" "device A" || true
    assert_safe_to_wipe "$SLOT_B" "device B" || true
  else
    printf '  (pass --a N --b M to check wipe-safety for specific slots)\n'
  fi
  exit 0
fi

require_two_distinct_slots || exit 1

# The address the seed derives to, computed with NO device present. This is A2, and it is also the
# oracle for everything below: if the cards do not both land here, the fleet is not coherent.
hdr "A2: derive the expected address with no device involved"
DRILL_DIR="${HSM_FLEET_DRILL_DIR:-${TMPDIR:-/tmp}/hsm-fleet-drill}"
mkdir -p "$DRILL_DIR"; chmod 700 "$DRILL_DIR"
MNF="$DRILL_DIR/drill.mnemonic"; printf '%s' "$DRILL_MNEMONIC" > "$MNF"; chmod 600 "$MNF"
EXPECT="$(python3 "$DERIVE" --mnemonic-file "$MNF" 2>/dev/null | grep -oE 'akash1[a-z0-9]+' | head -1)"
if [ -n "$EXPECT" ]; then P "seed derives offline to $EXPECT"; else
  F "offline derivation produced nothing — cannot evaluate the rest"; exit 1; fi

# ONE PKCS#12, built once from the seed and imported into BOTH devices. That is the point of the
# drill: the two cards are not copies of each other, they are two independent imports of one seed.
build_container(){
  P12="$DRILL_DIR/drill.p12"; PWF="$DRILL_DIR/drill.pw"; CERT="$DRILL_DIR/drill.crt"
  head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$PWF"; chmod 600 "$PWF"
  python3 "$HERE/seed-to-pkcs12.py" --mnemonic-file "$MNF" --password-file "$PWF" --out "$P12" >/dev/null 2>&1 || return 1
  # hsm-import-key.sh requires a certificate, and it is right to: a key without one is invisible
  # to gnupg-pkcs11-scd and ssh-keygen -D while still listing as a private key.
  openssl req -x509 -new -key <(openssl pkcs12 -in "$P12" -nocerts -nodes -passin "file:$PWF" 2>/dev/null) \
    -subj "/CN=$DRILL_LABEL" -days 1 -out "$CERT" 2>/dev/null || return 1
}

provision(){ # $1=slot $2=pin $3=name $4=serial -> echoes the DKEK KCV
  local slot="$1" pin="$2" name="$3" serial="${4:-}" work kcv pinf
  work="$(mktemp -d)"; chmod 700 "$work"
  pinf="$work/pin"; printf '%s' "$pin" > "$pinf"; chmod 600 "$pinf"
  local dkpw="$work/dkek.pw"; head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$dkpw"; chmod 600 "$dkpw"

  # Each device generates its OWN DKEK, locally. It never leaves this function and is destroyed
  # below. Under Option B there is nothing to archive: the seed is authoritative and already on
  # metal, so a DKEK share is a transport wrapper with a lifetime of one provisioning.
  # SAY WHICH STEP FAILED AND WHY. This used to send every step to /dev/null and return 1, so a
  # failure surfaced only as "device A provisioning failed" — four candidate causes and no way to
  # tell them apart without re-running by hand. The same swallowing hid a missing DKEK share file
  # in hsm-recovery-drill.sh on 2026-09-03 and cost an hour chasing card state that was fine.
  local plog="${PROV_LOG_DIR:-${TMPDIR:-/tmp}}/fleet-provision-$name.log"
  : > "$plog"
  _pstep(){ printf '\n### %s\n' "$1" >> "$plog"; shift; "$@" >> "$plog" 2>&1; }

  # The FILE is the proof, not the exit status: with no -r this call takes reader 0, prints
  # "Failed to connect to card" to a discarded stream, writes nothing, and still exits in a way a
  # bare check accepts (measured 2026-09-03).
  _pstep "create-dkek-share" sc-hsm-tool --reader "$(reader_of "$slot")" --create-dkek-share "$work/dkek.pbe" --password "$(cat "$dkpw")"
  [ -s "$work/dkek.pbe" ] \
    || { err "$name: create-dkek-share produced no share file — $(tail -1 "$plog")"; rm -rf "$work"; return 1; }

  # INITIALIZE's EXIT STATUS IS NOT A VERDICT — the Pico drops off the USB bus mid-command, which
  # every other suite here already accounts for. Judge it by whether the card comes back.
  _pstep "initialize" sc-hsm-tool --reader "$(reader_of "$slot")" --initialize --so-pin "$SO_PIN" --pin "$pin" --dkek-shares 1 --label "$name" || true
  wait_card "$slot" "$name" >> "$plog" 2>&1 \
    || { err "$name: card never came back after INITIALIZE (see $plog)"; rm -rf "$work"; return 1; }

  kcv="$(sc-hsm-tool --reader "$(reader_of "$slot")" --import-dkek-share "$work/dkek.pbe" --password "$(cat "$dkpw")" --so-pin "$SO_PIN" 2>&1 | tee -a "$plog" | grep -oE '[0-9A-F]{8,16}' | head -1)"

  # The import runs through scsh, so give it a bus with one card on it.
  local ik_slot="$slot" ik_reader; ik_reader="$(reader_of "$slot")"
  if [ -n "$serial" ] && isolate_begin "$serial"; then
    ik_slot="$ISO_SLOTID"; ik_reader="$ISO_READER"
  elif command -v hsm_reader_scsh_addressable >/dev/null 2>&1 \
       && ! hsm_reader_scsh_addressable "$ik_reader"; then
    # NOT ISOLATED, AND THIS CARD CANNOT BE NAMED. scsh matches reader names by PREFIX and takes the
    # first hit, so the card whose name is a strict prefix of the other's is unreachable: asking for
    # it hands back the other card. The import would then be aimed at the wrong device — the
    # identity guard in hsm-auto-import.js does stop it, but failing here says WHY, instead of
    # leaving a "WRONG CARD" refusal to be read as a defect in the guard.
    #
    # This is a bench-topology limit, not a code path to work around: it needs either single-card
    # isolation (a held RP2350 stays enumerated, so that needs switchable VBUS on the card's port)
    # or a replug so this card takes the longer "... Interface 01" name.
    err "$name: reader $ik_reader is named \"$(hsm_reader_name "$ik_reader" 2>/dev/null)\", which is a strict PREFIX of the other reader's name — scsh cannot address it, and isolation is unavailable on this bench (a held board stays enumerated, and these cards are not on a power-switchable port). Replug so $serial takes the longer name, or give its port switchable VBUS."
    rm -rf "$work"; return 1
    # >&2 — NOT stdout. provision() RETURNS THE DKEK KCV on stdout, so anything printed here is
    # captured into it. Measured 2026-09-03: this line contaminated KCV_A and KCV_B, and B4
    # ("the two DKEKs are genuinely unrelated") then compared two polluted strings that differed
    # only by the serial embedded in this message — reporting PASS for a check whose real inputs
    # were identical. A false PASS on an isolation property is worse than no check at all.
    printf '  (isolated: %s alone on the bus — slot %s, reader %s)\n' "$serial" "$ik_slot" "$ik_reader" >&2
  fi
  _pstep "import-key" "$HERE/hsm-import-key.sh" --slot "$ik_slot" --reader "$ik_reader" \
      --p12 "$P12" --pw-file "$PWF" --cert "$CERT" --id 33 --label "$DRILL_LABEL" \
      --dkek "$work/dkek.pbe" --dkek-pw "$dkpw" --pin-file "$pinf" \
    || { err "$name: key import failed — $(grep -iE 'error|GPError|SW1/SW2|failed' "$plog" | tail -1)"; isolate_end; rm -rf "$work"; return 1; }
  isolate_end

  shred -u "$work/dkek.pbe" "$dkpw" "$pinf" 2>/dev/null || rm -f "$work/dkek.pbe" "$dkpw" "$pinf"
  rm -rf "$work"
  printf '%s' "$kcv"
}

card_address(){ # $1=slot $2=pin
  local der; der="$(mktemp)"
  pkcs11-tool --module "$P11" --slot "$1" --login --pin "$2" --read-object --type pubkey \
      --label "$DRILL_LABEL" --output-file "$der" >/dev/null 2>&1 || { rm -f "$der"; return 1; }
  python3 "$DERIVE" --der "$der" 2>/dev/null | grep -oE 'akash1[a-z0-9]+' | head -1
  rm -f "$der"
}

sign_with(){ # $1=slot $2=pin $3=digestfile $4=sigfile
  pkcs11-tool --module "$P11" --slot "$1" --login --pin "$2" --sign --mechanism ECDSA \
    --label "$DRILL_LABEL" --input-file "$3" --output-file "$4" >/dev/null 2>&1
}

# =================================================================================================
# --pka helpers. INITIALIZE DEVICE drops the Pico off the USB bus mid-command, so an init's exit
# status means nothing (measured 2026-08-01): wait for the card to come BACK and verify every
# later claim by behaviour. Prompts go to /dev/tty so they survive command substitution and tee.
# =================================================================================================
wait_card(){ # $1=slot $2=name
  local tries=0
  until _slot_has_token "$1"; do
    tries=$((tries+1))
    if [ "$tries" -gt 12 ]; then
      err "$2 (slot $1) did not re-enumerate. Reseat it and re-run the mode that failed."
      return 1
    fi
    printf '  %s (slot %s) is off the bus — reseat it, then press Enter. > ' "$2" "$1" > /dev/tty
    IFS= read -r _ < /dev/tty
  done
  printf '  %s (slot %s) is back on the bus\n' "$2" "$1"
}

# Initialise one card and give it a DKEK, leaving dkek.pbe + dkek.pw in the caller's work dir for
# the key imports that follow. Extra args are appended to --initialize (the PKA flags for card A).
init_card(){ # $1=slot $2=pin $3=label $4=workdir ${5..}=extra init flags
  local slot="$1" pin="$2" name="$3" work="$4"; shift 4
  local dkpw="$work/dkek.pw" out kcv
  head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$dkpw"; chmod 600 "$dkpw"
  # See above: verify the artefact, not the status.
  sc-hsm-tool --reader "$(reader_of "$slot")" --create-dkek-share "$work/dkek.pbe" \
      --password "$(cat "$dkpw")" >/dev/null 2>&1
  [ -s "$work/dkek.pbe" ] || return 1
  # Exit status deliberately ignored: INITIALIZE DEVICE drops the Pico off the USB bus, and a
  # "failed" init can be a perfectly good wipe. The import below is the behavioural check.
  sc-hsm-tool --reader "$(reader_of "$slot")" --initialize --so-pin "$SO_PIN" --pin "$pin" \
      --dkek-shares 1 --label "$name" "$@" >"$work/init.log" 2>&1 || true
  printf '  (init exit status ignored — the Pico drops off the USB bus; verifying by behaviour)\n'
  wait_card "$slot" "$name" || return 1
  out="$(sc-hsm-tool --reader "$(reader_of "$slot")" --import-dkek-share "$work/dkek.pbe" \
      --password "$(cat "$dkpw")" --so-pin "$SO_PIN" 2>&1)" || { printf '%s\n' "$out" | tail -3; return 1; }
  kcv="$(printf '%s' "$out" | grep -oE '[0-9A-F]{8,16}' | head -1)"
  printf '  %s initialised, DKEK imported (kcv %s)\n' "$name" "${kcv:-?}"
}

# Throwaway custodian key material, generated OFF-card and imported with its certificate — the
# certificate is the documented prerequisite for `--export-for-pub-key-auth -i <ref>`, which
# selects the certificate EF and fails "Wrong key reference … File not found" for a bare key
# (PLAN.md 1.4 probe). Production custodians generate on their own tokens; these are stand-ins.
gen_custodian(){ # $1=index — writes cust$i.{key,crt,p12,pw} under $CUST_DIR
  local i="$1" pw="$CUST_DIR/cust$1.pw"
  head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$pw"; chmod 600 "$pw"
  openssl ecparam -name prime256v1 -genkey -noout -out "$CUST_DIR/cust$i.key" 2>/dev/null || return 1
  openssl req -x509 -new -key "$CUST_DIR/cust$i.key" -subj "/CN=pka-drill-custodian-$i" \
      -days 1 -out "$CUST_DIR/cust$i.crt" 2>/dev/null || return 1
  openssl pkcs12 -export -inkey "$CUST_DIR/cust$i.key" -in "$CUST_DIR/cust$i.crt" \
      -out "$CUST_DIR/cust$i.p12" -password "file:$pw" 2>/dev/null || return 1
}

# Imported keys land at PKCS#11 id 0x31+ even though unwrap reports keyId=1 (measured quirk):
# custodian i (the i-th key onto a fresh card) is SmartCard-HSM key-reference i, id byte 0x3$i.
import_custodian(){ # $1=index $2=workdir-with-dkek
  local i="$1" work="$2"
  "$HERE/hsm-import-key.sh" --slot "$SLOTID_B" --reader "$READER_B" \
      --p12 "$CUST_DIR/cust$i.p12" --pw-file "$CUST_DIR/cust$i.pw" \
      --cert "$CUST_DIR/cust$i.crt" --id "3$i" --label "pka-drill-custodian-$i" \
      --dkek "$work/dkek.pbe" --dkek-pw "$work/dkek.pw" --pin-file "$B_PIN_FILE" >/dev/null 2>&1
}

# Parse `--public-key-auth-status` into ST_REGISTERED/ST_MISSING/ST_REQUIRED/ST_AUTH. Empty on
# ANY parse failure — a readout we cannot parse is recorded, never guessed. Measured Pico format
# (2026-08-02): "Number of public keys: 3 / Missing public keys: 3 / Required pubkeys for auth: 2
# / Authenticated public keys: 0" — "Number of public keys" is the CAPACITY, not the enrolment
# count, so registered = capacity - missing. (The earlier parse read capacity AS registered and
# matched neither "Missing public keys" nor "Required pubkeys for auth" at all — this mode had
# never been run on hardware, so the bug had never fired.)
pka_status(){ # $1=slot
  local s; s="$(sc-hsm-tool --reader "$(reader_of "$1")" --public-key-auth-status 2>&1)" || true
  printf '%s\n' "$s" | sed 's/^/  status: /'
  local cap
  cap="$(printf '%s' "$s"         | grep -oiE 'number of public keys[^:]*: *[0-9]+' | grep -oE '[0-9]+' | head -1)"
  ST_MISSING="$(printf '%s' "$s" | grep -oiE 'missing[^:]*: *[0-9]+'      | grep -oE '[0-9]+' | head -1)"
  ST_REQUIRED="$(printf '%s' "$s" | grep -oiE 'required[^:]*: *[0-9]+'     | grep -oE '[0-9]+' | head -1)"
  ST_AUTH="$(printf '%s' "$s"    | grep -oiE 'authenticated[^:]*: *[0-9]+'| grep -oE '[0-9]+' | head -1)"
  ST_REGISTERED=""
  [[ "${cap:-}" =~ ^[0-9]+$ && "${ST_MISSING:-}" =~ ^[0-9]+$ ]] && ST_REGISTERED=$((cap - ST_MISSING))
}

if [ "$MODE" = "run" ]; then
  hdr "Wipe-safety"
  assert_safe_to_wipe "$SLOT_A" "device A" || exit 1
  assert_safe_to_wipe "$SLOT_B" "device B" || exit 1
  confirm || exit 1

  hdr "Build the throwaway container (one seed, imported twice)"
  build_container && P "PKCS#12 + certificate built from the test vector" || { F "container build failed"; exit 1; }

  hdr "Provision A and B INDEPENDENTLY (A4: B never consults A)"
  KCV_A="$(provision "$SLOT_A" "$PIN_A" fleet-a "$SERIAL_A")" && P "device A provisioned (dkek kcv ${KCV_A:-?})" || F "device A provisioning failed"
  KCV_B="$(provision "$SLOT_B" "$PIN_B" fleet-b "$SERIAL_B")" && P "device B provisioned (dkek kcv ${KCV_B:-?})" || F "device B provisioning failed"

  hdr "B4: the two DKEKs are genuinely unrelated"
  # PROVED BY BEHAVIOUR, NOT BY COMPARING KEY CHECK VALUES.
  #
  # The KCV comparison this used to do CANNOT pass on this firmware: measured 2026-09-03, both
  # cards report "DKEK key check value : 0000000000000000" even though each was provisioned with
  # an independently random share password, so their domains certainly differ. Comparing a value
  # the firmware never populates can only ever produce a verdict about the readout. (It also once
  # produced a false PASS here, when a stray status line contaminated the captured KCVs and made
  # two identical strings compare unequal.)
  #
  # So test the property itself: a key wrapped under A's DKEK must be REFUSED by B.
  # The third step is the CONTROL and it is what makes this a true positive rather than a
  # tautology — a blob that is simply malformed would be refused by B too, and would look
  # exactly like isolation. A must take its own blob back.
  b4_blob="$DRILL_DIR/b4-from-a.blob"
  b4_refs_a="$(wrappable_refs_on "$READER_A" "$PIN_A")"
  b4_src="$(printf '%s' "$b4_refs_a" | awk '{print $1}')"
  if [ -z "$b4_src" ]; then
    F "B4: no wrappable key reference on A — cannot obtain a blob to test isolation with"
  elif ! sc-hsm-tool --reader "$READER_A" --wrap-key "$b4_blob" --key-reference "$b4_src" --pin "$PIN_A" >/dev/null 2>&1 \
       || [ ! -s "$b4_blob" ]; then
    F "B4: could not wrap A's key (reference $b4_src) — cannot evaluate DKEK isolation"
  else
    P "wrapped A's key under A's DKEK ($(wc -c < "$b4_blob" | tr -d ' ') bytes, reference $b4_src)"
    # 1. B must REFUSE it.
    b4_on_b="$(sc-hsm-tool --reader "$READER_B" --unwrap-key "$b4_blob" --key-reference 9 --pin "$PIN_B" 2>&1)"
    # 2. A must ACCEPT it — the control.
    b4_on_a="$(sc-hsm-tool --reader "$READER_A" --unwrap-key "$b4_blob" --key-reference 9 --pin "$PIN_A" 2>&1)"
    # JUDGE BY OUTPUT: --unwrap-key exits 1 even on success (measured 2026-08-06).
    b4_b_ok=0; grep -qi "successfully imported" <<< "$b4_on_b" && b4_b_ok=1
    b4_a_ok=0; grep -qi "successfully imported" <<< "$b4_on_a" && b4_a_ok=1
    if [ "$b4_a_ok" != 1 ]; then
      F "B4 CONTROL FAILED: A would not take back its own blob ($(printf '%s' "$b4_on_a" | tail -1)) — the refusal by B proves nothing, because a blob nobody accepts is not evidence of isolation"
    elif [ "$b4_b_ok" = 1 ]; then
      F "B4 VIOLATED: device B UNWRAPPED a key wrapped under A's DKEK — the domains are NOT isolated and the fleet model is unsound"
    else
      P "B refused A's blob while A accepted it back — distinct DKEK domains, proven by behaviour"
    fi
  fi

  hdr "A3/A5: two devices, one address"
  ADDR_A="$(card_address "$SLOT_A" "$PIN_A")"; ADDR_B="$(card_address "$SLOT_B" "$PIN_B")"
  [ "$ADDR_A" = "$EXPECT" ] && P "device A holds the seed's key ($ADDR_A)" || F "device A: $ADDR_A != $EXPECT"
  [ "$ADDR_B" = "$EXPECT" ] && P "device B holds the seed's key ($ADDR_B)" || F "device B: $ADDR_B != $EXPECT"
  [ -n "$ADDR_A" ] && [ "$ADDR_A" = "$ADDR_B" ] && P "both sites agree, under different DKEKs" || F "the two sites disagree"

  hdr "A6: PINs are per-device"
  D="$(mktemp)"; head -c 32 /dev/urandom > "$D"; S="$(mktemp)"
  sign_with "$SLOT_A" "$PIN_A" "$D" "$S" && P "A signs with A's PIN" || F "A refused its own PIN"
  sign_with "$SLOT_B" "$PIN_B" "$D" "$S" && P "B signs with B's PIN" || F "B refused its own PIN"
  if sign_with "$SLOT_A" "$PIN_B" "$D" "$S" 2>/dev/null; then
    F "B'S PIN UNLOCKED A — a site compromise would take the whole fleet"
  else
    P "B's PIN is REFUSED by A (a site compromise stays one site)"
  fi
  # That wrong-PIN attempt just burned one of A's three tries. Restore it before continuing —
  # leaving a card at 2/3 because a test ran is exactly the kind of residue that bricks hardware.
  sign_with "$SLOT_A" "$PIN_A" "$D" "$S" >/dev/null 2>&1 \
    && P "A's retry counter restored by a correct PIN" || F "A did not accept its PIN afterwards — CHECK THE RETRY COUNTER BEFORE UNPLUGGING"

  hdr "NEGATIVE CONTROLS — this drill must be able to fail"
  sign_with "$SLOT_A" "$PIN_A" "$D" "$S"
  DER_A="$(mktemp)"
  pkcs11-tool --module "$P11" --slot "$SLOTID_A" --login --pin "$PIN_A" --read-object --type pubkey \
      --label "$DRILL_LABEL" --output-file "$DER_A" >/dev/null 2>&1
  head -c 32 /dev/urandom > "$D.wrong"
  if python3 "$VERIFY" --der "$DER_A" --digest "$D.wrong" --sig "$S" >/dev/null 2>&1; then
    F "a signature verified against the WRONG digest — the verifier is blind"
  else
    P "a wrong digest fails verification"
  fi
  # And the positive control: the SAME signature must verify against the RIGHT digest, or the
  # negative result above proves only that the verifier rejects everything.
  if python3 "$VERIFY" --der "$DER_A" --digest "$D" --sig "$S" >/dev/null 2>&1; then
    P "the same signature verifies against the CORRECT digest"
  else
    F "a valid signature did NOT verify — the verifier rejects everything, so the negative control above is meaningless"
  fi
  rm -f "$D" "$D.wrong" "$S" "$DER_A"
fi

# =================================================================================================
if [ "$MODE" = "run" ] || [ "$MODE" = "failover" ]; then
  hdr "A7: MEASURE the failover — this number has only ever been estimated"
  printf '  Physically remove device A (slot %s) now, then press Enter.\n' "$SLOT_A"
  printf '  The clock starts when you do. > '
  IFS= read -r _
  T0=$(date +%s)
  D="$(mktemp)"; head -c 32 /dev/urandom > "$D"; S="$(mktemp)"
  if sign_with "$SLOT_B" "$PIN_B" "$D" "$S"; then
    RTO=$(( $(date +%s) - T0 ))
    P "device B signed after A was removed — MEASURED RTO ${RTO}s"
    printf '  \033[1mRecord %ss in REQUIREMENTS.md A7. An RTO nobody has measured is an estimate.\033[0m\n' "$RTO"
  else
    F "device B could not sign with A absent — the standby is not a standby"
  fi
  rm -f "$D" "$S"
fi

# =================================================================================================
# --pka: PLAN.md 1.4 completion. Every step states its failure condition BEFORE it runs; every
# open question gets a BINARY recorded answer; nothing is trusted from a flag readout.
# Card A = the fleet device under PKA. Card B = the throwaway custodian stand-in (recorded as a
# limitation: what is measured is A's enforcement behaviour, not custodian hardware).
# =================================================================================================
if [ "$MODE" = "pka" ]; then
  TRANSCRIPT="$DRILL_DIR/pka-transcript-$(date +%Y%m%d-%H%M%S).log"
  exec > >(tee "$TRANSCRIPT") 2>&1
  printf '  transcript: %s\n' "$TRANSCRIPT"
  printf '  paste into doc/drills/YYYY-MM-DD-pka-enrol.md — add device + firmware + date per line.\n'

  # SO-PIN as pkcs11-tool wants it: the 16-character HEX string itself — OpenSC's
  # sc_hsm_encode_sopin turns each hex pair into one byte of the 8-byte initialisation
  # code. The old conversion to the decoded ASCII form ("57621880") was MEASURED wrong on
  # 2026-08-02: C_Login fails client-side with CKR_PIN_LEN_RANGE. Overridable.
  SO_PIN_P11="${HSM_SO_PIN_P11:-}"
  if [ -z "$SO_PIN_P11" ]; then
    if [[ "$SO_PIN" =~ ^[0-9A-Fa-f]{16}$ ]]; then
      SO_PIN_P11="$SO_PIN"
    else
      err "HSM_SO_PIN is not 16 hex digits; set HSM_SO_PIN_P11 to its pkcs11-tool form"; exit 2
    fi
  fi
  ATTACK_PIN="${HSM_ATTACK_PIN:-424242}"

  hdr "Wipe-safety"
  assert_safe_to_wipe "$SLOT_A" "device A" || exit 1
  assert_safe_to_wipe "$SLOT_B" "device B" || exit 1
  confirm || exit 1

  hdr "Build the throwaway containers (host-side; no card involved)"
  build_container && P "drill key container built from the test vector" || { F "container build failed"; exit 1; }
  CUST_DIR="$DRILL_DIR/custodians"; mkdir -p "$CUST_DIR"; chmod 700 "$CUST_DIR"
  for i in 1 2 3 4; do
    gen_custodian "$i" && P "custodian $i key+certificate built (throwaway stand-in)" \
                       || { F "custodian $i container build failed"; exit 1; }
  done
  B_WORK="$(mktemp -d)"; chmod 700 "$B_WORK"
  B_PIN_FILE="$B_WORK/pin"; printf '%s' "$PIN_B" > "$B_PIN_FILE"; chmod 600 "$B_PIN_FILE"

  hdr "STEP 1 — initialise card A with 2-of-3 PKA (the RATIFIED threshold, not the probe's 1-of-2)"
  printf '  FAILURE CONDITION: after init, --public-key-auth-status does not parse, or does not\n'
  printf '  show capacity 3 / required 2, or the drill key will not import — the mode cannot proceed.\n'
  A_WORK="$(mktemp -d)"; chmod 700 "$A_WORK"
  init_card "$SLOT_A" "$PIN_A" pka-drill-a "$A_WORK" \
      --public-key-auth 3 --required-pub-keys 2 || { F "card A initialisation/DKEK failed"; exit 1; }
  pka_status "$SLOT_A"
  if [ "${ST_REGISTERED:-}" = "0" ] && [ "${ST_MISSING:-}" = "3" ] && [ "${ST_REQUIRED:-}" = "2" ]; then
    P "A initialised with PKA: 0 registered / 3 missing / 2 required"
  else
    F "PKA init did not take as asked (registered=${ST_REGISTERED:-?} missing=${ST_MISSING:-?} required=${ST_REQUIRED:-?})"
    exit 1
  fi
  A_PIN_FILE="$A_WORK/pin"; printf '%s' "$PIN_A" > "$A_PIN_FILE"; chmod 600 "$A_PIN_FILE"
  "$HERE/hsm-import-key.sh" --slot "$SLOTID_A" --reader "$READER_A" \
      --p12 "$P12" --pw-file "$PWF" --cert "$CERT" --id 33 --label "$DRILL_LABEL" \
      --dkek "$A_WORK/dkek.pbe" --dkek-pw "$A_WORK/dkek.pw" --pin-file "$A_PIN_FILE" >/dev/null 2>&1 \
    && P "drill key imported onto A" || { F "drill key import onto A failed"; exit 1; }
  ADDR_A="$(card_address "$SLOT_A" "$PIN_A")"
  [ "$ADDR_A" = "$EXPECT" ] && P "A holds the seed's key ($ADDR_A)" || F "A: ${ADDR_A:-none} != $EXPECT"
  printf '  \033[33mNOTE\033[0m A is RRC-ENABLED here (sc-hsm-tool hardcodes it) — question (b) below NEEDS\n'
  printf '        RRC functional. Production posture (PKA + RRC-off) is UNVERIFIED: hsm-init-hardened.js\n'
  printf '        does not set PKA today (RUNBOOK-CUSTODIAN-ROTATION.md step 2).\n'
  U "PKA + RRC-off combined posture — not reachable with today's tooling; tracked in the rotation runbook"

  hdr "STEP 2 — custodian keys WITH certificates, on card B (the --export-for-pub-key-auth prerequisite)"
  printf '  FAILURE CONDITION: any custodian import fails, or any export fails with "Wrong key\n'
  printf '  reference … File not found" — the on-card-certificate prerequisite did not hold, which is\n'
  printf '  the exact PLAN 1.4 probe finding; registration onward is UNVERIFIED and the mode stops.\n'
  init_card "$SLOT_B" "$PIN_B" pka-drill-custodians "$B_WORK" || { F "card B initialisation failed"; exit 1; }
  EXPORT_OK=1
  for i in 1 2 3 4; do
    import_custodian "$i" "$B_WORK" || { F "custodian $i import onto B failed"; EXPORT_OK=0; break; }
    if sc-hsm-tool --reader "$READER_B" --export-for-pub-key-auth "$CUST_DIR/cust$i.pub" -i "$i" >/dev/null 2>&1 \
       && [ -s "$CUST_DIR/cust$i.pub" ]; then
      P "custodian $i exported for PKA (key-reference $i, certificate EF present)"
    else
      F "custodian $i export refused — the certificate prerequisite did NOT hold as scripted"
      EXPORT_OK=0; break
    fi
  done
  [ "$EXPORT_OK" = "1" ] || { U "everything downstream of the export failure — re-run after fixing the cert path"; exit 1; }

  hdr "STEP 3 — enrol the three custodians on card A; assert 3 registered / 2 required"
  printf '  FAILURE CONDITION: any registration fails, or status does not show 3/0 missing/2, or a\n'
  printf '  FOURTH registration is accepted (review-verified: the card must refuse once N are enrolled).\n'
  REG_OK=1
  for i in 1 2 3; do
    sc-hsm-tool --reader "$READER_A" --public-key-auth 3 --required-pub-keys 2 \
        --register-public-key "$CUST_DIR/cust$i.pub" >/dev/null 2>&1 \
      && P "custodian $i registered on A" || { F "custodian $i registration failed"; REG_OK=0; }
  done
  [ "$REG_OK" = "1" ] || exit 1
  pka_status "$SLOT_A"
  if [ "${ST_REGISTERED:-}" = "3" ] && [ "${ST_MISSING:-}" = "0" ] && [ "${ST_REQUIRED:-}" = "2" ]; then
    P "status confirms 3 registered / 0 missing / 2 required"
  else
    F "status disagrees with the enrolment (registered=${ST_REGISTERED:-?} missing=${ST_MISSING:-?} required=${ST_REQUIRED:-?})"
  fi
  if sc-hsm-tool --reader "$READER_A" --register-public-key "$CUST_DIR/cust4.pub" >/dev/null 2>&1; then
    F "a FOURTH key registered onto a full set — the refusal the rotation runbook relies on is absent"
  else
    P "a 4th registration is REFUSED once 3 are enrolled (there is no de-registration verb — this is C5)"
  fi

  hdr "STEP 4 — open question (a): with PKA enrolled, is PIN-only use now REFUSED?"
  printf '  FAILURE CONDITION: none — this step records a BINARY ANSWER, either way. The probe\n'
  printf '  (zero custodians) left the PIN fully working; D2 says PKA REPLACES the PIN. If a PIN-only\n'
  printf '  sign succeeds here, the D2 premise fails on the Pico and that is a gate-level finding.\n'
  D="$(mktemp)"; head -c 32 /dev/urandom > "$D"; S="$(mktemp)"
  if sign_with "$SLOT_A" "$PIN_A" "$D" "$S" 2>/dev/null; then
    A "(a) PKA does NOT replace the PIN — a PIN-only sign SUCCEEDED with 3 custodians enrolled"
    printf '  \033[1;31m  → the D2 claim "PKA replaces the static PIN" is FALSE on the Pico at enrolment. Record it.\033[0m\n'
  else
    A "(a) PKA REPLACES the PIN — a PIN-only sign was REFUSED with 3 custodians enrolled"
    P "D2's core premise holds on the Pico"
  fi
  rm -f "$D" "$S"

  hdr "STEP 5 — power-cycle: refusal until re-authorised + MEASURED 2-of-3 re-auth time (feeds A7/4.6)"
  printf '  FAILURE CONDITION: the card signs immediately after reseating, before any custodian\n'
  printf '  authentication — then power-off did NOT clear the authenticated set and the only tamper\n'
  printf '  signal colocation has is gone. (That also answers open question (c) — see STEP 7.)\n'
  printf '  Physically remove card A (slot %s) now, wait two seconds, reseat it, then press Enter.\n' "$SLOT_A"
  printf '  The re-auth clock starts when you do. > '
  IFS= read -r _
  T0=$(date +%s)
  wait_card "$SLOT_A" "device A" || exit 1
  D="$(mktemp)"; head -c 32 /dev/urandom > "$D"; S="$(mktemp)"
  if sign_with "$SLOT_A" "$PIN_A" "$D" "$S" 2>/dev/null; then
    A "(c) signing SURVIVED the power-cycle — the authenticated set did NOT clear (or PKA does not gate signing; cf. step 4)"
    F "no refusal after power-cycle — the tamper signal decision D2 was bought for is ABSENT"
  else
    P "A refuses to sign after power-cycle — the tamper signal exists"
  fi
  printf '\n  Now re-authorise: the custodian-auth VERB is unpinned in this repo (the rotation runbook\n'
  printf '  step 5 UNVERIFIED block) — use the rehearsed scsh PKA route against custodians 1 and 2 on\n'
  printf '  card B. The clock is RUNNING (started at power restore).\n'
  printf '  Press Enter when custodian #1 has authenticated. > '; IFS= read -r _
  printf '  Press Enter when custodian #2 has authenticated. > '; IFS= read -r _
  pka_status "$SLOT_A"
  [ "${ST_AUTH:-}" = "2" ] && P "status shows Authenticated: 2" \
    || U "Authenticated count unreadable or != 2 (${ST_AUTH:-?}) — the sign attempt below is the real proof"
  tries=0; REAUTH=""
  until sign_with "$SLOT_A" "$PIN_A" "$D" "$S" 2>/dev/null; do
    tries=$((tries+1)); [ "$tries" -ge 3 ] && break
    printf '  still refusing — complete/verify the custodian authentications, press Enter to retry. > '
    IFS= read -r _
  done
  if [ -z "$REAUTH" ] && [ -s "$S" ]; then
    REAUTH=$(( $(date +%s) - T0 ))
    P "A signed after 2-of-3 re-authentication — MEASURED re-auth time ${REAUTH}s"
    printf '\n  \033[1m*** RE-AUTH WALL-CLOCK: %ss ***\033[0m\n' "$REAUTH"
    printf '  \033[1mThis number feeds the A7 RTO (PLAN.md 4.6). The RTO stays UNNAMED until this is recorded.\033[0m\n\n'
  else
    F "A never signed after the reported 2 custodian authentications — re-auth path not established"
    U "re-auth timing — no valid signature was produced, so there is no number to record"
  fi
  rm -f "$D" "$S"

  hdr "STEP 6 — open question (b): does an SO-PIN RRC reset OVERRIDE PKA? (in this order, deliberately)"
  printf '  FAILURE CONDITION: none — BINARY ANSWER either way. A is reseated first so the step-5\n'
  printf '  authenticated set cannot confound the result: the sign attempt below runs with NO live\n'
  printf '  PKA session. If a sign under the SO-reset PIN succeeds, RRC overrides PKA and decisions\n'
  printf '  D2 and D3 become a MANDATORY PAIR, not independent choices.\n'
  printf '  Reseat card A (slot %s) to clear any live PKA session, then press Enter. > ' "$SLOT_A"
  IFS= read -r _
  wait_card "$SLOT_A" "device A" || exit 1
  if pkcs11-tool --module "$P11" --slot "$SLOTID_A" --login --login-type so \
       --so-pin "$SO_PIN_P11" --init-pin --new-pin "$ATTACK_PIN" >/dev/null 2>&1; then
    printf '  SO-PIN reset accepted (expected: A is RRC-ENABLED by construction — see step 1)\n'
    D="$(mktemp)"; head -c 32 /dev/urandom > "$D"; S="$(mktemp)"
    if sign_with "$SLOT_A" "$ATTACK_PIN" "$D" "$S" 2>/dev/null; then
      A "(b) RRC OVERRIDES PKA — a sign under the SO-reset PIN succeeded with NO PKA re-authentication"
      printf '  \033[1;31m  → D2 and D3 are a MANDATORY PAIR. PKA is worthless without RRC disabled. Record it.\033[0m\n'
    else
      A "(b) RRC does NOT override PKA — the SO-reset PIN alone cannot sign; PKA still gates"
      P "B8 stands independently of B6 (on the Pico)"
    fi
    rm -f "$D" "$S"
    # Leave no attacker PIN behind: the reset works at any time (B6), so restore the drill PIN.
    pkcs11-tool --module "$P11" --slot "$SLOTID_A" --login --login-type so \
        --so-pin "$SO_PIN_P11" --init-pin --new-pin "$PIN_A" >/dev/null 2>&1 \
      && P "drill PIN restored (no attacker-chosen PIN left on the card)" \
      || F "could not restore the drill PIN — re-initialise card A before any further use"
  else
    U "(b) the SO-PIN reset itself was REFUSED on an RRC-enabled init — unexpected; repeat by hand and record"
  fi

  hdr "STEP 7 — open question (c), and what to record where"
  printf '  (c) whether power-off clears the authenticated set is ANSWERED BY the step-5 refusal\n'
  printf '      assertion above — no separate arm is needed; cite the step-5 refusal line.\n'
  printf '  Record in PLAN.md 1.4: the (a)/(b)/(c) answers and the %ss re-auth number; then the\n' "${REAUTH:-UNMEASURED}"
  printf '  A7/4.6 RTO can finally be named. Requirement D1 stays OPEN — this is a Pico.\n'
  printf '  Transcript: %s\n' "$TRANSCRIPT"
fi

hdr "RESULT"
printf '  %d passed, %d failed, %d unverified\n' "$pass" "$fail" "$unv"
printf '\n  \033[1mD1 IS STILL OPEN.\033[0m These are Pico HSMs standing in for the Nitrokey HSM 2.\n'
printf '  A green run here proves the PROCEDURE and the SmartCard-HSM protocol behaviour.\n'
printf '  It proves nothing about the production silicon. Do not close D1 on the strength of it.\n'
[ "$fail" -eq 0 ] || exit 1
