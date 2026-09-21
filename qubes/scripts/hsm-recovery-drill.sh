#!/usr/bin/env bash
# hsm-recovery-drill.sh — rehearse the DAY-2 BREAK-GLASS paths end to end, on a scratch Pico,
# with transcript output suitable for pasting into doc/drills/.
#
# THE QUESTIONS IT ANSWERS. Day-2 recovery has been DESIGNED and MODELLED but the operator paths
# have never been performed against the hardware as a sequence:
#
#   1. BREAK-GLASS DKEK RESTORE — the corrected command
#      `sc-hsm-tool --import-dkek-share dkek.pbe --pwd-shares-total 4` (without --pwd-shares-total,
#      OpenSC never enters the share-reconstruction prompt path — RECOVERY-TECHNICAL.md 3B). The
#      operator types the PRIME + SHARE-ID + SHARE-VALUE sequence, 4 of 6 shares. A deliberately
#      WRONG share must be REFUSED first (negative control — a restore that accepts anything is
#      not a restore). Proof is BEHAVIOURAL: a blob wrapped under that DKEK at setup unwraps
#      after the restore, or it does not.
#   2. CUSTODIAN-ROTATION REHEARSAL — RUNBOOK-CUSTODIAN-ROTATION.md's only path: re-initialise
#      (that IS the revocation — there is no de-registration verb), re-provision from the seed,
#      re-enrol the survivors plus a replacement. With the two proofs the runbook demands: the
#      DEPARTED custodian's key must FAIL, and the new set must still reach threshold. This is
#      requirement C5's open Verify step.
#   3. SLIP-39 SEED RECOVERY — bip39-slip39-backup.py --recover round-trip: mint a throwaway
#      seed, split 4-of-6, recover from two DISTINCT quorums of 4, assert the recovered seed
#      derives the original address (derive-akash-address.py). Negative control: 3 shares must
#      NOT recover (B5).
#   4. RE-PROVISION PROOF — after all of the above has wiped the card repeatedly, unwrap the
#      ceremony-wrapped blob and assert the SAME address comes back (requirement A4's core).
#
# TWO DKEK ARTEFACTS, and why. A DKEK share created with the 4-of-6 password split (the
# break-glass artefact) has NO host-recoverable password — the shares are only consumable at
# sc-hsm-tool's own prompt — so the seed-key import (which wraps host-side under a decrypted
# share) cannot run under it. The drill therefore uses:
#   * dkek.pbe       the 4-of-6 share-split artefact — the thing step 1 restores interactively;
#   * dkek-auto.pbe  a password-protected share (0600, shredded at exit) standing in for the
#                    CEREMONY-TIME provisioning path, when the reconstructed password exists on
#                    the ceremony host. Steps 2 and 4 use it to re-provision the seed key.
# This is recorded as a limitation, not hidden: the share-prompt restore and the seed-key
# import are rehearsed against different DKEKs.
#
# WHAT IT CANNOT PROVE. Pico HSM stand-in for the Nitrokey HSM 2 — requirement D1 stays open no
# matter how green this run is. The custodian-authentication VERB is unpinned in this repo
# (RUNBOOK-CUSTODIAN-ROTATION.md step 5 UNVERIFIED block), so the step-2 auth proofs are
# operator-performed and recorded, not asserted by the script.
#
#   hsm-recovery-drill.sh --check --slot 0                     # what is attached; NO WRITES
#   hsm-recovery-drill.sh --run --slot 0                       # full drill, steps 1/3/4 (WIPES the card)
#   hsm-recovery-drill.sh --run --slot 0 --cust 1              # + step 2 (custodian rotation; --cust
#                                                              #  is a second card, WIPED, as the
#                                                              #  throwaway custodian stand-in)
#   hsm-recovery-drill.sh --run --slot 0 --auto                # hands-off: the WIPE confirmation is
#                                                              #  pre-authorised, USB re-enumeration is
#                                                              #  polled instead of prompted, and the
#                                                              #  DKEK share prompts are fed from the
#                                                              #  shares file the script itself minted.
#                                                              #  For scripted staging validation ONLY —
#                                                              #  real ceremonies run interactive so a
#                                                              #  human types the shares and confirms
#                                                              #  every wipe. Steps needing a physical
#                                                              #  reseat are SKIPPED, never faked.
#
# NOTHING HERE TOUCHES A REAL SEED. The card key comes from the published BIP39 test vector with
# no funds; the SLIP-39 seed is minted from /dev/urandom for the occasion and shredded at exit.
set -uo pipefail

# The ceremony's python dependencies (pycvc, shamir_mnemonic, mnemonic, pycryptodome) are
# hash-pinned and installed into a venv, NOT into the system interpreter. Prefer that venv so a
# bare `python3` resolves to it. MEASURED 2026-08-06: Homebrew moved python3 from 3.13 to 3.14 and
# orphaned the site-packages holding pycvc, which made the offline CVC check report the DEVICE
# certificate as unparseable when the real cause was a missing host library. Falls through to the
# system python3 when the venv is absent, so nothing breaks on a host that never made one.
CEREMONY_VENV="${CEREMONY_VENV:-$HOME/.local/share/akash-hsm-venv}"
[ -x "$CEREMONY_VENV/bin/python3" ] && PATH="$CEREMONY_VENV/bin:$PATH"

HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/verify-hsm-control.py"
DERIVE="$HERE/derive-akash-address.py"
SLIP39="$HERE/bip39-slip39-backup.py"

DRILL_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
DRILL_LABEL="recovery-drill-throwaway"
P11="${HSM_PKCS11_MODULE:-/usr/lib/opensc-pkcs11.so}"
SO_PIN="${HSM_SO_PIN:-3537363231383830}"
PIN="${HSM_PIN:-111111}"

pass=0; fail=0; unv=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
U(){ printf '  \033[33mUNVERIFIED\033[0m %s\n' "$1"; unv=$((unv+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
# The transcript is pasted into doc/drills. Anything printed from sc-hsm-tool goes through this first, so
# a colon-separated byte run (prime, share value) or a long bare hex run (a KCV, a key) never reaches it.
elide_hex(){ sed -E 's/[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){3,}/<hex elided>/g; s/[0-9A-Fa-f]{16,}/<hex elided>/g'; }
err(){ printf '  \033[31m!!\033[0m %s\n' "$*" >&2; }

MODE=""; SLOT=""; CUST_SLOT=""; AUTO=0; READER_ARG=""
while [ $# -gt 0 ]; do case "$1" in
  --check|--run) MODE="${1#--}";;
  --slot) SLOT="${2:-}"; shift;;
  # $SLOT was doing two jobs — a PKCS#11 slot ID for pkcs11-tool and a PC/SC reader index for
  # sc-hsm-tool. With one card attached those numbers coincide; with two they do not. Measured
  # 2026-09-03: PKCS#11 slot ids were 0x0 and 0x4 while the PC/SC readers were 0 and 1, so a
  # caller passing the slot id 4 made every `sc-hsm-tool --reader 4` address a reader that does
  # not exist — which is why the drill reported "key import failed" with no underlying error.
  --reader) READER_ARG="${2:-}"; shift;;
  --cust) CUST_SLOT="${2:-}"; shift;;
  --auto) AUTO=1;;
  -h|--help) sed -n '2,60p' "$0"; exit 0;;
  *) err "unknown argument: $1"; exit 2;;
esac; shift; done
[ -n "$MODE" ] || { sed -n '2,60p' "$0"; exit 2; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-bench-lock.sh"
hsm_bench_lock_acquire wait || exit $?

# Two handles, derived after parsing so --reader is actually visible. --reader wins; otherwise
# fall back to what the parent exported, and finally to --slot (correct on a single-card host,
# where the reader index and the PKCS#11 slot id are both 0).
_rd_rs="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-reader-select.sh"
# shellcheck source=/dev/null
[ -f "$_rd_rs" ] && . "$_rd_rs"
READER="${READER_ARG:-${HSM_PCSC_INDEX:-$SLOT}}"
SLOTID="${HSM_SLOT_ID:-$SLOT}"
# The custodian card needs the same split as the main one: --cust is a PKCS#11 SLOT id, and
# sc-hsm-tool wants a PC/SC READER index. They coincide on a one-card host and diverge on this
# bench (slot ids 0 and 4 against reader indices 0 and 1, measured 2026-09-03). This path only
# became reachable when a second SmartCard-HSM arrived, so it has never run with them differing.
CUST_READER="${HSM_CUST_PCSC_INDEX:-$CUST_SLOT}"

# HANDS-OFF MEANS NOTHING MAY WAIT FOR HANDS. In --auto the drill runs from a scheduler with no
# terminal, and any tool that decides to prompt inherits a stdin that will never deliver a byte and
# blocks FOREVER. That happened on 2026-08-07: sc-hsm-tool --create-dkek-share sat for 21 minutes
# and the whole nightly stopped behind it — no failure, no verdict, no transcript line, just a run
# that never ended. A step that hangs is worse than one that fails, because a failure is recorded
# and the battery moves on.
#
# Closing stdin here fixes the entire class in one place instead of wrapping thirty call sites.
# It is safe: every genuinely interactive prompt in this script reads from /dev/tty explicitly,
# and the share-feeding path pipes into the tool, so neither is affected.
if [ "$AUTO" = 1 ]; then
    exec < /dev/null
fi

# =================================================================================================
# GUARDS. `--initialize` aimed at the wrong reader is the catastrophic operation here.
# =================================================================================================
require_slot(){ # $1=value $2=flag
  case "$1" in ""|*[!0-9]*) err "$2 must be a numeric slot (got: '${1}')"; return 1;; esac
}

# SLOT-AWARE. `--list-slots` prints EVERY slot regardless of --slot, so `head -1` returns
# whichever card is listed first — not the one asked for. This function feeds the DESTRUCTIVE
# confirmation ("THIS WILL WIPE ... serials X / Y"), so a wrong answer here means the operator
# confirms a wipe of a device they were not shown. Measured 2026-09-03 with two cards attached.
slot_serial(){
  if command -v hsm_serial_at_slot_id >/dev/null 2>&1; then hsm_serial_at_slot_id "$1"; return; fi
  pkcs11-tool --module "$P11" --slot "$1" --list-slots 2>/dev/null | grep -oE 'serial num *: *[A-Za-z0-9]+' | head -1 | awk '{print $NF}'
}

# Same rule as the fleet drill: blank, or holding nothing but drill throwaway objects.
assert_safe_to_wipe(){ # $1=slot $2=name
  local slot="$1" name="$2" objs
  # THE ROLE REGISTRY GATE (same rule as the fleet drill's twin). A card that NAMES a token serial
  # must be registered staging in the committed registry (default-deny). A card with NO serial is
  # blank, and blank stays governed by the content rule below. When the resolver is not sourced
  # (the vault image ships scripts/ without tools/), the drill keeps its content gate and typed
  # confirmation; on the bench the resolver is always present and this gate holds.
  local _ser=""
  command -v slot_serial >/dev/null 2>&1 && _ser="$(slot_serial "$slot")"
  if [ -n "$_ser" ] && command -v hsm_assert_staging >/dev/null 2>&1; then
  # hsm_assert_staging_card, not hsm_assert_staging: the role gate says a card with this SERIAL may
  # be wiped, and a serial is self-reported. For a registered Nitrokey the card must also match the
  # C.DevAut digest the registry pins, which covers the device public key (regalia#481). A Pico entry
  # has no pin and passes straight through — its identity is proven over SWD instead.
    # NO SERIAL-ONLY FALLBACK. An older resolver without hsm_assert_staging_card would silently
    # degrade identity to a self-reported serial, which is precisely what a substituted genuine
    # Nitrokey reproduces. Missing gate, missing run.
    command -v hsm_assert_staging_card >/dev/null 2>&1 || {
      echo "REFUSING: this resolver has no hsm_assert_staging_card, so the card cannot be checked" >&2
      echo "  against the certificate the registry pins. Update tools/hsm-reader-select.sh." >&2
      return 1
    }
    hsm_assert_staging_card "$_ser" || return 1
  fi
  objs="$(pkcs11-tool --module "$P11" --slot "$slot" --list-objects 2>/dev/null)" || {
    err "$name (slot $slot): could not enumerate objects."
    err "REFUSING. A failed enumeration is not an empty card."
    return 1
  }
  # A LOCKED card cannot show its private objects without a PIN, so a "successful" enumeration
  # proves nothing about what it holds. 2026-08-02: this check reported an initialised,
  # PIN-locked card holding a key as "blank" — the unauthenticated listing showed only the
  # public half, whose label is EMPTY (the Pico's unwrapped/imported keys enumerate that way),
  # and the old label-only test read "no labels" as "no objects". Detect the lock from the
  # token flags and say so: locked is NOT blank, it means "contents unknown" — the wipe below
  # needs the same explicit typed confirmation as a card holding objects we don't recognise.
  # SLOT-AWARE. `--list-slots` prints EVERY slot regardless of --slot, so `head -1` reports the
  # FIRST card's flags under the second card's slot number. This feeds a wipe-safety decision, so
  # a wrong answer authorises a wipe on another device's state.
  #
  # Parsed in shell: macOS ships BSD awk with no strtonum(), so the hex slot id in "Slot 1 (0x4)"
  # cannot be converted there.
  local flags="" _ln _cur=""
  while IFS= read -r _ln; do
    case "$_ln" in
      "Slot "*"("0x*")"*)
        _cur="${_ln#*\(}"; _cur="${_cur%%\)*}"
        _cur="$(printf '%d' "$_cur" 2>/dev/null)" || _cur=""
        ;;
      *"token flags"*)
        [ "$_cur" = "$slot" ] && { flags="$_ln"; break; }
        ;;
    esac
  done <<EOF
$(pkcs11-tool --module "$P11" --list-token-slots 2>/dev/null)
EOF
  # Fallback for hosts with a single card, where slot id and list position coincide.
  [ -n "$flags" ] || flags="$(pkcs11-tool --module "$P11" --slot "$slot" --list-slots 2>/dev/null | grep -i 'token flags' | head -1)"
  if grep -qi 'user PIN locked' <<< "$flags"; then
    printf '  %s (slot %s): \033[1;31mLOCKED — contents unreadable, NOT blank\033[0m\n' "$name" "$slot"
    printf '    The typed WIPE confirmation is the only gate, exactly as for a card holding\n'
    printf '    unrecognised objects. Do not confirm unless you know this card is disposable.\n'
    return 0
  fi
  # Count OBJECTS, not labels: an object with an empty label is invisible to the label loop
  # below but is not an empty card. "Profile object" entries are PKCS#15 bookkeeping.
  local nobj; nobj="$(printf '%s' "$objs" | grep -cE '^(Public Key|Private Key|Secret Key|Certificate) Object' || true)"
  local labels; labels="$(printf '%s' "$objs" | grep -oE 'label: *.+' | sed 's/label: *//' | sort -u)"
  if [ "$nobj" = "0" ]; then
    printf '  %s (slot %s): blank\n' "$name" "$slot"; return 0
  fi
  local bad=0 l
  while IFS= read -r l; do
    [ -z "$l" ] && continue
    case "$l" in
      "$DRILL_LABEL"|rotation-drill-custodian-*) ;;
      *) err "$name (slot $slot) holds an object labelled '$l'"; bad=1;;
    esac
  done <<<"$labels"
  local nlab; nlab="$(printf '%s' "$objs" | grep -cE 'label: *.+' || true)"
  if [ "$nobj" -gt "$nlab" ]; then
    err "$name (slot $slot) holds $nobj object(s) but only $nlab with a non-empty label —"
    err "unlabelled objects cannot be classified. REFUSING to treat the card as safe to wipe."
    return 1
  fi
  [ "$bad" = 1 ] && { err "REFUSING to wipe $name."; return 1; }
  printf '  %s (slot %s): holds only drill throwaways (safe)\n' "$name" "$slot"
}

confirm_wipe(){
  if [ "$AUTO" = 1 ]; then
    printf '  \033[1;31mAUTO: wiping slot %s (serial %s)%s — pre-authorised by --auto, not prompting.\033[0m\n' \
      "$SLOT" "$(slot_serial "$SLOT")" "${CUST_SLOT:+, and slot $CUST_SLOT (serial $(slot_serial "$CUST_SLOT"))}"
    return 0
  fi
  printf '\n\033[1;31m  THIS WILL WIPE slot %s (serial %s)%s.\033[0m\n' \
    "$SLOT" "$(slot_serial "$SLOT")" "${CUST_SLOT:+, and slot $CUST_SLOT (serial $(slot_serial "$CUST_SLOT"))}"
  printf '  Type WIPE to proceed: '
  local ans; IFS= read -r ans
  [ "$ans" = "WIPE" ] || { err "not confirmed — nothing was written"; return 1; }
}

# INITIALIZE DEVICE drops the Pico off the USB bus mid-command: exit status means nothing.
wait_card(){ # $1=slot $2=name
  local tries=0 max=12
  [ "$AUTO" = 1 ] && max=40   # hands-off: poll ~2 minutes for re-enumeration instead of prompting
  # The card RESETS ~500 ms after INITIALIZE returns (pico-hsm schedules it so the APDU
  # response gets out first). Polling immediately therefore sees the still-present PRE-reset
  # token and returns a card that is about to vanish — measured 2026-08-06: wait_card returned
  # in 0 iterations and the very next IMPORT DKEK SHARE failed. Let the reset land first.
  sleep 3
  # CAPTURE, THEN MATCH — never `producer | grep -q` here, under `pipefail`.
  # grep -q quits at the first match, pkcs11-tool takes SIGPIPE and exits 141, and pipefail
  # reports 141 — so the condition reads FALSE exactly when the token appeared. In an `until`
  # loop that does not fail fast, it spins until `max` and then declares the card missing,
  # which is the same shape as the unbounded wait_card hang. Measured on sc-hsm-tool 2026-08-08:
  # inverted 5/5 with pipefail, correct 5/5 without.
  _slot_has_token(){
    local out
    out="$(pkcs11-tool --module "$P11" --slot "$1" --list-slots 2>/dev/null)"
    grep -q 'token label' <<< "$out"
  }
  until _slot_has_token "$1"; do
    tries=$((tries+1))
    if [ "$tries" -gt "$max" ]; then
      # Optional, opt-in escape hatch. A real ceremony leaves HSM_REENUM_RECOVER_CMD unset and
      # a human reseats the card. On a bench with a debug probe it can be pointed at
      # tools/hsm-swd-powman-recover.sh, which power-cycles the switched core over SWD — this
      # rig has no SRST, so that is the only way to revive a wedged card without hands.
      if [ -n "${HSM_REENUM_RECOVER_CMD:-}" ] && [ "${_reenum_recovered:-0}" != 1 ]; then
        _reenum_recovered=1
        printf '  %s (slot %s) did not re-enumerate — running HSM_REENUM_RECOVER_CMD\n' "$2" "$1"
        sh -c "$HSM_REENUM_RECOVER_CMD" || true
        tries=0
        continue
      fi
      err "$2 (slot $1) did not re-enumerate — reseat and re-run."; return 1
    fi
    if [ "$AUTO" = 1 ]; then
      sleep 3
    else
      printf '  %s (slot %s) is off the bus — reseat it, then press Enter. > ' "$2" "$1" > /dev/tty
      IFS= read -r _ < /dev/tty
    fi
  done
  # Enumerated is not the same as usable: require an actual answer before returning.
  local settle=0
  until sc-hsm-tool --reader "$1" >/dev/null 2>&1; do
    settle=$((settle+1))
    [ "$settle" -gt 20 ] && { err "$2 (slot $1) enumerated but does not answer"; return 1; }
    sleep 3
  done
  printf '  %s (slot %s) is back on the bus\n' "$2" "$1"
}

# =================================================================================================
hdr "Attached devices"
# A MISSING MODULE AND A MISSING CARD ARE DIFFERENT PROBLEMS, and this reported the second as the
# first. Under `pipefail` the grep returns 1 whenever no slot lines match — which is exactly what
# happens when the card is absent — so a wedged or unplugged device produced "no PKCS#11 module at
# /opt/homebrew/lib/opensc-pkcs11.so", sending the reader to check a library that was fine all
# along. Seen for real in the 2026-08-07 nightly, where e2e_recovery failed in 0 s with that
# message while the module was present and the card was simply off the bus.
[ -f "$P11" ] || { err "no PKCS#11 module at $P11 — set HSM_PKCS11_MODULE"; exit 1; }
_slots="$(pkcs11-tool --module "$P11" --list-slots 2>/dev/null)"
printf '%s\n' "$_slots" | grep -E 'Slot|serial|token label' | sed 's/^/  /' || true
grep -q 'token label' <<< "$(printf '%s' "$_slots")" \
  || { err "the PKCS#11 module loaded but NO TOKEN is present — the card is not on the bus (module: $P11)"; exit 1; }

if [ "$MODE" = "check" ]; then
  hdr "Read-only check — nothing is written"
  if [ -n "$SLOT" ]; then
    require_slot "$SLOT" "--slot" || exit 1
    assert_safe_to_wipe "$SLOT" "scratch device" || true
  else
    printf '  (pass --slot N to check wipe-safety)\n'
  fi
  exit 0
fi

require_slot "$SLOT" "--slot" || exit 1
if [ -n "$CUST_SLOT" ]; then
  require_slot "$CUST_SLOT" "--cust" || exit 1
  [ "$SLOT" != "$CUST_SLOT" ] || { err "--slot and --cust are the same slot ($SLOT)"; exit 1; }
  # REFUSE HERE, NOT AT STEP 2. The custodian key import goes through hsm-import-key.sh, which matches
  # reader names by PREFIX, so a prefix-named custodian reader would aim that import at the WRONG card
  # (#398). Checking it at STEP 2 would be too late in the only way that matters: steps 0 and 1 have
  # wiped and re-provisioned the PRIMARY card by then, so the run would destroy state it cannot go on
  # to use. Argument validation is the right place for an argument that cannot work.
  if command -v hsm_require_scsh_addressable >/dev/null 2>&1; then
    hsm_require_scsh_addressable "$CUST_READER" "the custodian stand-in" || {
      err "--cust names reader $CUST_READER, which Smart Card Shell cannot address (see above) — refusing before anything is wiped"
      exit 2
    }
  fi
fi

TRANSCRIPT_DIR="${HSM_RECOVERY_DRILL_DIR:-${TMPDIR:-/tmp}/hsm-recovery-drill}"
mkdir -p "$TRANSCRIPT_DIR"; chmod 700 "$TRANSCRIPT_DIR"
TRANSCRIPT="$TRANSCRIPT_DIR/recovery-transcript-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$TRANSCRIPT") 2>&1
printf '  transcript: %s\n' "$TRANSCRIPT"
printf '  paste into doc/drills/YYYY-MM-DD-recovery-drill.md — add device + firmware + date.\n'

WORK="$(mktemp -d)"; chmod 700 "$WORK"
trap 'shred -u "$WORK"/* 2>/dev/null || rm -f "$WORK"/*; rm -rf "$WORK"; hsm_bench_lock_release' EXIT

hdr "Wipe-safety"
assert_safe_to_wipe "$SLOT" "scratch device" || exit 1
[ -z "$CUST_SLOT" ] || assert_safe_to_wipe "$CUST_SLOT" "custodian stand-in" || exit 1
confirm_wipe || exit 1

# The oracle: the address the test-vector seed derives to with NO device involved (A2).
MNF="$WORK/drill.mnemonic"; printf '%s' "$DRILL_MNEMONIC" > "$MNF"; chmod 600 "$MNF"
EXPECT="$(python3 "$DERIVE" --mnemonic-file "$MNF" 2>/dev/null | grep -oE 'akash1[a-z0-9]+' | head -1)"
[ -n "$EXPECT" ] && P "seed derives offline to $EXPECT" || { F "offline derivation produced nothing"; exit 1; }

# The throwaway key container, built once (seed -> PKCS#12 + certificate).
P12="$WORK/drill.p12"; PWF="$WORK/drill.pw"; CERT="$WORK/drill.crt"
head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$PWF"; chmod 600 "$PWF"
python3 "$HERE/seed-to-pkcs12.py" --mnemonic-file "$MNF" --password-file "$PWF" --out "$P12" >/dev/null 2>&1 \
  && openssl req -x509 -new -key <(openssl pkcs12 -in "$P12" -nocerts -nodes -passin "file:$PWF" 2>/dev/null) \
     -subj "/CN=$DRILL_LABEL" -days 1 -out "$CERT" 2>/dev/null \
  && P "throwaway PKCS#12 + certificate built" || { F "container build failed"; exit 1; }

PIN_FILE="$WORK/pin"; printf '%s' "$PIN" > "$PIN_FILE"; chmod 600 "$PIN_FILE"

init_scratch(){ # ${1..}=extra init flags (PKA for the rotation phases)
  sc-hsm-tool --reader "$READER" --initialize --so-pin "$SO_PIN" --pin "$PIN" \
      --dkek-shares 1 --label recovery-drill "$@" > "$WORK/init.log" 2>&1 || true
  printf '  (init exit status ignored — the Pico drops off the USB bus; verifying by behaviour)\n'
  wait_card "$SLOT" "scratch device" || return 1

  # "THE CARD CAME BACK" IS NOT "THE CARD WAS WIPED". The exit status is unusable here (the Pico
  # drops off the bus mid-command), so this verified only that the device re-enumerated — which is
  # equally true of an INITIALIZE that never executed. When that happened the old DKEK domain
  # survived, and the NEXT step failed instead, with "IMPORT_DKEK_SHARE ... Not allowed" — a defect
  # reported one phase away from its cause, against a card the reader believes was just wiped.
  #
  # A wiped card holds no private keys, and pkcs15-tool can count them without a PIN. The DKEK key
  # check value cannot be used for this: it reads all-zero on this firmware even with a DKEK
  # imported, so it proves nothing either way.
  local _keys
  _keys="$(perl -e 'alarm 25; exec @ARGV' -- pkcs15-tool -r "$READER" --list-keys 2>/dev/null \
           | grep -ci 'Private .* Key' || true)"
  if [ "${_keys:-0}" -gt 0 ]; then
    F "the INITIALIZE did not take: the card still holds $_keys private key(s) after a wipe — it re-enumerated without being re-initialised, so every later step would run against stale state"
    return 1
  fi
  return 0
}

# The CEREMONY-TIME provisioning DKEK: password-protected, host-known password, shredded at exit.
DKEK_AUTO="$WORK/dkek-auto.pbe"; DKEK_AUTO_PW="$WORK/dkek-auto.pw"
head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$DKEK_AUTO_PW"; chmod 600 "$DKEK_AUTO_PW"
# --create-dkek-share LOOKS host-side — it derives a share file and writes it to disk — but
# sc-hsm-tool still opens a reader before doing anything, so it needs -r like every other call.
# Measured 2026-09-03 with the other board held off the bus: with no -r it took PC/SC reader 0,
# printed "Failed to connect to card: Card not present", wrote NO share file, and exited in a way
# this `&&` treated as success. The failure then surfaced two steps later as "provisioning DKEK
# import failed" — a missing file reported as a card problem.
# VERIFY THE ARTEFACT, NOT THE EXIT STATUS. With no -r, this call takes PC/SC reader 0, prints
# "Failed to connect to card" to a discarded stream, writes NO FILE, and still satisfies a bare
# `&&` (measured 2026-09-03). The failure then surfaced two steps later as a card problem. A step
# that is supposed to produce a file has not succeeded until the file exists and is non-empty.
sc-hsm-tool -r "$READER" --create-dkek-share "$DKEK_AUTO" --password "$(cat "$DKEK_AUTO_PW")" >/dev/null 2>&1 \
  && [ -s "$DKEK_AUTO" ] \
  && P "provisioning DKEK created (password path, ceremony-time stand-in)" \
  || { F "provisioning DKEK creation failed"; exit 1; }

import_auto_dkek(){
  sc-hsm-tool --reader "$READER" --import-dkek-share "$DKEK_AUTO" \
      --password "$(cat "$DKEK_AUTO_PW")" --so-pin "$SO_PIN" >/dev/null 2>&1
}

# KEEP THE CHILD'S OUTPUT. This sent everything to /dev/null, so a failure surfaced only as
# "key import failed" with no cause — which is the exact complaint recorded at the --reader option
# above ("which is why the drill reported 'key import failed' with no underlying error"), and the
# same swallowing hsm-fleet-drill.sh already fixed for itself with the note that it "hid a missing
# DKEK share file in hsm-recovery-drill.sh on 2026-09-03 and cost an hour chasing card state that
# was fine". The lesson was applied to one drill and not this one.
#
# It matters now because this step is INTERMITTENT: measured 2026-09-11, two nightly runs whose
# phases 0..d were byte-identical (same PKA finding, same card) gave phase e PASS then FAIL, so the
# cause cannot be read off the entry state and there is nothing else to read.
IMPORT_LOG="${IMPORT_LOG:-${TMPDIR:-/tmp}/hsm-recovery-drill-import.log}"
import_drill_key(){
  : > "$IMPORT_LOG"
  "$HERE/hsm-import-key.sh" --slot "$SLOTID" --reader "$READER" \
      --p12 "$P12" --pw-file "$PWF" --cert "$CERT" --id 33 --label "$DRILL_LABEL" \
      --dkek "$DKEK_AUTO" --dkek-pw "$DKEK_AUTO_PW" --pin-file "$PIN_FILE" >> "$IMPORT_LOG" 2>&1
}
# The first line worth showing, not the last line of the file: the tail of a GPError stack is a
# frame, and the frame is not the fault.
import_why(){
  grep -aiE 'GPError|SW1/SW2|REFUS|CKR_|error|no ATR|not found|cannot' "$IMPORT_LOG" 2>/dev/null \
    | head -1 | cut -c1-200
}

# --auto ONLY: feed sc-hsm-tool's share-reconstruction prompts from the shares file the script
# minted itself. The prompt sequence was measured against OpenSC 2026-08-02:
#   "Please enter prime:" <prime>
#   per share: "Press <enter> to enter share i of N" (consumes one line), then
#              "Please enter share ID:" <id>, "Please enter share value:" <value>
# $1=shares file (captured --create-dkek-share output) $2=shares to feed $3=optional "wrong":
# corrupt share 1's value — the negative control must be REFUSED at the decipher step.
feed_shares(){
  local f="$1" n="$2" wrong="${3:-}" prime ids vals i id val
  prime="$(grep -m1 -oE 'Prime *: *[0-9a-fA-F:]+' "$f" | grep -oE '[0-9a-fA-F:]+$')"
  ids="$(grep -oE 'Share ID *: *[0-9]+' "$f" | grep -oE '[0-9]+$')"
  vals="$(grep -oE 'Share value *: *[0-9a-fA-F:]+' "$f" | grep -oE '[0-9a-fA-F:]+$')"
  [ -n "$prime" ] && [ -n "$ids" ] && [ -n "$vals" ] || return 1
  printf '%s\n' "$prime"
  i=0
  while [ "$i" -lt "$n" ]; do
    i=$((i+1))
    id="$(printf '%s\n' "$ids" | sed -n "${i}p")"
    val="$(printf '%s\n' "$vals" | sed -n "${i}p")"
    [ -n "$id" ] && [ -n "$val" ] || return 1
    [ "$wrong" = "wrong" ] && [ "$i" = "1" ] && val="00:00:00:00:00:00:00:00"
    printf '\n%s\n%s\n' "$id" "$val"
  done
}

card_address(){ # read the pubkey back and derive the address; echo nothing on failure
  local der; der="$(mktemp)"
  # Imported keys land at PKCS#11 id 0x31 even though unwrap reports keyId=1 (measured quirk) —
  # try the label first, then the quirk id.
  pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --read-object --type pubkey \
      --label "$DRILL_LABEL" --output-file "$der" >/dev/null 2>&1 \
  || pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --read-object --type pubkey \
      --id 31 --output-file "$der" >/dev/null 2>&1 || { rm -f "$der"; return 1; }
  python3 "$DERIVE" --der "$der" 2>/dev/null | grep -oE 'akash1[a-z0-9]+' | head -1
  rm -f "$der"
}

sign_proof(){ # sign on the card, verify against $1 (pubkey DER), with a wrong-digest control
  local pub="$1" d s w
  d="$(mktemp)"; s="$(mktemp)"; w="$(mktemp)"
  head -c 32 /dev/urandom > "$d"; head -c 32 /dev/urandom > "$w"
  # After --unwrap-key the restored key has NO label and no cert (measured quirk: unwrapped
  # keys enumerate with an empty label and land at id 0x31), so sign by label first, then by id.
  pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --sign --mechanism ECDSA \
      --label "$DRILL_LABEL" --input-file "$d" --output-file "$s" >/dev/null 2>&1 \
  || pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --sign --mechanism ECDSA \
      --id 31 --input-file "$d" --output-file "$s" >/dev/null 2>&1 || { rm -f "$d" "$s" "$w"; return 1; }
  python3 "$VERIFY" --der "$pub" --digest "$d" --sig "$s" >/dev/null 2>&1 || { rm -f "$d" "$s" "$w"; return 1; }
  if python3 "$VERIFY" --der "$pub" --digest "$w" --sig "$s" >/dev/null 2>&1; then
    rm -f "$d" "$s" "$w"; return 2   # the verifier accepted a WRONG digest — blind control
  fi
  rm -f "$d" "$s" "$w"; return 0
}

# =================================================================================================
hdr "STEP 0 — provision the seed key (ceremony-time path) and wrap it"
printf '  FAILURE CONDITION: the DKEK import, the key import, or the wrap fails, or the card does\n'
printf '  not hold %s afterwards — nothing downstream can run.\n' "$EXPECT"
init_scratch || exit 1
import_auto_dkek && P "provisioning DKEK imported" || { F "provisioning DKEK import failed"; exit 1; }
import_drill_key && P "seed-derived drill key imported" \
  || { F "key import failed: $(import_why)  (full log: $IMPORT_LOG)"; exit 1; }
ADDR="$(card_address)"
[ "$ADDR" = "$EXPECT" ] && P "card holds the seed's key ($ADDR)" || { F "card: ${ADDR:-none} != $EXPECT"; exit 1; }
PUB_ORIG="$WORK/original-pub.der"
pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --read-object --type pubkey \
    --label "$DRILL_LABEL" --output-file "$PUB_ORIG" >/dev/null 2>&1 \
  && P "original public key recorded (the restore proofs verify against it)" \
  || U "pubkey not readable by label — restore proofs will rely on the sign/verify arm alone"

# sc-hsm-tool --unwrap-key EXITS 1 EVEN ON SUCCESS. Measured 2026-08-06:
#
#   $ sc-hsm-tool --unwrap-key blob --key-reference 2 --pin ...; echo $?
#   Wrapped key contains:
#     Key blob
#     Private Key Description (PRKD)
#     Certificate
#   Key successfully imported
#   1
#
# and the key really is there afterwards (it wraps from the destination reference). Checking the
# exit status therefore reports FAIL on a working restore — which is what made STEP 1 and STEP 4
# claim "unwrap failed" while STEP 4's own address and signature proofs passed on the very key it
# said had not arrived. Judge it by what the tool says it did, in keeping with this drill's
# behavioural-proof rule.
unwrap_key(){ # $1=blob $2=destination key reference
  local out
  out="$(sc-hsm-tool --reader "$READER" --unwrap-key "$1" --key-reference "$2" --pin "$PIN" 2>&1)"
  grep -qi 'successfully imported' <<< "$(printf '%s' "$out")"
}

# --- key-reference discovery -------------------------------------------------------------------
# The card assigns key references ITSELF, sequentially, and ignores the PKCS#11 --id you asked
# for: keys created as --id 02 and --id 04 landed at references 1 and 2 (measured 2026-08-06).
# Hardcoding "--key-reference 2 is the key I just made" is therefore wrong, and produced
# "carrier wrap failed (key-reference 2)" -> SW 6A82 File not found.
#
# --wrap-key does not modify the key, so probing with it is a safe way to ask the card which
# references actually hold a wrappable key. Snapshot before creating a key and after, and the
# difference IS the new key's reference.
# Probing costs a PIN VERIFICATION per attempt. With the correct PIN that is free (a successful
# verify resets the retry counter), but with a WRONG one it walks the counter to zero and blocks
# the card — measured 2026-08-06, six probe attempts locked a card outright. So never probe on an
# unverified PIN.
pin_is_good(){
  pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --list-objects >/dev/null 2>&1
}

wrappable_refs(){ # echoes the references that currently wrap, e.g. " 1 2"
  local r t out=""
  if ! pin_is_good; then
    err "refusing to probe key references: the user PIN does not verify (probing would lock the card)"
    return 1
  fi
  for r in 1 2 3 4 5 6; do
    t="$(mktemp)"
    if sc-hsm-tool --reader "$READER" --wrap-key "$t" --key-reference "$r" --pin "$PIN" \
         >/dev/null 2>&1 && [ -s "$t" ]; then
      out="$out $r"
    fi
    rm -f "$t"
  done
  printf '%s' "$out"
}

new_ref(){ # $1=refs before  $2=refs after -> echoes the reference that appeared
  local b="$1" a="$2" r
  for r in $a; do
    case " $b " in *" $r "*) ;; *) printf '%s' "$r"; return 0;; esac
  done
  return 1
}

# cmd_key_wrap refuses with SW 6A88 ("Data object not found") when the DKEK domain is not
# complete — dkeks != current_dkeks. That reads like a missing key but is a missing SHARE, so
# check it explicitly and say which it is.
assert_dkek_complete(){ # $1=context for the message
  local out
  out="$(sc-hsm-tool --reader "$READER" 2>&1)"
  if grep -qi 'import pending' <<< "$out"; then
    F "$1: the DKEK domain is INCOMPLETE ($(printf '%s' "$out" | grep -i 'import pending'))"
    return 1
  fi
  grep -qi 'DKEK shares' <<< "$out" || { F "$1: no DKEK domain on the card"; return 1; }
  return 0
}
# -----------------------------------------------------------------------------------------------

# The ceremony-wrapped artefact step 4 restores from. --wrap-key authenticates with the USER PIN.
WRAPPED="$WORK/funding-wrapped.bin"
assert_dkek_complete "before wrapping the funding key" || exit 1
FUNDING_REFS="$(wrappable_refs)"
[ -n "$FUNDING_REFS" ] || { F "no wrappable key on the card — the import did not land"; exit 1; }
FUNDING_REF="${FUNDING_REFS##* }"
sc-hsm-tool --reader "$READER" --wrap-key "$WRAPPED" --key-reference "$FUNDING_REF" --pin "$PIN" >/dev/null 2>&1 \
  && [ -s "$WRAPPED" ] && P "key wrapped under the provisioning DKEK -> funding-wrapped.bin (key-reference $FUNDING_REF)" \
  || { F "--wrap-key failed (key-reference $FUNDING_REF) — step 4 has nothing to unwrap"; exit 1; }

# =================================================================================================
# The BREAK-GLASS artefact: a DKEK whose share password exists only as 4-of-6 printed shares.
# A carrier blob is wrapped under it NOW (via a throwaway ON-CARD key — B2's never-generate rule
# governs the funding key, not a drill blob-carrier; the funding key itself was imported above).
# =================================================================================================
hdr "Setup — the 4-of-6 break-glass DKEK and its carrier blob"
printf '  FAILURE CONDITION: share creation fails, or the carrier blob cannot be wrapped — the\n'
printf '  restore in step 1 would have nothing to prove itself against.\n'
DKEK_PBE="$WORK/dkek.pbe"; SHARES_FILE="$WORK/dkek-shares.txt"
# BOUNDED, AND stdin FROM /dev/null. This call had neither, and it hung the entire nightly for
# 21 minutes on 2026-08-07: sc-hsm-tool wanted input, inherited a stdin that never delivered any,
# and blocked forever. Nothing upstream of it had a timeout either, so the battery simply stopped —
# no failure, no verdict, no transcript line, just a run that never ended. A step that can block
# indefinitely is worse than one that fails: a failure gets recorded and the suite moves on.
# Every other card call in this script is already wrapped this way; this one was missed.
if perl -e 'alarm 120; exec @ARGV' -- sc-hsm-tool -r "$READER" --create-dkek-share "$DKEK_PBE" \
     --pwd-shares-threshold 4 --pwd-shares-total 6 < /dev/null \
     > "$SHARES_FILE.raw" 2>&1 && [ -s "$DKEK_PBE" ]; then
  chmod 600 "$SHARES_FILE.raw"; mv "$SHARES_FILE.raw" "$SHARES_FILE"
  P "break-glass DKEK share created; the 6 password shares are in $SHARES_FILE (0600)"
  [ "$AUTO" = 1 ] \
    && printf '  AUTO: the share prompts will be fed from that file programmatically.\n' \
    || printf '  \033[1mOpen that file in a SECOND terminal now\033[0m — you will type from it, 4 shares per restore.\n'
else
  F "break-glass DKEK share creation failed"; exit 1
fi
BLOB_S="$WORK/carrier-wrapped.bin"
init_scratch || exit 1
restore_ok=0
if [ "$AUTO" = 1 ]; then
  printf '  AUTO: importing the break-glass DKEK with the shares fed from the file (rep #1).\n'
  out="$(feed_shares "$SHARES_FILE" 4 | sc-hsm-tool --reader "$READER" \
      --import-dkek-share "$DKEK_PBE" --pwd-shares-total 4 2>&1)"; rc=$?
  grep -q 'Please enter prime' <<< "$(printf '%s\n' "$out")" \
    && P "the corrected command entered the share-reconstruction prompt path (RECOVERY-TECHNICAL.md 3B)" \
    || F "the import never asked for shares — the prompt path the fix depends on is absent"
  if [ "$rc" = 0 ]; then
    restore_ok=1; P "break-glass DKEK imported (rep #1, shares fed programmatically)"
  else
    F "the fed DKEK import failed with CORRECT shares: $(printf '%s' "$out" | tail -1)"
  fi
else
  printf '  Importing the break-glass DKEK interactively — this is rep #1 of the share prompt.\n'
  printf '\n  \033[1mType at the prompts:\033[0m the PRIME, then per share the SHARE ID and SHARE VALUE —\n'
  printf '  any 4 of the 6 shares from %s.\n' "$SHARES_FILE"
  if sc-hsm-tool --reader "$READER" --import-dkek-share "$DKEK_PBE" --pwd-shares-total 4 < /dev/tty; then
    restore_ok=1; P "break-glass DKEK imported (rep #1)"
  else
    F "the interactive DKEK import failed with CORRECT shares — check the share file and retry"
  fi
fi
[ "$restore_ok" = "1" ] || exit 1
# --keypairgen, not --keygen: pkcs11-tool's --keygen makes SECRET keys and rejects an EC
# key type outright ("Unknown key type EC:prime256v1"), so this step could never have
# succeeded. Measured 2026-08-06.
assert_dkek_complete "before generating the carrier key" || exit 1
REFS_BEFORE="$(wrappable_refs)"
pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --keypairgen --key-type EC:prime256v1 \
    --id 02 --label "$DRILL_LABEL" >/dev/null 2>&1 \
  && P "throwaway carrier key generated on-card (drill blob-carrier only — B2 governs the funding key)" \
  || { F "on-card keygen failed — cannot create the carrier blob"; exit 1; }
REFS_AFTER="$(wrappable_refs)"
CARRIER_REF="$(new_ref "$REFS_BEFORE" "$REFS_AFTER")" \
  || { F "the generated carrier key is not wrappable (before:$REFS_BEFORE after:$REFS_AFTER)"; exit 1; }
# NOTE: CARRIER_REF may legitimately equal FUNDING_REF. init_scratch() above WIPES the card, so
# the funding key is gone by this point and the card reuses reference 1 for the carrier. Comparing
# the two references is therefore meaningless — an earlier version of this guard did exactly that
# and failed a perfectly good run. What IS meaningful is that the carrier blob is not the funding
# blob, which is checked after the wrap below.
sc-hsm-tool --reader "$READER" --wrap-key "$BLOB_S" --key-reference "$CARRIER_REF" --pin "$PIN" >/dev/null 2>&1 \
  && [ -s "$BLOB_S" ] && P "carrier blob wrapped under the break-glass DKEK (key-reference $CARRIER_REF)" \
  || { F "carrier wrap failed (key-reference $CARRIER_REF)"; exit 1; }
# The carrier must be a THROWAWAY key, never the funding key (B2). Identical bytes would mean the
# discovery picked the wrong key and this step quietly wrapped the funding key.
if cmp -s "$BLOB_S" "$WRAPPED"; then
  F "the carrier blob is byte-identical to the funding blob — the wrong key was wrapped"
  exit 1
fi

# =================================================================================================
hdr "STEP 1 — BREAK-GLASS DKEK RESTORE: --import-dkek-share dkek.pbe --pwd-shares-total 4"
printf '  Simulating the dead card: wipe, then restore the DKEK from the typed shares.\n'
printf '  FAILURE CONDITION (negative control): the card ACCEPTS a wrong share — a restore path\n'
printf '  that cannot reject bad material is not a control.\n'
init_scratch || exit 1
if [ "$AUTO" = 1 ]; then
  printf '  NEGATIVE CONTROL (auto): feeding 4 shares with share 1 CORRUPTED — the import must FAIL\n'
  printf '  at the decipher step, before the card is ever touched.\n'
  out="$(feed_shares "$SHARES_FILE" 4 wrong | sc-hsm-tool --reader "$READER" \
      --import-dkek-share "$DKEK_PBE" --pwd-shares-total 4 2>&1)"; rc=$?
  if [ "$rc" = 0 ]; then
    F "the card ACCEPTED a wrong DKEK share — the break-glass path has no integrity check"
    # Keep the evidence. This fired once in the #397 repro loop and the output was discarded, so that
    # occurrence cannot say which side accepted the wrong share: sc-hsm-tool's host-side decrypt of
    # dkek.pbe under the reconstructed password, or the card.
    printf '  sc-hsm-tool exited 0 with share 1 corrupted. Its last lines (hex elided):\n'
    printf '%s\n' "$out" | elide_hex | grep -v '^[[:space:]]*$' | tail -12 | sed 's/^/    | /'
  elif grep -qi 'Error decrypting DKEK share' <<< "$out"; then
    P "a wrong share is REFUSED at the decipher step — the negative control holds"
  else
    P "a wrong share is REFUSED (rc=$rc: $(printf '%s' "$out" | tail -1)) — the negative control holds"
  fi
else
  printf '\n  \033[1mNEGATIVE CONTROL — type a DELIBERATELY WRONG value at the first share prompt.\033[0m\n'
  printf '  Expected: the import FAILS (decryption/reconstruction error). Press Enter to begin. > '
  IFS= read -r _
  if sc-hsm-tool --reader "$READER" --import-dkek-share "$DKEK_PBE" --pwd-shares-total 4 < /dev/tty; then
    F "the card ACCEPTED a wrong DKEK share — the break-glass path has no integrity check"
  else
    P "a wrong share is REFUSED — the negative control holds"
  fi
fi
printf '  FAILURE CONDITION (positive arm): 4 CORRECT shares do not restore the DKEK — the\n'
printf '  documented break-glass path does not work and RECOVERY-TECHNICAL.md 3B is wrong.\n'
# Re-init between attempts: a failed import may leave the share counter in an unknown state, and
# "probably fine" is not a state.
init_scratch || exit 1
if [ "$AUTO" = 1 ]; then
  printf '  AUTO: correct restore (rep #2 — 4 CORRECT shares fed from the file).\n'
  out="$(feed_shares "$SHARES_FILE" 4 | sc-hsm-tool --reader "$READER" \
      --import-dkek-share "$DKEK_PBE" --pwd-shares-total 4 2>&1)"; rc=$?
  if [ "$rc" = 0 ]; then
    P "4-of-6 shares restored the DKEK — the corrected command works as documented"
  else
    F "the correct 4 shares did NOT restore the DKEK — the break-glass path is broken: $(printf '%s' "$out" | tail -1)"
  fi
else
  printf '  Press Enter to begin the correct restore (rep #2 — 4 CORRECT shares). > '; IFS= read -r _
  if sc-hsm-tool --reader "$READER" --import-dkek-share "$DKEK_PBE" --pwd-shares-total 4 < /dev/tty; then
    P "4-of-6 shares restored the DKEK — the corrected command works as documented"
  else
    F "the correct 4 shares did NOT restore the DKEK — the break-glass path is broken"
  fi
fi
# Behavioural proof, not a status readout: the carrier blob unwraps under the restored DKEK or
# the restore did not actually happen.
unwrap_key "$BLOB_S" 2 \
  && P "carrier blob unwrapped under the restored DKEK — the DKEK really is the same one" \
  || F "unwrap failed after a 'successful' restore — the import reported success without the DKEK"

# =================================================================================================
hdr "STEP 2 — CUSTODIAN-ROTATION REHEARSAL (requirement C5's open Verify step)"
printf '  Per RUNBOOK-CUSTODIAN-ROTATION.md: re-initialise (the revocation — there is NO\n'
printf '  de-registration verb), re-provision from the seed, re-enrol survivors + replacement.\n'
if [ -z "$CUST_SLOT" ]; then
  # SAY WHICH OF THE THREE THINGS IS MISSING. "no --cust slot given" is a statement about the command
  # line, and it reads as "pass the flag and this runs" — which is false on a bench where a second card
  # IS attached but its PC/SC reader name is a strict prefix of the other's. Smart Card Shell matches
  # reader names by prefix, so hsm-import-key.sh at the custodian step below cannot address that card
  # at all (#398). An UNVERIFIED whose stated reason is not the real reason is worse than a bare skip:
  # it sends the next person to add a flag instead of to the bus.
  _rd_others=""
  if command -v hsm_reader_indices >/dev/null 2>&1; then
    for _rd_i in $(hsm_reader_indices 2>/dev/null); do
      [ "$_rd_i" = "$READER" ] && continue
      _rd_others="$_rd_others $_rd_i"
    done
  fi
  if [ -z "${_rd_others# }" ]; then
    U "step 2 skipped — only one card is on the bus; custodian enrolment needs a SECOND SmartCard-HSM to export custodian keys from"
  else
    _rd_blocked=""
    for _rd_i in $_rd_others; do
      command -v hsm_reader_scsh_addressable >/dev/null 2>&1 \
        && ! hsm_reader_scsh_addressable "$_rd_i" && _rd_blocked="$_rd_blocked $_rd_i"
    done
    if [ -n "${_rd_blocked# }" ]; then
      U "step 2 skipped — a second card IS attached (reader(s)${_rd_others}) but reader(s)${_rd_blocked} cannot be addressed by Smart Card Shell: the name is a strict PREFIX of another reader's, so the custodian key import would reach the WRONG card. Passing --cust would not fix it (#398); the bus would have to change."
    else
      U "step 2 skipped — no --cust slot given, though a second addressable card is present at reader(s)${_rd_others}: pass --cust to run the rehearsal"
    fi
  fi
else
  # Addressability was settled at argument-validation time, before anything was wiped.
  printf '  FAILURE CONDITION: the pre-rotation set does not enrol, or the post-rotation address\n'
  printf '  differs. The auth proofs are operator-performed (verb unpinned) and recorded.\n'
  CUST_WORK="$(mktemp -d)"; chmod 700 "$CUST_WORK"
  CW_PIN="$CUST_WORK/pin"; printf '%s' "$PIN" > "$CW_PIN"; chmod 600 "$CW_PIN"
  DK="$CUST_WORK/dkek.pw"; head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$DK"; chmod 600 "$DK"
  sc-hsm-tool --reader "$CUST_READER" --create-dkek-share "$CUST_WORK/dkek.pbe" --password "$(cat "$DK")" >/dev/null 2>&1 \
    && sc-hsm-tool --reader "$CUST_READER" --initialize --so-pin "$SO_PIN" --pin "$PIN" --dkek-shares 1 --label cust-standin >/dev/null 2>&1 || true
  wait_card "$CUST_SLOT" "custodian stand-in" || exit 1
  sc-hsm-tool --reader "$CUST_READER" --import-dkek-share "$CUST_WORK/dkek.pbe" --password "$(cat "$DK")" --so-pin "$SO_PIN" >/dev/null 2>&1 \
    && P "custodian stand-in initialised" || { F "custodian stand-in DKEK import failed"; exit 1; }

  EXPORT_OK=1
  for i in 1 2 3 4; do
    P12PW="$CUST_WORK/cust$i.pw"
    head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$P12PW"; chmod 600 "$P12PW"
    openssl ecparam -name prime256v1 -genkey -noout -out "$CUST_WORK/cust$i.key" 2>/dev/null \
      && openssl req -x509 -new -key "$CUST_WORK/cust$i.key" -subj "/CN=rotation-drill-custodian-$i" -days 1 -out "$CUST_WORK/cust$i.crt" 2>/dev/null \
      && openssl pkcs12 -export -inkey "$CUST_WORK/cust$i.key" -in "$CUST_WORK/cust$i.crt" -out "$CUST_WORK/cust$i.p12" -password "file:$P12PW" 2>/dev/null \
      || { F "custodian $i container build failed"; EXPORT_OK=0; break; }
    "$HERE/hsm-import-key.sh" --slot "$CUST_SLOT" --reader "$CUST_READER" \
        --p12 "$CUST_WORK/cust$i.p12" --pw-file "$P12PW" --cert "$CUST_WORK/cust$i.crt" \
        --id "3$i" --label "rotation-drill-custodian-$i" \
        --dkek "$CUST_WORK/dkek.pbe" --dkek-pw "$DK" --pin-file "$CW_PIN" >/dev/null 2>&1 \
      || { F "custodian $i import failed"; EXPORT_OK=0; break; }
    # The certificate EF is the documented prerequisite (PLAN 1.4 probe): no cert, no export.
    if sc-hsm-tool --reader "$CUST_READER" --export-for-pub-key-auth "$CUST_WORK/cust$i.pub" -i "$i" >/dev/null 2>&1 && [ -s "$CUST_WORK/cust$i.pub" ]; then
      P "custodian $i key+certificate exported for PKA"
    else
      F "custodian $i export refused — the on-card-certificate prerequisite did not hold"
      EXPORT_OK=0; break
    fi
  done

  if [ "$EXPORT_OK" != "1" ]; then
    U "rotation rehearsal aborted at the export prerequisite — re-run after fixing the cert path"
  else
    hdr "STEP 2a — pre-departure state: PKA 2-of-3, custodians 1,2,3 enrolled"
    init_scratch --public-key-auth 3 --required-pub-keys 2 || exit 1
    import_auto_dkek && import_drill_key && P "re-provisioned from the seed (provisioning DKEK)" \
      || F "pre-rotation re-provision failed"
    for i in 1 2 3; do
      sc-hsm-tool --reader "$READER" --public-key-auth 3 --required-pub-keys 2 \
          --register-public-key "$CUST_WORK/cust$i.pub" >/dev/null 2>&1 \
        && P "custodian $i enrolled" || F "custodian $i enrolment failed"
    done

    hdr "STEP 2b — custodian 3 departs: re-initialise, re-provision, re-enrol 1,2 + replacement 4"
    printf '  (production MUST do this via hsm-init-hardened.js RRC-off — that script does not set\n'
    printf '   PKA today; here sc-hsm-tool is used, RRC hardcoded ON. Recorded as UNVERIFIED.)\n'
    U "rotation under the RRC-off hardened path with PKA — tooling gap, runbook step 2"
    init_scratch --public-key-auth 3 --required-pub-keys 2 || exit 1
    import_auto_dkek && import_drill_key || F "post-rotation re-provision failed"
    ADDR="$(card_address)"
    [ "$ADDR" = "$EXPECT" ] && P "post-rotation card holds the SAME address ($ADDR) — B2 makes the wipe survivable" \
                           || F "post-rotation address ${ADDR:-none} != $EXPECT"
    for i in 1 2 4; do
      sc-hsm-tool --reader "$READER" --public-key-auth 3 --required-pub-keys 2 \
          --register-public-key "$CUST_WORK/cust$i.pub" >/dev/null 2>&1 \
        && P "custodian $i enrolled (post-rotation set)" || F "custodian $i enrolment failed"
    done
    sc-hsm-tool --reader "$READER" --public-key-auth-status 2>&1 | sed 's/^/  status: /'

    hdr "STEP 2c — the two proofs (operator-performed: the custodian-auth verb is UNPINNED)"
    if [ "$AUTO" = 1 ]; then
      U "step 2c SKIPPED in --auto — the custodian-auth proofs are operator-performed by design;"
      U "  faking them hands-off would invent the answer. Re-run interactively with --cust."
    else
    printf '  PROOF 1 — THE OLD KEY MUST FAIL. Present the DEPARTED custodian 3 key via the rehearsed\n'
    printf '  PKA auth route. Expected: REFUSED, and --public-key-auth-status must not count it.\n'
    printf '  Perform it now. Did custodian 3 authentication FAIL as expected? [y/n] > '
    IFS= read -r ans
    case "$ans" in
      y|Y) P "departed custodian key no longer authenticates — revocation is real";;
      *) F "departed custodian key STILL AUTHENTICATES — C5 fails; one stale credential + one current custodian is a quorum";;
    esac
    sc-hsm-tool --reader "$READER" --public-key-auth-status 2>&1 | sed 's/^/  status: /'
    printf '  PROOF 2 — THE NEW SET MUST REACH THRESHOLD. Authenticate custodians 1 and 4, then the\n'
    printf '  script attempts a sign. Expected: Authenticated: 2; the sign verifies against the\n'
    printf '  original public key. Press Enter when both have authenticated. > '
    IFS= read -r _
    sc-hsm-tool --reader "$READER" --public-key-auth-status 2>&1 | sed 's/^/  status: /'
    rc=0; sign_proof "$PUB_ORIG" || rc=$?
    if [ "$rc" = 0 ]; then
      P "the rotated set signs, verified against the original pubkey (wrong-digest control clean)"
    elif [ "$rc" = 2 ]; then
      F "the verifier accepted a WRONG digest — every verify line above is worthless"
    else
      U "no signature after the reported authentications — assert the auth route by hand and record"
    fi
    fi
  fi
  rm -rf "$CUST_WORK"
fi

# =================================================================================================
hdr "STEP 3 — SLIP-39 SEED RECOVERY round-trip (host-only; no card)"
printf '  FAILURE CONDITION: a recovered mnemonic differs from the minted one, a recovered address\n'
printf '  differs from the original, or 3 shares RECOVER (B5: no sub-threshold reconstruction).\n'
if ! python3 -c "import mnemonic, shamir_mnemonic" 2>/dev/null; then
  U "python 'mnemonic'/'shamir-mnemonic' packages missing — SLIP-39 arm skipped"
else
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/entropy.hex"
  python3 "$SLIP39" --from-entropy --in "$WORK/entropy.hex" --out "$WORK/seed.mnemonic" 2>/dev/null \
    && P "throwaway seed minted from /dev/urandom entropy" || F "seed mint failed"
  ADDR_ORIG="$(python3 "$DERIVE" --mnemonic-file "$WORK/seed.mnemonic" 2>/dev/null | grep -oE 'akash1[a-z0-9]+' | head -1)"
  [ -n "$ADDR_ORIG" ] && P "original address: $ADDR_ORIG" || F "no address from the minted seed"
  python3 "$SLIP39" --in "$WORK/seed.mnemonic" --threshold 4 --shares 6 --out "$WORK/slip39.txt" 2>/dev/null \
    && P "split 4-of-6 (reconstruct-verified by the tool itself)" || F "SLIP-39 split failed"
  grep -v '^#' "$WORK/slip39.txt" | grep . > "$WORK/shares.txt"
  n=0; : > "$WORK/q1.txt"; : > "$WORK/q2.txt"
  while IFS= read -r line; do
    n=$((n+1))
    [ "$n" -le 4 ] && printf '%s\n' "$line" >> "$WORK/q1.txt"
    [ "$n" -ge 3 ] && printf '%s\n' "$line" >> "$WORK/q2.txt"
  done < "$WORK/shares.txt"
  for q in q1 q2; do
    if ! python3 "$SLIP39" --recover --in "$WORK/$q.txt" --out "$WORK/$q.mnemonic" 2>/dev/null; then
      F "recovery from quorum $q failed"; continue
    fi
    if [ "$(tr -d '[:space:]' < "$WORK/$q.mnemonic")" = "$(tr -d '[:space:]' < "$WORK/seed.mnemonic")" ]; then
      ADDR_RT="$(python3 "$DERIVE" --mnemonic-file "$WORK/$q.mnemonic" 2>/dev/null | grep -oE 'akash1[a-z0-9]+' | head -1)"
      [ "$ADDR_RT" = "$ADDR_ORIG" ] && P "quorum $q recovers the EXACT seed; address matches ($ADDR_RT)" \
                                   || F "quorum $q recovered a seed deriving ${ADDR_RT:-none} != $ADDR_ORIG"
    else
      F "quorum $q recovered a DIFFERENT mnemonic"
    fi
  done
  head -3 "$WORK/shares.txt" > "$WORK/three.txt"
  if python3 "$SLIP39" --recover --in "$WORK/three.txt" --out "$WORK/three.mnemonic" 2>/dev/null; then
    if [ "$(tr -d '[:space:]' < "$WORK/three.mnemonic")" = "$(tr -d '[:space:]' < "$WORK/seed.mnemonic")" ]; then
      F "3 of 6 shares RECOVERED the seed — the 4-of-6 threshold is not enforced (B5 fails)"
    else
      P "3 shares yield only a WRONG seed — but SILENTLY; record that the tool did not error"
    fi
  else
    P "3 of 6 shares fail to reconstruct (B5: below threshold leaks nothing)"
  fi
fi

# =================================================================================================
hdr "STEP 4 — RE-PROVISION PROOF (requirement A4's core): unwrap the blob, SAME address back"
printf '  FAILURE CONDITION: after a fresh wipe, the ceremony-wrapped blob does not unwrap, the\n'
printf '  restored key does not sign, the signature does not verify against the ORIGINAL public\n'
printf '  key, or the address differs from %s.\n' "$EXPECT"
init_scratch || exit 1
import_auto_dkek && P "provisioning DKEK restored (password path)" \
  || { F "provisioning DKEK import failed — the blob cannot be unwrapped"; }
unwrap_key "$WRAPPED" 1 \
  && P "ceremony-wrapped blob unwrapped onto the fresh card" \
  || { F "unwrap failed — the ceremony artefact did not survive the drill"; }
ADDR="$(card_address)"
if [ -n "$ADDR" ]; then
  [ "$ADDR" = "$EXPECT" ] && P "the SAME address came back: $ADDR" || F "address ${ADDR} != $EXPECT"
else
  U "pubkey not readable after unwrap (unwrapped keys carry no cert) — proving by signature instead"
fi
rc=0; sign_proof "$PUB_ORIG" || rc=$?
if [ "$rc" = 0 ]; then
  P "the restored key SIGNS and verifies against the original pubkey — key identity proven (A4)"
elif [ "$rc" = 2 ]; then
  F "the verifier accepted a WRONG digest — the sign proofs in this drill are worthless"
else
  F "the restored key did not produce a verifiable signature"
fi

hdr "RESULT"
printf '  %d passed, %d failed, %d unverified\n' "$pass" "$fail" "$unv"
# A run that needed a debug probe to get the card back must NOT read as a clean run. The escape
# hatch exists so one wedge does not cost the whole drill, but it is bench instability and it has
# to survive into the summary — a transcript line 400 lines up is not where anyone looks, and
# "0 failed" that quietly depended on out-of-band SWD recovery is the kind of green this project
# has been burned by before.
if [ "${_reenum_recovered:-0}" = 1 ]; then
  printf '\n  \033[33mNOTE: the card had to be revived by HSM_REENUM_RECOVER_CMD during this run.\033[0m\n'
  printf '  It stopped re-enumerating on its own after an INITIALIZE and was recovered out of band.\n'
  printf '  The verdicts above stand, but this run did NOT demonstrate unattended re-provisioning.\n'
fi
printf '\n  \033[1mD1 IS STILL OPEN.\033[0m This is a Pico standing in for the Nitrokey HSM 2.\n'
printf '  Transcript: %s — paste into doc/drills/YYYY-MM-DD-recovery-drill.md.\n' "$TRANSCRIPT"
[ "$fail" -eq 0 ] || exit 1
