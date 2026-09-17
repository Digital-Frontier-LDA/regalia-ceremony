#!/usr/bin/env bash
# hsm-staging-e2e.sh — end-to-end validation of this repo's HSM tooling against the SINGLE
# staging Pico HSM, hands-off, with a transcript. DESTRUCTIVE BY DESIGN: it wipes and
# re-provisions the card in every phase. Hard-guarded to the documented staging serial
# (ESPICOHSMTR) — it refuses to touch anything else. This is the staging/drill device and
# holds only replaceable staging material; never point it at a card that matters.
#
#   HSM_PKCS11_MODULE=/opt/homebrew/lib/opensc-pkcs11.so \
#   SCSH_HOME=~/tools/scsh-3.18.77 \
#   qubes/scripts/hsm-staging-e2e.sh
#
# Phases, each with a stated FAILURE CONDITION and a PASS/FAIL/SKIPPED verdict:
#
#   a  HARDENED INIT — wipe + re-init via hsm-init-hardened.js with HSM_RRC_MODE=off (the
#      ratified D3 posture; also validates the script's rewritten default and its VERIFY
#      output on real hardware). The expected SCARD_E_NOT_TRANSACTED/CARD_REMOVED ending is
#      handled; the card is polled back onto the bus.
#   b  BEHAVIOURAL RRC VERIFY — the SO-PIN reset attack MUST fail (CKR_GENERAL_ERROR), the
#      attacker-chosen PIN MUST NOT open the card, the init-time PIN MUST, and sc-hsm-tool
#      MUST NOT print "User PIN reset with SO-PIN enabled". Flags are never trusted.
#   c  PRODUCTION POSTURE — re-init with a 10-digit user PIN and HSM_PIN_RETRIES=10; the card
#      must report "User PIN tries left: 10" (PLAN.md 1.3's outcome).
#   d  PKA PROBE — the single-card slice of PLAN.md 1.4: init --public-key-auth 3
#      --required-pub-keys 2, assert --public-key-auth-status parses, then the open question
#      the 2026-08-01 probe left: can custodian keys WITH CERTIFICATES on the SAME card be
#      exported (--export-for-pub-key-auth) and registered (--register-public-key)? The probe
#      failed the export with "Wrong key reference" and inferred a second card is needed —
#      but its keys had no certs. Either outcome is a recorded finding. If registration
#      works: enrol 2 custodians and answer question (a) — does PKA REPLACE the PIN once
#      custodians are enrolled? Power-cycle arms are SKIPPED (need a physical reseat), never
#      faked.
#   e  RECOVERY DRILL --auto — hsm-recovery-drill.sh steps 1/3/4 hands-off: the corrected
#      break-glass command (--import-dkek-share dkek.pbe --pwd-shares-total 4, share prompts
#      fed programmatically), the wrong-share negative control, the SLIP-39 4-of-6
#      round-trip, and re-provision-from-seed → same address.
#
# THE SO-PIN IS TRIED EXACTLY ONCE. Preflight does a single pkcs11-tool SO login with the
# documented staging SO-PIN (HSM_SO_PIN, default 3537363231383830 — the pico-hsm example
# value this staging card was provisioned with). If the card answers CKR_PIN_INCORRECT,
# every destructive phase is SKIPPED and the run reports it — the SO-PIN retry counter is
# finite and guessing is not a strategy.
#
# NOTHING HERE TOUCHES A REAL SEED. Every key derives from the published BIP39 test vector
# (worthless by construction) or from /dev/urandom throwaways minted for the occasion. All
# PINs below are throwaway and live only in the transcript. GPG's scdaemon is killed at
# preflight — it grabs the reader and turns card operations into inexplicable failures.
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
P11="${HSM_PKCS11_MODULE:-/usr/lib/opensc-pkcs11.so}"
. "$(cd "$HERE/../.." && pwd)/tools/hsm-bench-lock.sh"
hsm_bench_lock_acquire wait || exit $?

# CAPTURE, THEN MATCH — never `pkcs11-tool ... | grep -q` under `pipefail`.
# grep -q quits at the first match, pkcs11-tool takes SIGPIPE and exits 141, and pipefail reports
# 141 — so the predicate reads FALSE exactly when the token appeared. Measured on sc-hsm-tool
# 2026-08-08: inverted 5/5 with pipefail, correct 5/5 without. In an `until` loop that means
# spinning to the retry ceiling and then declaring the card missing when it was there all along.
# shellcheck disable=SC2120  # the optional argument IS the interface: both callers want the
# default ($SLOTID), and a caller targeting another slot passes one. Dropping the parameter to
# silence this would make that impossible and save nothing.
_slot_has_token(){
  local _s
  _s="$(pkcs11-tool --module "$P11" --slot "${1:-$SLOTID}" --list-slots 2>/dev/null)"
  grep -q 'token label' <<< "$_s"
}

SCSH="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}"
SLOT="${HSM_SLOT:-0}"
# See hardware/pico-hsm/UPSTREAM-DEVAUT-DEADLOCK.md: ESPICOHSMTR was a hardcoded firmware
# fallback that gave EVERY device the same serial. Patched firmware derives ESP + 8 hex + 00001
# from the board id, so this staging board is ESP2202E14A. Override for any other card.
EXPECT_SERIAL="${HSM_E2E_SERIAL:-ESP2202E14A}"

# $SLOT was doing two jobs: a PKCS#11 slot ID for pkcs11-tool and a PC/SC reader index for
# sc-hsm-tool. That works only while exactly one card is attached. With two, the numbers diverge
# — measured 2026-09-03, the PKCS#11 slot IDs were 0x0 and 0x4 while the PC/SC readers were 0 and
# 1, so "slot 0" named one card and "reader 0" named the other. This suite performs INITIALIZE
# DEVICE, so that is not a reporting bug, it is a wipe aimed at the wrong device.
#
# Resolve both from the serial we already require. Single-card hosts are unchanged.
READER="${HSM_PCSC_INDEX:-$SLOT}"
SLOTID="${HSM_SLOT_ID:-$SLOT}"
if [ -z "${HSM_E2E_NO_AUTOTARGET:-}" ] && [ -n "$EXPECT_SERIAL" ]; then
  _rs="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-reader-select.sh"
  if [ -f "$_rs" ]; then
    # shellcheck source=/dev/null
    . "$_rs"
    if [ "$(hsm_reader_indices 2>/dev/null | wc -l | tr -d ' ')" -gt 1 ]; then
      _r="$(hsm_reader_for "$EXPECT_SERIAL" 2>/dev/null)" || _r=""
      _i="$(hsm_slot_id_for "$EXPECT_SERIAL" 2>/dev/null)" || _i=""
      if [ -n "$_r" ] && [ -n "$_i" ]; then
        READER="$_r"; SLOTID="$_i"
        printf '  targeting %s — PC/SC reader %s, PKCS#11 slot id %s\n' "$EXPECT_SERIAL" "$READER" "$SLOTID"
      else
        printf '  WARNING: two readers but could not resolve %s; using slot/reader %s\n' "$EXPECT_SERIAL" "$SLOT" >&2
      fi
    fi
  fi
fi
SO_PIN_HEX="${HSM_SO_PIN:-3537363231383830}"
# THE ROLE REGISTRY GATE. This suite performs INITIALIZE DEVICE (a wipe) on $EXPECT_SERIAL. The
# JS children re-verify the card's EF 2F02 serial, but that proves only that the wipe lands on the
# card this script AIMED at — not that aiming there was permissible. The committed registry
# (tools/hsm-staging-registry.json) is that permission, default-deny. Sourced above in the autotarget block;
# source again unconditionally so the gate holds on every path, and refuse without it.
_e2e_rs="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-reader-select.sh"
# shellcheck source=/dev/null
[ -f "$_e2e_rs" ] && . "$_e2e_rs"
if command -v hsm_assert_staging >/dev/null 2>&1; then
    hsm_assert_staging "$EXPECT_SERIAL" || exit 2
else
    # printf, not err(): err() is defined below, and a function resolves at CALL time — calling
    # it above its definition prints "command not found" and runs on. The exit must not depend
    # on a helper that does not exist yet.
    printf '  !! the role registry gate (tools/hsm-reader-select.sh) is unavailable — a suite that\n' >&2
    printf '  !! runs INITIALIZE DEVICE does not run without the default-deny gate.\n' >&2
    exit 2
fi
ATTACK_PIN="999999"
PIN_B="${HSM_E2E_PIN_B:-731946}"        # throwaway, phases a/b (6-digit, retries 3)
PIN_C="${HSM_E2E_PIN_C:-5829061437}"    # throwaway, phase c (10-digit, retries 10)
PIN_D="${HSM_E2E_PIN_D:-602847}"        # throwaway, phase d (6-digit)
DRILL_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

pass=0; fail=0; skip=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
S(){ printf '  \033[33mSKIPPED\033[0m %s\n' "$1"; }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
err(){ printf '  \033[31m!!\033[0m %s\n' "$*" >&2; }

RESULTS="$(mktemp)"   # phase|RESULT|one-line evidence
rec(){ # $1=phase $2=PASS|FAIL|SKIPPED $3=evidence
  case "$2" in PASS) pass=$((pass+1));; FAIL) fail=$((fail+1));; *) skip=$((skip+1));; esac
  printf '%s\n' "$3" | head -1 | sed "s/'/ /g" | \
    { IFS= read -r ev; printf '%s|%s|%s\n' "$1" "$2" "$ev" >> "$RESULTS"; }
  case "$2" in PASS) P "$1 — $3";; FAIL) F "$1 — $3";; *) S "$1 — $3";; esac
}

# INITIALIZE DEVICE drops the Pico off the USB bus mid-command (measured 2026-08-01): an
# init's exit status means nothing. Poll the card back; verify everything by behaviour.
wait_card(){ # $1=name
  local tries=0
  until _slot_has_token; do
    tries=$((tries+1))
    [ "$tries" -gt 40 ] && { err "$1 did not re-enumerate after ~2 minutes — reseat and re-run."; return 1; }
    sleep 3
  done
  sleep 2   # settle: re-enumeration races the very next command (measured)
  printf '  card is back on the bus\n'
}

hardened_init(){ # $1=user-pin $2=retries $3=logfile — via scsh, RRC OFF
  # NAME THE CARD, AND MAKE THE SCRIPT PROVE IT GOT THERE.
  # This passed no reader at all, so scsh bound to whatever PC/SC enumerated first. With one card
  # that is fine; with two it is an INITIALIZE DEVICE — a full wipe — aimed by luck. It has been
  # working only because the staging card happens to hold the suffixed reader name, and the two
  # names swapped when the bench was replugged on 2026-09-03.
  # HSM_EXPECT_SERIAL is the backstop: scsh matches reader names by PREFIX and cannot address a
  # card whose name is a prefix of another's, so being unable to name it is not hypothetical.
  local _hi_name=""
  command -v hsm_reader_name >/dev/null 2>&1 && _hi_name="$(hsm_reader_name "$READER")"
  # HSM_EXPECT_SERIAL is a backstop INSIDE the initializer, which means the refusal arrives as a
  # JavaScript exception from a step that has already been launched at a card. Ask first: if scsh
  # cannot address this reader the run cannot proceed correctly, and saying so here names the bench
  # topology instead of leaving a "WRONG CARD" error to be read as a guard misfiring. Measured
  # 2026-09-11: e2e_phases.log:71 recorded serial ESP41D722E2 while this suite was pinned to
  # ESP2202E14A, so the unaddressable case is what actually happens here, not a hypothetical.
  if command -v hsm_require_scsh_addressable >/dev/null 2>&1; then
    hsm_require_scsh_addressable "$READER" "$EXPECT_SERIAL" || return 1
  fi
  ( cd "$SCSH" && HSM_SO_PIN="$SO_PIN_HEX" HSM_USER_PIN="$1" HSM_PIN_RETRIES="$2" \
      HSM_READER="$_hi_name" HSM_EXPECT_SERIAL="$EXPECT_SERIAL" \
      HSM_RRC_MODE=off HSM_LABEL=staging-e2e ./scriptrunner "$HERE/hsm-init-hardened.js" \
  ) > "$3" 2>&1
  # exit status deliberately ignored — the card drops off the bus at the end of initialize()
  wait_card "card"
}

# SO-PIN as pkcs11-tool wants it: the 16-character HEX string, NOT the ASCII decoding of it.
# OpenSC encodes each pair of hex characters into one byte of the 8-byte initialisation code
# (card-sc-hsm.c sc_hsm_encode_sopin), so "3537363231383830" arrives as the same 8 bytes scsh
# sets from ByteString(hex, HEX). MEASURED 2026-08-02: the decoded ASCII form ("57621880")
# fails client-side with CKR_PIN_LEN_RANGE and is never presented to the card — the same
# latent bug hsm-fleet-drill.sh carried until today.
SO_PIN_P11="${HSM_SO_PIN_P11:-$SO_PIN_HEX}"
[[ "$SO_PIN_P11" =~ ^[0-9A-Fa-f]{16}$ ]] || { err "SO-PIN is not 16 hex digits; set HSM_SO_PIN_P11"; exit 2; }

# =================================================================================================
RUN_DIR="${HSM_E2E_DIR:-${TMPDIR:-/tmp}/hsm-staging-e2e}"
mkdir -p "$RUN_DIR"; chmod 700 "$RUN_DIR"
TRANSCRIPT="$RUN_DIR/e2e-transcript-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$TRANSCRIPT") 2>&1
printf '  transcript: %s\n' "$TRANSCRIPT"
printf '  device under test: PKCS#11 slot id %s / PC/SC reader %s, expected serial %s\n' "$SLOTID" "$READER" "$EXPECT_SERIAL"
printf '  throwaway PINs (transcript only): phase-b %s · phase-c %s · phase-d %s · attack %s\n' \
  "$PIN_B" "$PIN_C" "$PIN_D" "$ATTACK_PIN"

hdr "PHASE 0 — preflight"
printf '  FAILURE CONDITION: tools/module missing, the attached card is not the staging serial,\n'
printf '  or GPGs scdaemon is holding the reader.\n'
pkill -f scdaemon 2>/dev/null && printf '  killed a running scdaemon (it grabs the reader)\n' || true
for t in pkcs11-tool sc-hsm-tool openssl python3; do
  command -v "$t" >/dev/null || { rec 0 FAIL "missing tool: $t"; exit 1; }
done
[ -f "$P11" ] || { rec 0 FAIL "no PKCS#11 module at $P11 — set HSM_PKCS11_MODULE"; exit 1; }
[ -x "$SCSH/scriptrunner" ] || { rec 0 FAIL "no scsh scriptrunner at $SCSH — set SCSH_HOME"; exit 1; }
# `--list-slots` prints EVERY slot regardless of --slot, so `head -1` reads whichever card is
# listed first, not ours. With two attached that is how a suite can "confirm" the staging serial
# and then operate on the other device.
if command -v hsm_serial_at_slot_id >/dev/null 2>&1; then
  SERIAL="$(hsm_serial_at_slot_id "$SLOTID")"
else
  SERIAL="$(pkcs11-tool --module "$P11" --slot "$SLOTID" --list-slots 2>/dev/null | grep -oE 'serial num *: *[A-Za-z0-9]+' | head -1 | awk '{print $NF}')"
fi
if [ "$SERIAL" != "$EXPECT_SERIAL" ]; then
  rec 0 FAIL "slot $SLOTID serial '${SERIAL:-none}' != staging serial $EXPECT_SERIAL — REFUSING to touch it"
  exit 1
fi
P "staging card confirmed: serial $SERIAL on PKCS#11 slot id $SLOTID (PC/SC reader $READER)"
sc-hsm-tool --reader "$READER" 2>&1 | grep -E 'Version|SO-PIN|User PIN|DKEK shares' | sed 's/^/  preflight: /'
rec 0 PASS "tools present; card is the staging serial $SERIAL"

# =================================================================================================
hdr "PHASE 0b — the SO-PIN, tried EXACTLY ONCE"
printf '  FAILURE CONDITION: CKR_PIN_INCORRECT — the documented staging SO-PIN is wrong and ALL\n'
printf '  destructive phases are skipped. The SO-PIN counter is finite; nothing here guesses.\n'
out="$(pkcs11-tool --module "$P11" --slot "$SLOTID" --login --login-type so \
    --so-pin "$SO_PIN_P11" --list-objects 2>&1)"; rc=$?
CAN_WRITE=0
if [ "$rc" = 0 ]; then
  CAN_WRITE=1
  rec 0b PASS "SO login accepted the documented staging SO-PIN on the first and only attempt"
elif grep -q 'CKR_PIN_INCORRECT' <<< "$out"; then
  rec 0b FAIL "CKR_PIN_INCORRECT — the staging SO-PIN is WRONG; halting all destructive work"
else
  rec 0b FAIL "SO login inconclusive (rc=$rc: $(printf '%s' "$out" | tail -1)) — treating as NO-GO for destructive work"
fi
sc-hsm-tool --reader "$READER" 2>&1 | grep -E 'SO-PIN tries' | sed 's/^/  after the single attempt: /'

skip_rest(){ # $1=phase $2=name — destructive phase with no SO-PIN
  hdr "PHASE $1 — $2"
  rec "$1" SKIPPED "no usable SO-PIN (phase 0b) — destructive work halted by design"
}

# =================================================================================================
if [ "$CAN_WRITE" != 1 ]; then
  skip_rest a "hardened init (RRC off)"
  skip_rest b "behavioural RRC verify"
  skip_rest c "production posture (10-digit PIN, 10 retries)"
  skip_rest d "PKA probe"
  skip_rest e "recovery drill --auto"
else

# =================================================================================================
hdr "PHASE a — hardened init via hsm-init-hardened.js, HSM_RRC_MODE=off"
printf '  FAILURE CONDITION: the scsh run never reaches initialize, the options line is not\n'
printf '  mode=off / options=0x0, or the card does not come back on the bus.\n'
hardened_init "$PIN_B" 3 "$RUN_DIR/phase-a-scsh.log" || { rec a FAIL "card did not re-enumerate after hardened init"; }
if grep -q 'STEP options: mode=off — options=0x0' "$RUN_DIR/phase-a-scsh.log"; then
  P "scsh sent options=0x0 (RRC fully off) — the rewritten default said what it did"
else
  F "options line missing/wrong in scsh log:"; grep -E 'STEP|NOTE' "$RUN_DIR/phase-a-scsh.log" | sed 's/^/    /'
fi
grep -qE 'SCARD_E_NOT_TRANSACTED|CARD_REMOVED' "$RUN_DIR/phase-a-scsh.log" \
  && P "ended on the EXPECTED card-drop exception (documented Pico behaviour, not a failure)" \
  || P "no card-drop exception this run (also fine — verify by behaviour below)"
grep -q 'INIT COMPLETE — BUT NOT VERIFIED' "$RUN_DIR/phase-a-scsh.log" \
  && P "the script's VERIFY block printed its 'verify behaviourally' instructions" \
  || printf '  (scsh log ended before the VERIFY block — the card dropped first; behaviour decides)\n'
if _slot_has_token; then
  rec a PASS "hardened init ran (options=0x0) and the card re-enumerated; behaviour verified in phase b"
else
  rec a FAIL "card absent after hardened init"
fi

# =================================================================================================
hdr "PHASE b — behavioural RRC verify (the SO-PIN reset attack MUST be refused)"
printf '  FAILURE CONDITION: C_InitPIN succeeds, the attacker PIN opens the card, the original\n'
printf '  PIN stops working, or sc-hsm-tool prints the vulnerable-config tell.\n'
B_OK=1
out="$(pkcs11-tool --module "$P11" --slot "$SLOTID" --login --login-type so \
    --so-pin "$SO_PIN_P11" --init-pin --new-pin "$ATTACK_PIN" 2>&1)"; rc=$?
if [ "$rc" != 0 ] && grep -q 'CKR_GENERAL_ERROR' <<< "$out"; then
  P "C_InitPIN REFUSED with CKR_GENERAL_ERROR — the attack is blocked"
else
  F "C_InitPIN was NOT refused as expected (rc=$rc: $(printf '%s' "$out" | tail -1))"; B_OK=0
fi
if pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$ATTACK_PIN" --list-objects >/dev/null 2>&1; then
  F "the attacker-chosen PIN OPENED the card — the reset took"; B_OK=0
else
  P "the attacker-chosen PIN is refused"
fi
if pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN_B" --list-objects >/dev/null 2>&1; then
  P "the init-time PIN still opens the card (retry counter restored)"
else
  F "the init-time PIN no longer works"; B_OK=0
fi
# CAPTURE, THEN MATCH. `sc-hsm-tool --reader "$READER" | grep -q` under `pipefail` is the predicate measured
# inverting 5/5 on 2026-08-08: grep -q quits on the match, sc-hsm-tool takes SIGPIPE and exits
# 141, and pipefail reports 141 — so it answers FALSE precisely when the pattern IS present.
# Here that inverts a SECURITY check into a false PASS: the vulnerable-RRC tell would be on the
# card, the match would succeed, the condition would read false, and the else branch would
# assert that the hardened posture holds. A posture check that cannot see the vulnerable state
# is worse than no check, because it is quoted as evidence.
_sct="$(sc-hsm-tool --reader "$READER" 2>&1)"
if grep -q 'User PIN reset with SO-PIN enabled' <<< "$_sct"; then
  F "sc-hsm-tool prints the vulnerable-config tell"; B_OK=0
else
  P "sc-hsm-tool does NOT print 'User PIN reset with SO-PIN enabled' (the accurate tell)"
fi
[ "$B_OK" = 1 ] && rec b PASS "attack refused (CKR_GENERAL_ERROR); original PIN works; no vulnerable tell" \
                || rec b FAIL "RRC-off posture did NOT hold behaviourally — see lines above"

# =================================================================================================
hdr "PHASE c — production posture: 10-digit PIN with retry counter 10 (PLAN.md 1.3)"
printf '  FAILURE CONDITION: the card does not report exactly User PIN tries left: 10 after a\n'
printf '  hardened re-init with HSM_PIN_RETRIES=10 and a 10-digit PIN.\n'
hardened_init "$PIN_C" 10 "$RUN_DIR/phase-c-scsh.log"
TRIES="$(sc-hsm-tool --reader "$READER" 2>&1 | grep -oE 'User PIN tries left *: *[0-9]+' | grep -oE '[0-9]+$')"
if [ "$TRIES" = "10" ]; then
  rec c PASS "card reports User PIN tries left: 10 with a 10-digit PIN (PLAN 1.3 outcome reproduced)"
else
  rec c FAIL "card reports 'User PIN tries left: ${TRIES:-unreadable}' — expected 10"
fi

# =================================================================================================
hdr "PHASE d — PKA probe: same-card custodians WITH certificates (PLAN.md 1.4, single card)"
printf '  FAILURE CONDITION (gate): --public-key-auth-status does not parse after a PKA init.\n'
printf '  Everything past that is an OPEN QUESTION — failures are recorded findings, not script\n'
printf '  bugs. Power-cycle arms are SKIPPED: they need a physical reseat.\n'
DW="$(mktemp -d)"; chmod 700 "$DW"
printf '%s' "$PIN_D" > "$DW/pin"; chmod 600 "$DW/pin"
head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$DW/dkek.pw"; chmod 600 "$DW/dkek.pw"
D_GATE=0
# VERIFY THE ARTEFACT, NOT THE EXIT STATUS. With no -r, this call takes PC/SC reader 0, prints
# "Failed to connect to card" to a discarded stream, writes NO FILE, and still satisfies a bare
# `&&` (measured 2026-09-03). The failure then surfaced two steps later as a card problem. A step
# that is supposed to produce a file has not succeeded until the file exists and is non-empty.
sc-hsm-tool --reader "$READER" --create-dkek-share "$DW/dkek.pbe" --password "$(cat "$DW/dkek.pw")" >/dev/null 2>&1 \
  && [ -s "$DW/dkek.pbe" ] \
  && sc-hsm-tool --reader "$READER" --initialize --so-pin "$SO_PIN_HEX" --pin "$PIN_D" \
       --dkek-shares 1 --label pka-e2e --public-key-auth 3 --required-pub-keys 2 > "$DW/init.log" 2>&1 || true
printf '  (init exit status ignored — the Pico drops off the USB bus; verifying by behaviour)\n'
if wait_card "card" \
  && sc-hsm-tool --reader "$READER" --import-dkek-share "$DW/dkek.pbe" \
       --password "$(cat "$DW/dkek.pw")" --so-pin "$SO_PIN_HEX" >/dev/null 2>&1; then
  st="$(sc-hsm-tool --reader "$READER" --public-key-auth-status 2>&1)"
  printf '%s\n' "$st" | sed 's/^/  status: /'
  # Measured Pico format (2026-08-02): "Number of public keys: 3 / Missing public keys: 3 /
  # Required pubkeys for auth: 2 / Authenticated public keys: 0". "Number of public keys" is
  # the CAPACITY, not the enrolment count — registered = capacity - missing.
  ST_CAP="$(printf '%s' "$st" | grep -oiE 'number of public keys[^:]*: *[0-9]+' | grep -oE '[0-9]+' | head -1)"
  ST_MIS="$(printf '%s' "$st" | grep -oiE 'missing[^:]*: *[0-9]+' | grep -oE '[0-9]+' | head -1)"
  ST_REQ="$(printf '%s' "$st" | grep -oiE 'required[^:]*: *[0-9]+' | grep -oE '[0-9]+' | head -1)"
  ST_REG=""; [[ "${ST_CAP:-}" =~ ^[0-9]+$ && "${ST_MIS:-}" =~ ^[0-9]+$ ]] && ST_REG=$((ST_CAP - ST_MIS))
  if [ "$ST_REG" = "0" ] && [ "${ST_MIS:-}" = "3" ] && [ "${ST_REQ:-}" = "2" ]; then
    P "PKA init took: 0 registered / 3 missing / 2 required — the status readout parses"
    D_GATE=1
  else
    rec d FAIL "PKA status did not parse as 0/3/2 (got ${ST_REG:-?}/${ST_MIS:-?}/${ST_REQ:-?})"
  fi
else
  rec d FAIL "PKA initialisation or DKEK import failed"
fi

if [ "$D_GATE" = 1 ]; then
  # Two throwaway custodian keys + the test-vector signing key, all WITH certificates, all on
  # THIS card. Import order fixes the SmartCard-HSM key references: cust1=1, cust2=2, signer=3.
  # Labels deliberately inside hsm-recovery-drill.sh's wipe-safe allowlist so phase e can run.
  D_IMPORTS=1
  # One && chain with every stream discarded cannot say WHICH step failed, and "container/import
  # failed" covers four host-side openssl calls and one on-card import that mean completely
  # different things — a host toolchain gap versus a card that refuses the import. Name the stage
  # and keep the error, so the recorded finding is a measurement rather than a guess.
  cust_stage() {   # $1 = stage name; rest = command. Sets STAGE/STAGE_OUT on failure.
    local name="$1"; shift
    [ -n "$STAGE" ] && return 0            # already failed; do not run later stages
    STAGE_OUT="$("$@" 2>&1)" || STAGE="$name"
    return 0
  }
  # Prefer the line that says WHAT went wrong over the stack trace beneath it. `tail -2` surfaced
  # "at SmartCardHSM.js#1580" and buried "SW1/SW2=6982" — the same mistake the CI gate made when it
  # reported a bystander CVC_* line instead of the verifier's own FAILED: reason.
  stage_reason(){
    local r
    r="$(printf '%s' "$1" | grep -aiE 'SW1/SW2|GPError|error:|refused|denied' | head -1)"
    [ -n "$r" ] || r="$(printf '%s' "$1" | grep -viE '^[[:space:]]*$' | tail -1)"
    printf '%s' "$r" | sed 's/^[[:space:]]*//' | cut -c1-200
  }
  D_FAIL_OUT=""
  for i in 1 2; do
    head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$DW/cust$i.pw"; chmod 600 "$DW/cust$i.pw"
    STAGE=""; STAGE_OUT=""
    cust_stage "openssl ecparam" openssl ecparam -name prime256v1 -genkey -noout -out "$DW/cust$i.key"
    cust_stage "openssl req" openssl req -x509 -new -key "$DW/cust$i.key" \
        -subj "/CN=rotation-drill-custodian-$i" -days 1 -out "$DW/cust$i.crt"
    cust_stage "openssl pkcs12" openssl pkcs12 -export -inkey "$DW/cust$i.key" -in "$DW/cust$i.crt" \
        -out "$DW/cust$i.p12" -password "file:$DW/cust$i.pw"
    cust_stage "hsm-import-key.sh (on-card)" "$HERE/hsm-import-key.sh" --slot "$SLOTID" --reader "$READER" \
        --p12 "$DW/cust$i.p12" --pw-file "$DW/cust$i.pw" --cert "$DW/cust$i.crt" \
        --id "3$i" --label "rotation-drill-custodian-$i" \
        --dkek "$DW/dkek.pbe" --dkek-pw "$DW/dkek.pw" --pin-file "$DW/pin"
    if [ -z "$STAGE" ]; then
      P "custodian $i imported WITH certificate (key-reference $i)"
    else
      F "custodian $i failed at [$STAGE]: $(stage_reason "$STAGE_OUT")"
      D_FAIL_OUT="$STAGE_OUT"; D_IMPORTS=0; break
    fi
  done
  printf '%s' "$DRILL_MNEMONIC" > "$DW/mnemonic"; chmod 600 "$DW/mnemonic"
  head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$DW/drill.pw"; chmod 600 "$DW/drill.pw"
  # Same treatment as the custodian loop: "signing-key import failed" spanned a seed derivation, a
  # certificate mint and an on-card import, which fail for unrelated reasons.
  STAGE=""; STAGE_OUT=""
  cust_stage "seed-to-pkcs12.py" python3 "$HERE/seed-to-pkcs12.py" --mnemonic-file "$DW/mnemonic" \
      --password-file "$DW/drill.pw" --out "$DW/drill.p12"
  if [ -z "$STAGE" ]; then
    # The key is extracted in its own step rather than inside a process substitution, so a failure
    # here is attributable instead of surfacing as an opaque openssl req error.
    cust_stage "openssl pkcs12 (extract key)" sh -c \
        "umask 077; openssl pkcs12 -in '$DW/drill.p12' -nocerts -nodes -passin 'file:$DW/drill.pw' > '$DW/drill.key'"
    cust_stage "openssl req (drill cert)" openssl req -x509 -new -key "$DW/drill.key" \
        -subj "/CN=recovery-drill-throwaway" -days 1 -out "$DW/drill.crt"
    cust_stage "hsm-import-key.sh (on-card)" "$HERE/hsm-import-key.sh" --slot "$SLOTID" --reader "$READER" \
        --p12 "$DW/drill.p12" --pw-file "$DW/drill.pw" --cert "$DW/drill.crt" \
        --id 33 --label recovery-drill-throwaway \
        --dkek "$DW/dkek.pbe" --dkek-pw "$DW/dkek.pw" --pin-file "$DW/pin"
  fi
  if [ -z "$STAGE" ]; then
    P "test-vector signing key imported WITH certificate (key-reference 3)"
  else
    F "signing key failed at [$STAGE]: $(stage_reason "$STAGE_OUT")"
    [ -n "$D_FAIL_OUT" ] || D_FAIL_OUT="$STAGE_OUT"
    D_IMPORTS=0
  fi
  rm -f "$DW/drill.key"

  D_EXPORT=0
  if [ "$D_IMPORTS" = 1 ]; then
    D_EXPORT=1
    for i in 1 2; do
      eout="$(sc-hsm-tool --reader "$READER" --export-for-pub-key-auth "$DW/cust$i.pub" -i "$i" 2>&1)"; erc=$?
      if [ "$erc" = 0 ] && [ -s "$DW/cust$i.pub" ]; then
        P "custodian $i exported for PKA from THIS card (certificate EF present)"
      else
        F "custodian $i export failed (rc=$erc): $(printf '%s' "$eout" | tail -1)"
        D_EXPORT=0
      fi
    done
  fi

  if [ "$D_IMPORTS" != 1 ]; then
    # 6982 is not a broken import — it is the card ANSWERING the probe. A card initialised with
    # --public-key-auth N --required-pub-keys R refuses key import until R public-key
    # authentications have happened, and those require registered keys that cannot be imported.
    # That is a closed loop, and it is the answer phase d was written to get.
    #
    # CONFIRMED BY A/B on this board 2026-08-06, same blob and same tooling, one flag apart:
    #   control (no PKA flags)                      -> UNWRAP KEY: "OK into keyId=1", exit 0
    #   --public-key-auth 3 --required-pub-keys 2   -> UNWRAP KEY: SW=6982, exit 1
    # Note it is 6982 (security condition not satisfied), NOT the 6400 of pico-keys-sdk#25 — this
    # is the card refusing correctly, not the unexplained failure in that report.
    if grep -qa '6982' <<< "$D_FAIL_OUT"; then
      rec d PASS "FINDING: a PKA-initialised card (required 2, authenticated 0) REFUSES key import — UNWRAP KEY returns SW=6982. Same-card custodian enrolment is therefore impossible by construction: the keys you would register cannot be imported first. A second SmartCard-HSM really is required, and the 2026-08-01 probe's inference was right even though its reasoning (missing certificates) was not"
    else
      rec d FAIL "same-card custodian imports failed for a reason OTHER than the PKA security condition: $(stage_reason "$D_FAIL_OUT")"
    fi
  elif [ "$D_EXPORT" != 1 ]; then
    rec d FAIL "HARDWARE FINDING: same-card keys-with-certs still cannot --export-for-pub-key-auth (exact error above) — a second SmartCard-HSM really is required"
  else
    D_REG=1
    for i in 1 2; do
      rout="$(sc-hsm-tool --reader "$READER" --public-key-auth 3 --required-pub-keys 2 \
          --register-public-key "$DW/cust$i.pub" 2>&1)"; rrc=$?
      if [ "$rrc" = 0 ]; then P "custodian $i REGISTERED on the same card that hosts the key"
      else F "custodian $i registration failed (rc=$rrc): $(printf '%s' "$rout" | tail -1)"; D_REG=0; fi
    done
    st="$(sc-hsm-tool --reader "$READER" --public-key-auth-status 2>&1)"
    printf '%s\n' "$st" | sed 's/^/  status: /'
    if [ "$D_REG" != 1 ]; then
      rec d FAIL "HARDWARE FINDING: export works same-card but --register-public-key refuses it (exact error above) — a second token is required after all"
    else
      # OPEN QUESTION (a): with custodians enrolled, does the PIN alone still use the card?
      head -c 32 /dev/urandom > "$DW/d.bin"
      if pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN_D" --sign \
           --mechanism ECDSA --label recovery-drill-throwaway \
           --input-file "$DW/d.bin" --output-file "$DW/s.bin" >/dev/null 2>&1; then
        rec d PASS "FINDING (a): PIN-only sign SUCCEEDED with 2 custodians enrolled — PKA does NOT replace the PIN at enrolment on the Pico"
      else
        rec d PASS "FINDING (a): PIN-only sign REFUSED with 2 custodians enrolled — PKA replaces the PIN on the Pico"
      fi
    fi
  fi
fi
printf '  \033[33mSKIPPED\033[0m power-cycle arms (does auth die on power-off, measured re-auth, RRC-vs-PKA)\n'
printf '          — they need a physical reseat; nothing here fakes them. See hsm-fleet-drill.sh --pka.\n'
shred -u "$DW"/* 2>/dev/null || rm -f "$DW"/*; rm -rf "$DW"

# =================================================================================================
hdr "PHASE e — recovery drill --auto (break-glass DKEK, SLIP-39, re-provision proof)"
printf '  FAILURE CONDITION: the drill exits non-zero, never enters the share-reconstruction\n'
printf '  prompt path, accepts a wrong share, or the re-provisioned address differs.\n'
eout="$RUN_DIR/phase-e-drill.log"
HSM_PKCS11_MODULE="$P11" "$HERE/hsm-recovery-drill.sh" --run --slot "$SLOTID" --reader "$READER" --auto 2>&1 | tee "$eout"
erc="${PIPESTATUS[0]}"
dline="$(grep -E '^  [0-9]+ passed, [0-9]+ failed, [0-9]+ unverified' "$eout" | tail -1 | sed 's/^  //')"
grep -q 'entered the share-reconstruction prompt path' "$eout" \
  && P "the corrected --pwd-shares-total 4 command really entered the share prompt path" \
  || F "the share prompt path was never entered — the 3B fix is not validated"
grep -q 'a wrong share is REFUSED' "$eout" \
  && P "wrong-share negative control held" || F "wrong-share negative control did not hold"
grep -q 'the SAME address came back' "$eout" \
  && P "re-provision-from-seed returned the same address" || F "re-provision proof missing/failed"
if [ "$erc" = 0 ]; then
  rec e PASS "recovery drill --auto green ($dline)"
else
  rec e FAIL "recovery drill --auto exited $erc ($dline)"
fi

fi # CAN_WRITE

# =================================================================================================
hdr "PHASE f — SUMMARY"
printf '\n  \033[1m%-8s %-9s %s\033[0m\n' "phase" "result" "evidence"
printf '  %-8s %-9s %s\n' "-----" "------" "--------"
while IFS='|' read -r ph res ev; do
  printf '  %-8s %-9s %s\n' "$ph" "$res" "$ev"
done < "$RESULTS"
printf '\n  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
printf '\n  \033[1mD1 IS STILL OPEN.\033[0m This is a Pico standing in for the Nitrokey HSM 2.\n'
printf '  Power-cycle arms and the two-token custodian flow still need a human / a second card.\n'
printf '  Transcript: %s\n' "$TRANSCRIPT"
rm -f "$RESULTS"
[ "$fail" -eq 0 ] || exit 1
