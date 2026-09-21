#!/usr/bin/env bash
# hsm-staging-restore.sh — put the staging card back into the posture the battery expects.
#
#   tools/hsm-staging-restore.sh
#
# The destructive suites and any hand-run experiment leave the card in whatever state they ended
# in: RRC re-enabled by a plain --initialize, a different user PIN, a key at a different id, or no
# key at all. hsm-staging-ci.sh's gate then fails on hw_rrc / hw_sign — correctly, because the card
# genuinely is not in the documented posture, but the failure looks like a device problem and is
# not one. This restores the posture in one command so a gate failure means what it says.
#
# What "the posture" is:
#   * D3: RRC OFF (no "User PIN reset with SO-PIN enabled" tell) via hsm-init-hardened.js
#   * the staging user PIN, with the documented retry count
#   * the staging DKEK domain
#   * the deterministic BIP39-vector key hsm-auto-import.sh installs, at the first free key id
#     (1 on a freshly initialised card) and labelled akash-funding
#   * $STAGING/expected-pub.der pinned to THAT key (delegated to hsm-staging-pin.sh)
#
# NEVER POINT THIS AT A CEREMONY CARD. It wipes the device and installs a key derived from a
# PUBLISHED test vector — worthless by construction, and that is the point.
set -u

# DEFINED FIRST, BEFORE ANY CALL SITE. These sat below the card-resolution block that now calls
# die(): bash resolves a function at CALL time, so `die "..."` above its definition prints
# "die: command not found" and CONTINUES — the guard exits 0 and the script runs on with the
# unresolved reader, which is the precise failure the guard was added to prevent. Verified by
# running a die-before-definition snippet: it reached the next line and exited 0.
say(){ printf '  %s\n' "$*"; }
die(){ printf '  \033[31m%s\033[0m\n' "$*" >&2; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
. "$REPO/tools/hsm-ceremony-scripts.sh"
SCRIPTS="$HSM_CEREMONY_SCRIPTS"

# PRIVATE LOG FILES, NOT FIXED /tmp PATHS. The init log is the ONLY place the hardened init's
# "REFUSING" reaches this script — the exit status is meaningless here because the Pico drops off
# the bus mid-command. With a fixed path and no `set -e`, another local user can pre-create
# /tmp/hsm-restore-init.log as a symlink: to an unwritable target, and the redirect fails silently
# leaving yesterday's contents; or to /dev/null, and the refusal is discarded. Either way the
# `grep REFUSING` finds nothing, the script reports the card is back, and step 2 spends the SO-PIN
# on a card the init refused to touch. mktemp in a 0700 directory removes the pre-creation window.
_SR_LOGDIR="$(mktemp -d "${TMPDIR:-/tmp}/hsm-restore.XXXXXXXX")" || exit 1
chmod 700 "$_SR_LOGDIR"
INIT_LOG="$_SR_LOGDIR/init.log"
IMPORT_LOG_FILE="$_SR_LOGDIR/import.log"
. "$REPO/tools/hsm-bench-lock.sh"
hsm_bench_lock_acquire wait || exit $?
STAGING="${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}"
SCSH="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}"
P11="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"
SO_PIN="${HSM_SO_PIN:-3537363231383830}"
PIN="${HSM_USER_PIN:-648219}"
RETRIES="${HSM_PIN_RETRIES:-3}"
SLOT="${HSM_SLOT:-0}"
# Two cards can be attached; bare sc-hsm-tool/pkcs11-tool mean "reader 0" / "first slot listed",
# neither of which is a stable identity. This script RE-PROVISIONS what it talks to, so take the
# handles the parent resolved (HSM_PCSC_INDEX / HSM_SLOT_ID) when they are present.
READER="${HSM_PCSC_INDEX:-$SLOT}"
SLOTID="${HSM_SLOT_ID:-$SLOT}"
# INHERIT THE PARENT'S PINNED CARD. hsm-staging-ci.sh resolves the staging card, exports
# HSM_TARGET_SERIAL alongside HSM_PCSC_INDEX, and then runs this script as posture_restore. Reading
# only HSM_RESTORE_SERIAL meant this script compared the reader the parent handed it against its OWN
# hardcoded default, so a battery pinned to any other card got
# "REFUSING: reader 0 holds ESP41D722E2, not ESP2202E14A" — measured 2026-09-11, the one failure in
# an otherwise green destructive nightly, which then left the card outside posture precisely because
# the step that exists to restore it refused. Precedence: an explicit override, then the identity the
# parent already proved.
#
# THERE IS NO DEFAULT CARD. There used to be one -- ESP2202E14A, the historical single-card bench --
# and on 2026-09-14 it aimed this script's INITIALIZE DEVICE at the wrong card: a repro loop's
# exit-path restore ran with no serial in scope while ESP2202E14A held the secp256k1 key #435's
# physical Cosmos qualification ran on. Nothing was wiped only because that card happened to hold the
# prefix reader name, which the addressability guard below refuses. A bench arrangement is not a
# safety property. The battery exports HSM_TARGET_SERIAL before calling this, so it is unaffected;
# every other caller must now say which card it means.
RESTORE_SERIAL="${HSM_RESTORE_SERIAL:-${HSM_TARGET_SERIAL:-}}"
[ -n "$RESTORE_SERIAL" ] || die "REFUSING: no card named. This script re-initialises the card it targets, so it has no default. Set HSM_RESTORE_SERIAL (or HSM_TARGET_SERIAL) to the token serial of the staging card to restore."
# scsh takes a reader NAME and matches by prefix; this script runs INITIALIZE DEVICE, so an
# unnamed target is a wipe aimed by enumeration order. HSM_EXPECT_SERIAL makes the JS refuse
# outright if it lands on the wrong device.
_sr_rs="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/hsm-reader-select.sh"
# shellcheck source=/dev/null
[ -f "$_sr_rs" ] && . "$_sr_rs"

# THE ROLE REGISTRY GATE, BEFORE ANY CARD I/O. This script runs INITIALIZE DEVICE — a wipe — on
# $RESTORE_SERIAL, and the hardened init's own HSM_EXPECT_SERIAL guard proves only that the card
# is the one this script AIMED at, not that aiming there was permissible. The committed registry
# (tools/hsm-staging-registry.json) is that permission, default-deny: unlisted, prod, or an unreadable
# registry all refuse here, before a single APDU is spent.
# hsm_assert_staging_card, not hsm_assert_staging: the role gate says a card with this SERIAL may
# be wiped, and a serial is self-reported. For a registered Nitrokey the card must also match the
# C.DevAut digest the registry pins, which covers the device public key (regalia#481). A Pico entry
# has no pin and passes straight through — its identity is proven over SWD instead.
if command -v hsm_assert_staging_card >/dev/null 2>&1; then
    hsm_assert_staging_card "$RESTORE_SERIAL" || exit 1
elif command -v hsm_assert_staging >/dev/null 2>&1; then
    # A serial-only check would accept a substituted card reporting a registered serial, so the
    # older resolver is a refusal rather than a weaker gate.
    echo "REFUSING: hsm_assert_staging_card is unavailable — this resolver cannot check the card" >&2
    echo "  against the certificate the registry pins. Update tools/hsm-reader-select.sh." >&2
    exit 1
else
    die "the role registry gate is unavailable (tools/hsm-reader-select.sh did not source) — a wipe script does not run without it"
fi

# RESOLVE BY SERIAL, NEVER BY ENUMERATION ORDER. $SLOT defaults to 0, so run standalone this script
# used to aim every step — including the SO-PIN-bearing DKEK import below — at PC/SC reader 0,
# "whichever board enumerated first". MEASURED 2026-09-11: reader 0 was ESP41D722E2, the card this
# script is NOT pinned to, which was sitting one failed login from lockout. hsm_reader_for resolves
# by token serial and refuses when the answer is ambiguous; that is the whole reason it exists, and
# this script sourced it without ever calling it.
if [ -z "${HSM_PCSC_INDEX:-}" ] && command -v hsm_reader_for >/dev/null 2>&1; then
    _sr_r="$(hsm_reader_for "$RESTORE_SERIAL" 2>/dev/null)" || _sr_r=""
    [ -n "$_sr_r" ] || die "cannot resolve $RESTORE_SERIAL to a PC/SC reader, and defaulting to reader $SLOT is how a re-provisioning lands on the wrong card. Attach it, or pass HSM_PCSC_INDEX explicitly."
    READER="$_sr_r"
fi
if [ -z "${HSM_SLOT_ID:-}" ] && command -v hsm_slot_id_for >/dev/null 2>&1; then
    _sr_s="$(hsm_slot_id_for "$RESTORE_SERIAL" 2>/dev/null)" || _sr_s=""
    [ -n "$_sr_s" ] && SLOTID="$_sr_s"
fi
_sr_name=""
command -v hsm_reader_name >/dev/null 2>&1 && _sr_name="$(hsm_reader_name "$READER")"

CEREMONY_VENV="${CEREMONY_VENV:-$HOME/.local/share/akash-hsm-venv}"
[ -x "$CEREMONY_VENV/bin/python3" ] && PATH="$CEREMONY_VENV/bin:$PATH"

# Wait on sc-hsm-tool, NOT pkcs11-tool. pkcs11-tool hangs holding the reader when the card is
# wedged, and `perl -e alarm` does not reliably kill it — it wedges pcscd and needs a kill -9.
# With no bound on the call, the until-loop below never advances and the whole script hangs:
# MEASURED 2026-08-07, this function sat for 86 minutes on one hung pkcs11-tool after the hardened
# init failed with SCARD_E_NOT_TRANSACTED. sc-hsm-tool bounds cleanly under the same alarm, and
# "answers with a Version line" is what "the card is back" actually means.
wait_card(){
    local t=0
    until perl -e 'alarm 20; exec @ARGV' -- sc-hsm-tool -r "$READER" 2>&1 | grep -qi '^Version'; do
        t=$((t+1)); [ "$t" -gt 40 ] && return 1; sleep 3
    done
    sleep 2; say "card is back"
}

# PROVE WHICH CARD THIS IS BEFORE WRITING TO IT. Only the scsh step (hsm-init-hardened.js) carried
# an identity guard; the sc-hsm-tool and pkcs11-tool steps below carried none, so a mis-resolved
# reader spent an SO-PIN and a user PIN on an unproven device. MEASURED 2026-09-11: step 2 aimed
# --import-dkek-share --so-pin at ESP41D722E2. Fails CLOSED — an unreadable reader is not a safe
# reader, because "" compared unequal to the expected serial is exactly how the first resolver
# nominated the wrong card for a wipe.
if command -v hsm_serial_at_reader >/dev/null 2>&1; then
    _sr_at="$(hsm_serial_at_reader "$READER" 2>/dev/null)" || _sr_at=""
    [ -n "$_sr_at" ] || die "reader $READER did not answer with a serial — cannot prove it is $RESTORE_SERIAL, and this script wipes what it talks to"
    [ "$_sr_at" = "$RESTORE_SERIAL" ] || die "REFUSING: reader $READER holds $_sr_at, not $RESTORE_SERIAL. This script runs INITIALIZE DEVICE and would erase that card."
    say "target: $RESTORE_SERIAL at PC/SC reader $READER, PKCS#11 slot id $SLOTID"
fi

[ -s "$STAGING/dkek.pbe" ] || die "no staging DKEK share at $STAGING/dkek.pbe"
[ -s "$STAGING/dkek.pw" ]  || die "no staging DKEK password at $STAGING/dkek.pw"

say "1. hardened init — RRC OFF, staging PIN, $RETRIES retries"
# SCSH CANNOT ADDRESS EVERY READER. It matches reader names by PREFIX and takes the first hit, so a
# reader whose full name is a strict prefix of another attached reader's name is unreachable:
# asking for it returns the OTHER card. MEASURED 2026-09-03 and again 2026-09-11 — reader 1
# ("...Pico Key CCID Interface", ESP2202E14A) is unaddressable while reader 0
# ("...Pico Key CCID Interface 01") is attached. Passing HSM_READER does not fix it; the name IS
# the ambiguity. Isolating by holding the other board in reset does not fix it either: a held
# RP2350 stays ENUMERATED, so PC/SC still lists two readers (hsm-fleet-drill.sh records the same
# measurement). This is a bench-topology limit, so refuse here and say so, rather than running a
# wipe and leaving the JS guard's "WRONG CARD" refusal to be read as a defect in the guard.
# THE APDU PATH FIRST, JAVA ONLY IF IT IS ABSENT (regalia#486, decided 2026-09-21).
# hsm-init-hardened.sh builds the same INITIALIZE DEVICE with opensc-explorer — options 0x0000, the
# PINs on stdin rather than in argv, the label written in the init's own session. It needs no JVM,
# so it also works on a rack or a vault VM where installing one is not on the table. Verified on
# DENK0404144 (fw 4.1, 2026-09-21): options readback shows RRC off, C_InitPIN with the SO-PIN is
# REFUSED, the original user PIN still opens the card, and the token label is what was asked for.
# The scsh script stays as the fallback and is byte-compatible; the reader-name interlock below is
# only needed by that path, since scsh matches reader names by PREFIX.
INIT_SH="${HSM_INIT_HARDENED_SH:-$SCRIPTS/hsm-init-hardened.sh}"
if [ -r "$INIT_SH" ]; then
    HSM_SO_PIN="$SO_PIN" HSM_USER_PIN="$PIN" \
      perl -e 'alarm 300; exec @ARGV' -- bash "$INIT_SH" --reader "$READER" \
        --expect-serial "$RESTORE_SERIAL" --rrc off --retries "$RETRIES" --label staging \
        > "$INIT_LOG" 2>&1
else
    if command -v hsm_require_scsh_addressable >/dev/null 2>&1; then
        hsm_require_scsh_addressable "$READER" "$RESTORE_SERIAL" || exit 1
    fi
    ( cd "$SCSH" && HSM_SO_PIN="$SO_PIN" HSM_USER_PIN="$PIN" HSM_PIN_RETRIES="$RETRIES" \
        HSM_READER="$_sr_name" HSM_EXPECT_SERIAL="$RESTORE_SERIAL" \
          HSM_RRC_MODE=off HSM_LABEL=staging ./scriptrunner "$SCRIPTS/hsm-init-hardened.js" \
    ) > "$INIT_LOG" 2>&1
fi
# The init's exit status means nothing for a run that REACHED the card — the Pico drops off the USB
# bus mid-command. But it means nothing for a REFUSAL either, and a refusal never touches the card:
# MEASURED 2026-09-11, the JS guard refused with "WRONG CARD", this script printed "card is back"
# because the card was trivially alive, and step 2 then spent an SO-PIN on it. Read the log for the
# refusal the exit status throws away.
if grep -qi 'REFUSING' "$INIT_LOG" 2>/dev/null; then
    die "the hardened init REFUSED and no key material was touched: $(grep -io 'REFUSING[^"]*' "$INIT_LOG" | head -1 | cut -c1-240)"
fi
wait_card || die "card never came back after the hardened init (see $INIT_LOG)"
# VERIFY THE POSTURE, DO NOT ASSERT IT. wait_card proves the card ANSWERS, which is liveness, not
# posture — step 1 printed "RRC OFF ... card is back" while RRC remained ENABLED on both cards
# (MEASURED 2026-09-11). D3 requires the "User PIN reset with SO-PIN enabled" tell to be absent, so
# read it back. Fails CLOSED: an unanswered probe cannot clear the check, otherwise a sc-hsm-tool
# that times out silently certifies the posture it failed to read.
_sr_post="$(perl -e 'alarm 25; exec @ARGV' -- sc-hsm-tool -r "$READER" 2>&1)"
if ! printf '%s\n' "$_sr_post" | grep -qi '^Version'; then
    die "cannot verify the posture — sc-hsm-tool did not answer on reader $READER after the init"
fi
if printf '%s\n' "$_sr_post" | grep -qi 'reset with SO-PIN'; then
    die "the hardened init reported no failure, but RRC is still ENABLED on $RESTORE_SERIAL (the 'User PIN reset with SO-PIN enabled' tell is present). D3 requires it OFF. See $INIT_LOG."
fi
say "RRC verified OFF on $RESTORE_SERIAL"

say "2. import the staging DKEK share"
DKEK_PW="$(cat "$STAGING/dkek.pw")" perl -e 'alarm 120; exec @ARGV' -- \
    sc-hsm-tool -r "$READER" --import-dkek-share "$STAGING/dkek.pbe" --password env:DKEK_PW \
    --so-pin "$SO_PIN" < /dev/null >/dev/null 2>&1 \
  && say "DKEK imported" || die "DKEK import failed"

say "3. install the seed key (hsm-auto-import.sh)"
# Hand the child the card we resolved. Without HSM_PCSC_INDEX it defaults to PC/SC reader 0,
# which with two boards attached is whichever enumerated first — measured 2026-09-03, that was
# the OTHER card, and the import died with "no ATR — no card in the reader" against a reader
# whose card was deliberately held in reset.
HSM_PCSC_INDEX="$READER" HSM_SLOT_ID="$SLOTID" \
HSM_AUTO_DIR="$STAGING/auto-import" SCSH_HOME="$SCSH" HSM_USER_PIN="$PIN" \
HSM_DKEK_SHARE_IN="$STAGING/dkek.pbe" HSM_DKEK_PW_IN="$STAGING/dkek.pw" \
    perl -e 'alarm 300; exec @ARGV' -- "$SCRIPTS/hsm-auto-import.sh" --run \
    > "$IMPORT_LOG_FILE" 2>&1 \
  && say "seed key imported" || die "auto-import failed (see $IMPORT_LOG_FILE)"

say "4. re-pin expected-pub.der to the key provisioning actually installs"
"$REPO/tools/hsm-staging-pin.sh" --write >/dev/null 2>&1 || true
"$REPO/tools/hsm-staging-pin.sh" | sed 's/^/  /' | tail -2

say "5. verify the posture"
sc-hsm-tool -r "$READER" 2>&1 | grep -iE 'version|reset with SO-PIN|tries left|DKEK shares' | sed 's/^/    /'
# SIGN WITH THE KEY THAT WAS JUST INSTALLED, NOT WITH A REMEMBERED ID.
#
# This signed `--id 31`, and hsm-auto-import.js installs at `determineFreeKeyId()` — which is 1 on
# a card the step above has just wiped. So this check could not pass on a freshly restored card: it
# reported "the card does not sign/verify against the pin — posture NOT restored" after a restore
# that had worked, on a Nitrokey HSM 2 (DENK0404144) 2026-09-21. 31 was a bench artefact from a
# card whose low ids were already taken; the header of this file repeated it as if it were the
# contract. The id is read back from the card by the LABEL the import writes.
W=$(mktemp -d); head -c 32 /dev/urandom > "$W/d"
KEY_LABEL="${HSM_RESTORE_KEY_LABEL:-akash-funding}"
KEY_ID="$(perl -e 'alarm 45; exec @ARGV' -- pkcs11-tool --module "$P11" --slot "$SLOTID" \
            --login --pin "$PIN" --list-objects --type privkey 2>/dev/null \
          | awk -v want="$KEY_LABEL" '/^ *label:/{l=$2} /^ *ID:/{if (l==want) {print $2; exit}}')"
if [ -z "$KEY_ID" ]; then
    rm -rf "$W"
    die "no private key labelled '$KEY_LABEL' on $RESTORE_SERIAL after the import — there is nothing to verify"
fi
say "    key '$KEY_LABEL' is at id $KEY_ID"
if perl -e 'alarm 45; exec @ARGV' -- pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$PIN" --sign \
     --mechanism ECDSA --id "$KEY_ID" --input-file "$W/d" --output-file "$W/s" >/dev/null 2>&1 \
   && python3 "$SCRIPTS/verify-hsm-control.py" --der "$STAGING/expected-pub.der" \
        --digest "$W/d" --sig "$W/s" >/dev/null 2>&1; then
    say "OK: signs with the staging PIN and verifies against the pin"
    rm -rf "$W"
else
    rm -rf "$W"; die "the card does not sign/verify against the pin — posture NOT restored"
fi
