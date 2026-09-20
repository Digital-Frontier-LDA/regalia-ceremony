#!/usr/bin/env bash
# Regression test for the EF.C_DevAut self-provisioning deadlock.
#
# The bug: dev_name is parsed from EF.C_DevAut, but asn1_cvc_aut() refuses to build the EE
# certificate without dev_name — and EF.C_DevAut is only created inside that same INITIALIZE
# path. So once EF.C_DevAut is lost (flash erase / flash_nuke / corruption) the device could
# never be re-initialized, and OpenSC's PKCS#15 emulator then aborts on
# "Could not decode EF.C_DevAut", leaving PKCS#11 with CKR_USER_PIN_NOT_INITIALIZED.
#
# This test reproduces the exact condition (full chip erase) and asserts that first
# provisioning now completes and yields a device-unique PKCS#11 token serial.
#
# Requires: an OpenOCD server on :4444 with the target attached, and a built firmware ELF.
#
#   ./hsm-devaut-bootstrap-test.sh --elf /path/to/pico_hsm.elf
#
# MULTI-BOARD BENCH (2026-09-02): there are now two RP2350B boards and two probes attached, so
# nothing here may rely on "the card" or "the probe" being unambiguous.
#
#   --probe <serial>          bind OpenOCD to ONE debug probe (else it picks arbitrarily)
#   --expect-board <hex16>    OTP chip id this probe MUST be on; the erase is refused otherwise
#   --reader <n>              which PC/SC reader to drive (sc-hsm-tool defaults to 0)
#   --expect-serial <str>     assert the exact resulting token serial (else: device-unique form)
#   --protect-serial <str>    refuse to INITIALIZE a reader reporting this serial (default the
#                             provisioned staging card ESP2202E14A)
#
# The --expect-board check is the load-bearing one: it is read over SWD from the chip that is
# about to be erased, so it cannot be fooled by reader renumbering or USB ordering.
#
#   ./hsm-devaut-bootstrap-test.sh --elf fw.elf --probe E66548... --expect-board 8625B32841D722E2 \
#       --reader 1 --expect-serial ESP41D722E2
#
set -uo pipefail

ELF=""
SO_PIN="${HSM_SO_PIN:-3537363231383830}"
PIN="${HSM_PIN:-648219}"
OCD_PORT="${OCD_PORT:-4444}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
P11_MODULE="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"
PROBE="${PROBE:-}"
EXPECT_BOARD="${EXPECT_BOARD:-}"
READER="${READER:-0}"
EXPECT_SERIAL="${EXPECT_SERIAL:-}"
PROTECT_SERIAL="${PROTECT_SERIAL:-ESP2202E14A}"
OCD_PID=""

while [ $# -gt 0 ]; do
    case "$1" in
        --elf) ELF="$2"; shift 2 ;;
        --probe) PROBE="$2"; shift 2 ;;
        --expect-board) EXPECT_BOARD="$2"; shift 2 ;;
        --reader) READER="$2"; shift 2 ;;
        --expect-serial) EXPECT_SERIAL="$2"; shift 2 ;;
        --protect-serial) PROTECT_SERIAL="$2"; shift 2 ;;
        --port) OCD_PORT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[ -n "$ELF" ] || { echo "usage: $0 --elf <pico_hsm.elf> --probe S --expect-board ID [--reader N]" >&2; exit 2; }

# THE ERASE IS THE WHOLE TEST, SO IDENTITY IS NOT OPTIONAL. This runs a FULL CHIP ERASE. Without
# --probe, OpenOCD picks a probe arbitrarily among those attached; without --expect-board there is
# nothing to compare the die against, and the run erases whichever board that probe happens to be
# on. Both used to be optional, with the reader-side --protect-serial interlock as the only guard —
# but that guard reads a TOKEN SERIAL over PC/SC, and reader indices renumber independently of
# probe ordering, so it cannot say which die the erase will land on.
#
# This is not a hardship for a blank board: the OTP chip id is read over SWD from the die itself
# (0x40130000), which answers on a board carrying no firmware at all — the case the old opt-out
# existed for. `--expect-board` is available exactly when the erase is.
[ -n "$PROBE" ] || { echo "REFUSING: --probe is required. This test runs a full chip erase, and with several probes attached OpenOCD would pick one arbitrarily." >&2; exit 2; }
[ -n "$EXPECT_BOARD" ] || { echo "REFUSING: --expect-board is required. The OTP chip id read over SWD is the only identity that names the die about to be erased (reader indices and USB order do not)." >&2; exit 2; }
[ -f "$ELF" ] || { echo "FAIL: ELF not found: $ELF" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
run()  { perl -e 'alarm shift; exec @ARGV' "$@"; }

reader_indices(){ opensc-tool --list-readers 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1}'; }
# The serial line is TAB-indented ("\tSerial number  : ESP..."), so a '^Serial number' anchor
# matches nothing and every reader looks blank — which made resolve_reader hand back the
# PROTECTED card as a candidate on 2026-09-02. The INITIALIZE interlock caught it; this is the
# reason that second interlock exists.
reader_serial(){ run 25 pkcs15-tool -r "$1" --dump 2>/dev/null \
                   | awk -F': *' '/^[[:space:]]*Serial number/ && !seen {print $2; seen = 1}'; }

# READER=auto: locate the PROTECTED card positively, then target the other reader.
#
# The first version did the opposite — it treated any reader that did not answer as the protected
# serial as a candidate. MEASURED 2026-09-02, twice: while OpenOCD was still busy and the freshly
# flashed board had not re-enumerated, `pkcs15-tool` timed out against the provisioned card, the
# empty result compared unequal to the protected serial, and the resolver nominated the
# PROVISIONED CARD as the target for a wipe. The INITIALIZE interlock caught it both times.
#
# "I could not read it" is not "it is not the protected card". So: refuse unless the protected
# card is found at exactly one reader AND exactly one other reader exists.
resolve_reader(){
    local idx s others="" nprot=0 nother=0
    for idx in $(reader_indices); do
        s="$(reader_serial "$idx")"
        if [ "$s" = "$PROTECT_SERIAL" ]; then
            nprot=$((nprot+1))
            echo "  reader $idx: $s  <- protected, excluded" >&2
        else
            others="$idx"; nother=$((nother+1))
            echo "  reader $idx: ${s:-<no serial: blank or unreadable>}" >&2
        fi
    done
    if [ -z "$PROTECT_SERIAL" ]; then
        [ "$nother" -eq 1 ] || { echo "  need exactly 1 reader, got $nother" >&2; return 1; }
        echo "$others"; return 0
    fi
    [ "$nprot" -eq 1 ] || { echo "  protected card $PROTECT_SERIAL not positively located ($nprot matches) — refusing" >&2; return 1; }
    [ "$nother" -eq 1 ] || { echo "  expected exactly 1 other reader, got $nother — refusing" >&2; return 1; }
    echo "$others"
}

# Own our OpenOCD rather than assuming a shared one on :4444, and never `pkill -f openocd`:
# with two probes attached that would kill the other board's session too.
cleanup(){ [ -n "$OCD_PID" ] && kill "$OCD_PID" 2>/dev/null; return 0; }
trap cleanup EXIT INT TERM

# INTERLOCK, RUN FIRST AND WITHOUT THE TELNET SERVER. Read the OTP chip id off the die we are
# about to erase and require it to be the board we were told to touch. Reader indices renumber
# and USB ordering is not stable; the OTP id is the chip. 0x40130000 rows 0-1 hold the 64-bit
# id, low word first.
#
# One-shot `-c init -c mdw -c exit`, NOT telnet. Measured 2026-09-02: the telnet path raced its
# own server start and returned an empty response against a target that answered correctly a
# second later — which refused the correct board. It failed closed, but a check that says no to
# everything is not a check.
if [ -n "$EXPECT_BOARD" ]; then
    [ -n "$PROBE" ] || fail "--expect-board requires --probe (else OpenOCD picks a probe arbitrarily)"
    otp="$("$OCD_BIN" -f interface/cmsis-dap.cfg -c "adapter serial $PROBE" -c "adapter speed 5000" \
             -f target/rp2350.cfg -c "gdb port disabled" -c "tcl port disabled" \
             -c "telnet port disabled" -c "init" -c "mdw 0x40130000 2" -c "exit" 2>&1)"
    lo="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$otp" | awk '{print $2}')"
    hi="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$otp" | awk '{print $3}')"
    [ -n "$lo" ] && [ -n "$hi" ] || fail "could not read OTP chip id over SWD from probe $PROBE:
$otp"
    got="$(printf '%s%s' "$hi" "$lo" | tr 'a-f' 'A-F')"
    [ "$got" = "$(tr 'a-f' 'A-F' <<< "$EXPECT_BOARD")" ] \
        || fail "REFUSING TO ERASE: probe $PROBE is on board $got, expected $EXPECT_BOARD"
    pass "probe confirmed on board $got — safe to erase"
    # THE ROLE REGISTRY GATE. The OTP check above proves WHICH board the probe reaches; this
    # proves that board is registered scratch before the full-chip erase below runs. The board is
    # reverse-mapped through HSM_BOARD_MAP to its token serial, so the same committed registry
    # (tools/hsm-staging-registry.json) that gates every --initialize gates the erase path too. It
    # runs only when the reverse map knows this board; the OTP check above is the unconditional one.
    _da_rr="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hsm-reader-select.sh"
    # shellcheck source=/dev/null
    [ -f "$_da_rr" ] && . "$_da_rr"
    if command -v hsm_assert_staging_board >/dev/null 2>&1; then
        hsm_assert_staging_board "$EXPECT_BOARD" || exit 2
    fi
fi

if [ -n "$PROBE" ]; then
    OCD_LOG="${OCD_LOG:-/tmp/openocd-$PROBE.log}"
    "$OCD_BIN" -f interface/cmsis-dap.cfg -c "adapter serial $PROBE" -c "adapter speed 5000" \
        -f target/rp2350.cfg -c "telnet port $OCD_PORT" -c "gdb port disabled" \
        -c "tcl port disabled" > "$OCD_LOG" 2>&1 &
    OCD_PID=$!
    for _ in $(seq 1 20); do sleep 1; nc -z localhost "$OCD_PORT" 2>/dev/null && break; done
    nc -z localhost "$OCD_PORT" 2>/dev/null || fail "OpenOCD did not come up on :$OCD_PORT for probe $PROBE"
    pass "OpenOCD bound to probe $PROBE on :$OCD_PORT"
fi

ocd_out(){ printf '%s\nexit\n' "$1" | run 40 nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000'; }

# Recovery rung for the target board, pinned to OUR probe.
#
# MEASURED 2026-09-02: a freshly flashed board came up enumerated on USB as 2e8a:10fd but with no
# PC/SC reader at all, and stayed that way through `halt; reset run`. Direct POWMAN register writes
# were refused ("Failed to write memory") while reads succeeded. The rescue DP cleared it first try.
# So the escalation here is rescue-first, not warm-reset-first: on a board that has just been
# erased and reflashed, the cheap rung has not once been the one that worked.
recover_target(){
    [ -n "$PROBE" ] || return 1
    local one=("$OCD_BIN" -f interface/cmsis-dap.cfg -c "adapter serial $PROBE"
               -c "adapter speed 5000" -f target/rp2350.cfg -c "gdb port disabled"
               -c "tcl port disabled" -c "telnet port disabled" -c "init")
    echo "  recover: rescue DP on probe $PROBE"
    "${one[@]}" -c "poll off" -c "${OCD_CHIPNAME:-rp2350}.dap apreg ${RP_AP:-0x80000} 0 0x80000000" \
                -c "${OCD_CHIPNAME:-rp2350}.dap apreg ${RP_AP:-0x80000} 0 0" -c "exit" >/dev/null 2>&1
    echo "  recover: reset run"
    "${one[@]}" -c "reset run" -c "exit" >/dev/null 2>&1
    sleep 8
}
echo "=== 1. full chip erase (flash_nuke equivalent) — destroys EF.C_DevAut ==="
(echo "reset halt"; sleep 2; echo "flash erase_sector 0 0 last"; sleep 75; echo "exit") \
    | nc localhost "$OCD_PORT" >/dev/null 2>&1

echo "=== 2. flash firmware ==="
# OpenOCD prints "** Verified OK **" to its own log; the telnet stream is not a
# reliable place to look for it, so check both.
OCD_LOG="${OCD_LOG:-/tmp/openocd.log}"
flash_out="$( (echo "program $ELF verify"; sleep 50; echo "reset run"; sleep 5; echo "exit") \
    | nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000' )"
if ! grep -qi "Verified OK" <<< "$flash_out"; then
    # Capture, then match: `tail | grep -q` under pipefail can report 141 instead of the match.
    _ocdtail="$([ -f "$OCD_LOG" ] && tail -40 "$OCD_LOG" 2>/dev/null || true)"
    if ! grep -qi "Verified OK" <<< "$_ocdtail"; then
        fail "firmware did not verify (checked telnet output and $OCD_LOG)"
    fi
fi
pass "firmware flashed and verified"

# LET GO OF THE SWD BUS BEFORE ASKING THE CARD ANYTHING.
#
# The server was held open for the whole run. OpenOCD polls the target continuously, and an
# attached OpenOCD is enough on its own to stop a healthy Pico HSM answering — measured
# 2026-09-02 on the provisioned card, where a read-only `init; mdw` session left it enumerated
# but mute until `halt; reset run`.
#
# Here it showed up as the freshly flashed board repeatedly leaving the bus (9 "external reset
# detected" in one run), which renumbered the PC/SC readers BETWEEN resolving the target and
# using it: the resolver correctly picked board #2 at reader 0, board #2 then dropped, the
# provisioned card became reader 0, and the INITIALIZE interlock refused. Three runs died that
# way, each one a correct refusal of a genuinely wrong target.
#
# Everything from here is host-side, so the probe is not needed until recovery.
if [ -n "$OCD_PID" ]; then
    kill "$OCD_PID" 2>/dev/null
    wait "$OCD_PID" 2>/dev/null
    OCD_PID=""
    sleep 3
    pass "released the SWD bus — the card runs undisturbed from here"
fi

# Wait for USB re-enumeration before issuing INITIALIZE; a fixed delay races it.
#
# CAPTURE, THEN MATCH. `run 25 sc-hsm-tool | grep -q` under `pipefail` is the inverted predicate
# measured on 2026-08-08: grep -q quits on the match, sc-hsm-tool takes SIGPIPE and exits 141, and
# pipefail reports 141 — so the test reads FALSE exactly when the card answered. Verified 5/5 with
# pipefail and 5/5 the other way without it. Here it would have burned the full 120 s wait and then
# failed with "card never enumerated" against a card that had enumerated on the first try.
if [ "$READER" = "auto" ]; then
    # Wait for a reader that is not the protected card to appear, then pin to it.
    echo "resolving target reader (protected: $PROTECT_SERIAL)"
    R=""
    for attempt in 1 2 3; do
        for _ in $(seq 1 16); do
            sleep 5
            R="$(resolve_reader 2>/dev/null)" && [ -n "$R" ] && break
        done
        [ -n "$R" ] && break
        echo "target reader did not appear (attempt $attempt) — escalating to the recovery ladder"
        recover_target || break
    done
    [ -n "$R" ] || { resolve_reader >/dev/null; fail "no non-protected reader appeared after flashing, even after recovery"; }
    READER="$R"
    pass "target reader resolved to $READER (protected card left alone)"
fi

card_says_version(){
    local out
    out="$(run 25 sc-hsm-tool -r "$READER" 2>&1)"
    grep -q "Version" <<< "$out"
}
for _ in $(seq 1 24); do
    sleep 5
    card_says_version && break
done
card_says_version || fail "card never enumerated after flashing"
pass "card enumerated before INITIALIZE"

echo "=== 3. first INITIALIZE on a device with no EF.C_DevAut ==="
# Second interlock, at the PC/SC layer: never INITIALIZE a reader that is answering as the
# protected card. Cheap, and it is the step that would destroy it.
if [ -n "$PROTECT_SERIAL" ]; then
    tgt="$(run 40 pkcs11-tool --module "$P11_MODULE" --slot-index "$READER" --list-token-slots 2>&1)"
    if grep -qE "serial num[[:space:]]*:[[:space:]]*${PROTECT_SERIAL}\b" <<< "$tgt"; then
        fail "REFUSING TO INITIALIZE: reader $READER is the protected card $PROTECT_SERIAL"
    fi
    pass "reader $READER is not the protected card $PROTECT_SERIAL"
fi
run 200 sc-hsm-tool -r "$READER" --initialize --so-pin "$SO_PIN" --pin "$PIN" \
    --dkek-shares 1 --label devauttest </dev/null 2>&1 | tail -2

# The firmware schedules a reset after INITIALIZE, so the device re-enumerates.
# Poll rather than guessing a fixed delay.
state=""
for _ in $(seq 1 20); do
    sleep 5
    state="$(run 40 sc-hsm-tool -r "$READER" 2>&1)"
    grep -q "Version" <<< "$state" && break
done
grep -q "Version" <<< "$state" || fail "card does not answer after INITIALIZE (waited 100s)"
pass "card alive after INITIALIZE"

echo "=== 4. PKCS#15 emulator must initialise (this is what EF.C_DevAut gates) ==="
slots="$(run 60 pkcs11-tool --module "$P11_MODULE" --slot-index "$READER" --list-token-slots 2>&1)"
grep -qi "token" <<< "$(echo "$slots")" \
    || fail "no PKCS#11 token — EF.C_DevAut still missing or undecodable:
$slots"
pass "PKCS#11 token present (EF.C_DevAut decodable)"

echo "=== 5. token serial must be device-unique, not the shared constant ==="
serial="$(echo "$slots" | grep -oE 'serial num[[:space:]]*:[[:space:]]*[A-Za-z0-9]+' \
          | head -1 | sed -E 's/.*:[[:space:]]*//')"
[ -n "$serial" ] || serial="$(run 40 pkcs15-tool -r "$READER" --dump 2>&1 \
          | grep -iE '^[[:space:]]*Serial number' | head -1 | sed -E 's/.*:[[:space:]]*//')"
echo "observed token serial: '${serial}'"

[ -n "$serial" ] || fail "could not read a token serial number"

if [ -n "$EXPECT_SERIAL" ]; then
    # Prediction stated before the flash. Used for BOTH arms of the A/B: the stock-firmware arm
    # predicts the shared constant, the patched arm predicts this board's own id.
    [ "$serial" = "$EXPECT_SERIAL" ] \
        || fail "serial '$serial' != predicted '$EXPECT_SERIAL'"
    pass "serial '$serial' matches the prediction made before flashing"
else
    [ "$serial" != "ESPICOHSMTR" ] \
        || fail "serial is the shared constant ESPICOHSMTR — every device would collide"
    grep -qE '^ESP[0-9A-F]{8}$' <<< "$(echo "$serial")" \
        || fail "serial '$serial' does not match the expected device-unique form ESP<8 upper-hex>"
    pass "serial '$serial' is device-unique and correctly formed"
fi

echo
echo "ALL CHECKS PASSED — self-provisioning works on a device with no EF.C_DevAut."
