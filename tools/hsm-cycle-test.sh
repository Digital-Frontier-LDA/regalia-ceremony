#!/usr/bin/env bash
# hsm-cycle-test.sh — measure how reliably a Pico HSM survives re-provisioning.
#
#   ./hsm-cycle-test.sh --cycles 10
#   ./hsm-cycle-test.sh --cycles 5 --uart /dev/tty.usbserial-0001    # capture firmware logs
#   ./hsm-cycle-test.sh --cycles 3 --full                            # whole chain, not just reset
#   ./hsm-cycle-test.sh --cycle-port 2                               # acceptance test for the
#                                                                    # power-switchable hub
#
# UNATTENDED HANG RECOVERY. Set HSM_UHUBCTL_LOC (hub location from `uhubctl`, e.g. "1-1") and
# HSM_UHUBCTL_PORT (the Pico's port number) and a hung device gets its port power-cycled
# instead of needing a physical replug. Tested with a Plugable USBC-HUB7BC — note its
# rightmost port does NOT switch, use any other.
#
# WHY THIS EXISTS. `sc-hsm-tool -r "$READER" --initialize` re-personalises the device, and the firmware resets
# itself afterwards so the card can rebuild state (without that reset the card never comes back
# and only a PHYSICAL REPLUG recovers it). That reset was measured at 7/7 on a warm device and
# 1/1 HUNG on the first initialize after a firmware flash — a real difference on a tiny sample.
# Settling that needs repetition with consistent instrumentation, which is what this is.
#
# INSTRUMENTATION NOTES, all learned by getting them wrong first:
#   - Presence is read from the USB layer, NOT from `opensc-tool --list-readers`. That call costs
#     ~1s, and the reset completes in ~1-3s, so polling with it MISSES the gap and reports a
#     successful reset as "never rebooted".
#   - A reboot is detected by the device IDENTITY CHANGING, not by observing an absence. Racing a
#     ~1s absence window produces false negatives; a new identity is durable evidence.
#   - Exit codes are read directly, never through a pipe. `cmd | tail` yields tail's status, which
#     silently turns a failure into a pass.
set -u

CYCLES=5
UART=""
FULL=0
UHUBCTL_LOC="${HSM_UHUBCTL_LOC:-}"
UHUBCTL_PORT="${HSM_UHUBCTL_PORT:-}"
SO_PIN="${HSM_SO_PIN:-3537363231383830}"
USER_PIN="${HSM_USER_PIN:-648219}"
STAGING="${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}"
VIDPID="2e8a:10fd"
# Resolved RELATIVE TO THIS REPO — see the same note in hsm-scenarios.sh.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The defaults named ceremony/qubes/scripts/, the retired monorepo layout, so every --full chain
# here would have failed on a missing script. Resolved through the shared helper instead.
# shellcheck source=/dev/null
. "$REPO/tools/hsm-ceremony-scripts.sh"
AUTO_IMPORT="${HSM_AUTO_IMPORT:-$(hsm_ceremony_script hsm-auto-import.sh)}"
VERIFY="${HSM_VERIFY:-$(hsm_ceremony_script verify-hsm-control.py)}"
. "$REPO/tools/hsm-bench-lock.sh"
hsm_bench_lock_acquire wait || exit $?

# TARGET SELECTION — this suite WIPES AND RE-PERSONALISES the card it talks to, and it had no way
# to say which card that is. With two Pico HSMs attached (from 2026-09-02) bare `sc-hsm-tool`
# means "PC/SC reader 0", which is whichever board enumerated first and was measured to flip after
# a firmware reset. Set HSM_TARGET_SERIAL to pin the run to one card by token serial.
HSM_TARGET_SERIAL="${HSM_TARGET_SERIAL:-}"
READER="${HSM_PCSC_INDEX:-0}"
SLOTIX="${HSM_SLOT_INDEX:-0}"
SLOTID="${HSM_SLOT_ID:-0}"
# ARGUMENTS FIRST, BEFORE ANY CARD IS RESOLVED. --cycle-port is a HUB acceptance test: it asks
# whether the hub really switches power on a port, touches no card and wipes nothing. Parsed after
# the targeting block, it could never run on the bench where it is needed — a wedged card makes
# hsm_serial_at_reader fail and the registry gate exits first, so the one test that would tell you
# whether you can power-cycle your way out was unreachable exactly when the card was stuck.
while [ $# -gt 0 ]; do
    case "$1" in
        --cycles) CYCLES="$2"; shift 2;;
        --uart)   UART="$2"; shift 2;;
        --full)   FULL=1; shift;;
        --cycle-port) CYCLE_PORT_TEST="$2"; shift 2;;
        -h|--help) sed -n '2,30p' "$0"; exit 0;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

# Sourced UNCONDITIONALLY (see the same note in hsm-scenarios.sh): the resolver defines functions
# and runs nothing, and both the multi-reader refusal and the role gate below need it.
# shellcheck source=/dev/null
[ -f "$REPO/tools/hsm-reader-select.sh" ] && . "$REPO/tools/hsm-reader-select.sh"

# The hub test resolves no card, so neither the targeting nor the role gate applies to it: they
# exist to name the card this suite WIPES, and this branch wipes nothing.
if [ -z "${CYCLE_PORT_TEST:-}" ]; then
    # THE UNTARGETED FALLBACK IS ONLY SAFE WITH ONE CARD ON THE BUS (same reasoning and same measured
    # flip as hsm-scenarios.sh): reader 0 is whichever board enumerated first, and this suite WIPES
    # what it talks to. Refuse when a second card makes the default ambiguous.
    if [ -z "$HSM_TARGET_SERIAL" ] && [ -z "${HSM_PCSC_INDEX:-}" ] \
       && command -v hsm_reader_indices >/dev/null 2>&1; then
        _ct_n="$(hsm_reader_indices 2>/dev/null | grep -c .)"
        if [ "${_ct_n:-0}" -gt 1 ]; then
            echo "FATAL: $_ct_n PC/SC readers are present and no card was named, but this suite re-provisions (WIPES) its target. Set HSM_TARGET_SERIAL to the card to wipe (or HSM_PCSC_INDEX if you have already resolved it); reader 0 is whichever board enumerated first and that is not an identity." >&2
            exit 2
        fi
    fi
    if [ -n "$HSM_TARGET_SERIAL" ]; then
        READER="$(hsm_reader_for "$HSM_TARGET_SERIAL")" || {
            echo "FATAL: cannot resolve HSM_TARGET_SERIAL=$HSM_TARGET_SERIAL to a reader" >&2; exit 2; }
        SLOTIX="$(hsm_slot_index_for "$HSM_TARGET_SERIAL")" || {
            echo "FATAL: cannot resolve HSM_TARGET_SERIAL=$HSM_TARGET_SERIAL to a PKCS#11 slot" >&2; exit 2; }
        # Address the slot by ID. The ordinal shifts when the other card leaves or rejoins the bus;
        # the ID does not. Measured 2026-09-03: ids 0x0 and 0x4 against ordinals 0 and 1.
        SLOTID="$(hsm_slot_id_for "$HSM_TARGET_SERIAL")" || {
            echo "FATAL: cannot resolve HSM_TARGET_SERIAL=$HSM_TARGET_SERIAL to a PKCS#11 slot id" >&2; exit 2; }
        printf 'targeting card %s (reader %s, slot id %s) — this suite WIPES it\n' \
            "$HSM_TARGET_SERIAL" "$READER" "$SLOTID"
    fi

    # THE ROLE REGISTRY GATE — same rule as hsm-scenarios.sh: the card this suite WIPES must be
    # registered staging in the committed registry (default-deny), whether it was named by serial,
    # handed down by a parent, or fell back to the single-card reader default.
    if ! command -v hsm_assert_staging >/dev/null 2>&1; then
        echo "FATAL: the role registry gate (tools/hsm-reader-select.sh) is unavailable — this suite" >&2
        echo "re-provisions its target and refuses to run without the default-deny gate." >&2
        exit 2
    fi
    if [ -n "$HSM_TARGET_SERIAL" ]; then
        hsm_assert_staging "$HSM_TARGET_SERIAL" || exit 2
    else
        _ct_ser="$(hsm_serial_at_reader "$READER" 2>/dev/null)" || _ct_ser=""
        [ -n "$_ct_ser" ] || {
            echo "FATAL: reader $READER did not answer with a serial — cannot prove it is a registered" >&2
            echo "staging card, and this suite re-provisions what it talks to. A blank card is provisioned" >&2
            echo "by the bootstrap path, not by this suite; a wedged card must never pass for a blank one." >&2
            exit 2; }
        hsm_assert_staging "$_ct_ser" || exit 2
    fi
    # Children resolve their own card from these. Two variables, because they are two things:
    # HSM_PCSC_INDEX is what `sc-hsm-tool -r` wants; HSM_READER is a reader NAME, which is what
    # scsh's `new Card()` wants (hsm-import-key.sh:104).
    export HSM_PCSC_INDEX="$READER" HSM_SLOT_INDEX="$SLOTIX" HSM_SLOT_ID="$SLOTID"
    # Assign, THEN export. `export X="$(cmd)"` masks the command's exit status, and an empty
    # HSM_READER is not a harmless default: scsh matches reader names by PREFIX, so an empty name
    # matches the FIRST reader — which is how a run reaches the wrong card.
    _rn="$(hsm_reader_name "$READER" 2>/dev/null)" || _rn=""
    if [ -n "$_rn" ]; then export HSM_READER="$_rn"; else
      printf 'WARNING: could not read the name of reader %s; leaving HSM_READER unset rather than empty\n' "$READER" >&2
    fi
fi

P11MOD="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"

# Device identity, cheaply, on whichever platform. It only has to CHANGE across a re-enumeration;
# its actual value is meaningless. On Linux the bus/device number is reassigned on reconnect; on
# macOS the IORegistry entry id is.
device_id() {
    case "$(uname -s)" in
        Darwin) ioreg -p IOUSB -w0 2>/dev/null | grep -i "pico" | grep -oE "id 0x[0-9a-f]+" | head -1;;
        Linux)  lsusb -d "$VIDPID" 2>/dev/null | head -1 | awk '{print $2"/"$4}';;
        *)      echo "unsupported platform: $(uname -s)" >&2; exit 2;;
    esac
}

card_responds() {
    # Judge by output: sc-hsm-tool exits 0 while printing "Failed to connect to card", so an
    # exit-status check reports an absent card as alive (see tools/hsm-scenarios.sh card_alive).
    perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool -r "$READER" 2>&1 | grep -qi '^Version'
}

# Wait for a NEW identity, i.e. the device re-enumerated. Returns 0 with SECS set, else 1.
SECS=0
wait_for_new_id() {
    local before="$1" limit="${2:-45}" waited=0 now
    while [ "$waited" -lt "$limit" ]; do
        sleep 1; waited=$((waited + 1))
        now="$(device_id)"
        if [ -n "$now" ] && [ "$now" != "$before" ]; then SECS=$waited; return 0; fi
    done
    SECS=$waited; return 1
}

start_uart_capture() {
    [ -n "$UART" ] || return 0
    [ -e "$UART" ] || { echo "  ! UART $UART not present, continuing without logs" >&2; UART=""; return 0; }
    # Raw read in the background. cat is enough: we only ever want to see what the firmware said,
    # never to write to it.
    ( stty -f "$UART" 115200 raw 2>/dev/null || stty -F "$UART" 115200 raw 2>/dev/null ) || true
    cat "$UART" > "$LOGDIR/uart-cycle-$1.log" 2>/dev/null &
    UART_PID=$!
}

stop_uart_capture() {
    [ -n "${UART_PID:-}" ] || return 0
    kill "$UART_PID" 2>/dev/null; wait "$UART_PID" 2>/dev/null
    UART_PID=""
}

# Cut and restore the Pico's hub port via uhubctl. Returns 0 when the device is back.
power_cycle_port() {
    [ -n "$UHUBCTL_LOC" ] && [ -n "$UHUBCTL_PORT" ] || return 1
    command -v uhubctl >/dev/null || { echo "uhubctl not installed (brew install uhubctl)" >&2; return 1; }
    uhubctl -l "$UHUBCTL_LOC" -p "$UHUBCTL_PORT" -a off >/dev/null 2>&1
    sleep 3
    uhubctl -l "$UHUBCTL_LOC" -p "$UHUBCTL_PORT" -a on  >/dev/null 2>&1
    for _ in $(seq 1 20); do
        sleep 1
        [ -n "$(device_id)" ] && return 0
    done
    return 1
}

if [ -n "${CYCLE_PORT_TEST:-}" ]; then
    UHUBCTL_PORT="${UHUBCTL_PORT:-$CYCLE_PORT_TEST}"
    echo "power-cycle acceptance test: loc=$UHUBCTL_LOC port=$UHUBCTL_PORT"
    [ -n "$UHUBCTL_LOC" ] || { echo "set HSM_UHUBCTL_LOC first (see `uhubctl` output)" >&2; exit 2; }
    [ -n "$(device_id)" ] || { echo "no Pico HSM on the bus to cycle" >&2; exit 1; }
    if power_cycle_port; then
        echo "PASS: device dropped and re-enumerated — the hub really switches that port"
        exit 0
    else
        echo "FAIL: device did not come back — check loc/port, or the hub fakes power switching" >&2
        exit 1
    fi
fi

LOGDIR="$(mktemp -d)"
echo "logs: $LOGDIR"
[ -n "$UART" ] && echo "uart: $UART (115200)"
echo "cycles: $CYCLES  mode: $([ "$FULL" = 1 ] && echo full-chain || echo reset-only)"
echo

if [ -z "$(device_id)" ]; then
    echo "no Pico HSM on the bus ($VIDPID) — plug it in first" >&2
    exit 1
fi

pass=0; fail=0; declined=0; times=""; chain_pass=0; chain_fail=0; consec_declined=0; power_cycles=0
for n in $(seq 1 "$CYCLES"); do
    printf 'cycle %s/%s: ' "$n" "$CYCLES"
    start_uart_capture "$n"
    before="$(device_id)"

    # The alarm must OUTLIVE the firmware's own 180s commit cap plus response time, otherwise
    # a legitimate slow wipe reads as a stall and the refusal response arrives after we died.
    perl -e 'alarm 300; exec @ARGV' -- sc-hsm-tool -r "$READER" --initialize \
        --so-pin "$SO_PIN" --pin "$USER_PIN" --dkek-shares 1 --label "cycle$n" \
        < /dev/null > "$LOGDIR/init-$n.log" 2>&1
    init_rc=$?

    # A completed reset is proven by the card coming back in the FRESH post-initialize
    # state — a DKEK domain pending its share. Two earlier signals died on measurement:
    # macOS now RECYCLES the USB registry id for a same-serial reconnect (identical id
    # before and after a verified reboot, 2026-08-02), and OpenSC does not surface the
    # --label value in the PKCS#11 token label. "DKEK import pending" is durable
    # evidence: the previous cycle's chain completed its domain, so only a wipe +
    # re-init + reboot produces "pending". The 360s window must outlive the firmware's
    # 300s core1 watchdog deadline, so a recovery reset is SEEN rather than misread.
    settled=0
    for waited in $(seq 1 360); do
        sleep 1
        if sc-hsm-tool -r "$READER" 2>/dev/null | grep -q "DKEK import pending"; then
            settled=1; SECS=$waited; break
        fi
    done
    if [ "$settled" = 1 ]; then
        pass=$((pass + 1)); times="$times $SECS"
        echo "RECOVERED in ${SECS}s (init rc=$init_rc, fresh DKEK-pending state confirmed)"
    else
        # "No re-enumeration" has TWO causes and they are opposites. The firmware declines to
        # reset when the flash commit is unconfirmed (returning SW_EXEC_ERROR and staying alive
        # on purpose, since an operator who can retry beats a device needing a datacenter visit).
        # That also produces no new identity — but the device is FINE. Calling it a hang would
        # report the safety mechanism working as a failure, so distinguish them by whether the
        # device is still on the bus.
        stop_uart_capture
        if [ -n "$(device_id)" ]; then
            echo "DECLINED to reset but device is ALIVE (init rc=$init_rc) — commit was"
            echo "         unconfirmed and the firmware correctly refused to reset. Retryable."
            declined=$((declined + 1)); consec_declined=$((consec_declined + 1))
            # A refusal is retryable by design, so retry — but a device that refuses forever
            # is its own finding, so bound the retries and stop loudly.
            if [ "$consec_declined" -ge 3 ]; then
                echo "3 consecutive refusals — stopping; this needs eyes, not more retries."
                break
            fi
            continue
        else
            # Device left the bus. With a power-switchable hub configured this is no longer a
            # walk-to-the-desk event: cut the port, restore it, and keep going. The wedged boot
            # is abandoned, not scored; the next cycle re-runs the full chain anyway.
            if [ -n "$UHUBCTL_LOC" ] && [ -n "$UHUBCTL_PORT" ]; then
                echo "HUNG — power-cycling the port (loc=$UHUBCTL_LOC port=$UHUBCTL_PORT)..."
                if power_cycle_port; then
                    power_cycles=$((power_cycles + 1))
                    echo "  REVIVED by power cycle #$power_cycles — campaign continues."
                    continue
                fi
                echo "  power cycle did NOT revive it — that needs eyes, not more retries."
            fi
            fail=$((fail + 1))
            echo "HUNG — gone from the bus after ${SECS}s. NEEDS A PHYSICAL REPLUG; stopping."
            [ -n "$UART" ] && echo "  firmware log: $LOGDIR/uart-cycle-$n.log"
        fi
        break
    fi
    stop_uart_capture
    consec_declined=0

    if [ "$FULL" = 1 ]; then
        # The whole point of --full: assert CRYPTO CORRECTNESS every cycle, not just that the
        # device came back. Re-provisioning that reliably produces the WRONG key would pass a
        # reset-only test forever, and would lose funds in production. So each cycle re-imports
        # the seed-derived key and proves the card signs for the seed's public key — plus a
        # negative control, so a verifier that trivially returns success cannot fake a pass.
        chain_ok=1
        if [ ! -f "$STAGING/dkek.pbe" ] || [ ! -f "$STAGING/dkek.pw" ]; then
            echo "  ! no DKEK share in $STAGING — cannot run the chain"; chain_ok=0
        elif [ ! -x "$AUTO_IMPORT" ]; then
            echo "  ! auto-import script not found at $AUTO_IMPORT (set HSM_AUTO_IMPORT)"; chain_ok=0
        fi

        if [ "$chain_ok" = 1 ]; then
            DKEK_PW="$(cat "$STAGING/dkek.pw")" perl -e 'alarm 120; exec @ARGV' -- \
                sc-hsm-tool -r "$READER" --import-dkek-share "$STAGING/dkek.pbe" \
                --password env:DKEK_PW --so-pin "$SO_PIN" < /dev/null \
                > "$LOGDIR/dkek-$n.log" 2>&1 || chain_ok=0
            [ "$chain_ok" = 1 ] || echo "  CHAIN FAIL: dkek import"
        fi

        if [ "$chain_ok" = 1 ]; then
            HSM_AUTO_DIR="$STAGING/auto-import" SCSH_HOME="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}" \
            HSM_USER_PIN="$USER_PIN" HSM_DKEK_SHARE_IN="$STAGING/dkek.pbe" \
            HSM_DKEK_PW_IN="$STAGING/dkek.pw" \
                perl -e 'alarm 300; exec @ARGV' -- "$AUTO_IMPORT" --run \
                > "$LOGDIR/import-$n.log" 2>&1 || chain_ok=0
            [ "$chain_ok" = 1 ] || echo "  CHAIN FAIL: key import (see $LOGDIR/import-$n.log)"
        fi

        if [ "$chain_ok" = 1 ]; then
            head -c 32 /dev/urandom > "$LOGDIR/d-$n.bin"
            # --slot, because the chain check is the whole point: without it pkcs11-tool picks the
            # first token, so on a two-card bench this can sign with the OTHER card and then report
            # "CHAIN FAIL: card signature does NOT match the seed's pubkey" for a healthy target —
            # while spending a PIN login on a card nobody named. hsm-scenarios.sh already passes it.
            pkcs11-tool --module "$P11MOD" --slot "$SLOTID" --login --pin "$USER_PIN" --sign --mechanism ECDSA \
                --id 31 --input-file "$LOGDIR/d-$n.bin" --output-file "$LOGDIR/s-$n.bin" \
                > "$LOGDIR/sign-$n.log" 2>&1 || chain_ok=0
            if [ "$chain_ok" = 1 ]; then
                python3 "$VERIFY" --der "$STAGING/expected-pub.der" \
                    --digest "$LOGDIR/d-$n.bin" --sig "$LOGDIR/s-$n.bin" >/dev/null 2>&1
                if [ $? -ne 0 ]; then
                    chain_ok=0; echo "  CHAIN FAIL: card signature does NOT match the seed's pubkey"
                else
                    # Negative control: the same signature against a DIFFERENT digest must FAIL.
                    # Without this, a verifier stuck returning 0 would make every cycle "pass".
                    head -c 32 /dev/urandom > "$LOGDIR/dbad-$n.bin"
                    python3 "$VERIFY" --der "$STAGING/expected-pub.der" \
                        --digest "$LOGDIR/dbad-$n.bin" --sig "$LOGDIR/s-$n.bin" >/dev/null 2>&1
                    if [ $? -eq 0 ]; then
                        chain_ok=0; echo "  CHAIN FAIL: negative control PASSED — verifier is not discriminating"
                    fi
                fi
            else
                echo "  CHAIN FAIL: on-card signing"
            fi
        fi

        if [ "$chain_ok" = 1 ]; then
            chain_pass=$((chain_pass + 1)); echo "  chain OK (key imported, signed, verified, negative control held)"
        else
            chain_fail=$((chain_fail + 1))
        fi
    fi
done

echo
echo "==================================================="
echo " passed: $pass    hung: $fail    declined-safely: $declined    of $((pass + fail + declined)) attempted"
[ -n "$times" ] && echo " recovery times:$times (seconds)"
[ "$FULL" = 1 ] && echo " full chain: $chain_pass verified, $chain_fail failed"
[ "$power_cycles" -gt 0 ] && echo " power-cycle recoveries: $power_cycles"
echo " logs: $LOGDIR"
echo "==================================================="
[ "$fail" -eq 0 ] && [ "${chain_fail:-0}" -eq 0 ] || exit 1
