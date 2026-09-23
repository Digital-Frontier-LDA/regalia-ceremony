#!/usr/bin/env bash
# hsm-journal-powercut.sh — does upstream's flash journal stop a power cut from wedging the card,
# or from losing a write the card already acknowledged?
#
#   tools/hsm-journal-powercut.sh [cycles] [outdir]
#
# THE QUESTION. pico-keys-sdk 5efcd251 added a per-sector write-ahead journal that scan_region()
# replays at boot when it finds the filesystem corrupted (hardware/pico-hsm/UPSTREAM-FLASH-JOURNAL.md).
# Our Bug 6 symptoms were: writes that did not survive, and a boot that hard-faulted on corrupted
# metadata. This asks, per cut, the three things those symptoms were about:
#
#   * does the card come back at all?                      (WEDGED if not)
#   * is every keygen the card ACKNOWLEDGED still there?    (LOST_ACKED_WRITE if not)
#   * did the journal have to act?                         (the boot log's "flash redo restored")
#
# The third is what makes a clean result mean something: "came back fine, journal restored" is
# evidence about the journal, "came back fine, journal silent" only says the cut did no damage.
#
# WHAT THIS DOES NOT ANSWER. The cross-sector ORDERING hypothesis needs the FORENSIC_CAUSAL recorder
# and tools/hsm-bug6-powerloss.sh. That recorder lived only on the old macOS bench; this rig needs
# nothing but stock firmware built with UART stdio.
#
# POWER. HSM_JCUT_POWER=qrexec uses the dom0 service in qubes/bench/, which also re-attaches the card
# after a cut — on Qubes R4.2 a re-enumerated device does not come back to this qube on its own.
# HSM_JCUT_POWER=manual (the default) cues an operator to pull the cable, then to plug it back in and
# re-attach it from dom0. Run it in a terminal the operator is watching. The cut is timed from when
# the device LEAVES USB, not from the cue, so reaction time does not blur where the cut landed.
#
# HONEST LIMITS. A hub cut lands wherever it lands, so a clean run bounds the failure rate, it does
# not prove it zero. And this DESTROYS keys on purpose: staging only, serial-checked.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
. "$REPO/tools/hsm-reader-select.sh"

POWER_MODE="${HSM_JCUT_POWER:-manual}"
case "$POWER_MODE" in manual) CYCLES="${1:-5}" ;; qrexec) CYCLES="${1:-20}" ;;
    *) echo "HSM_JCUT_POWER must be manual or qrexec" >&2; exit 2 ;; esac
OUT="${2:-$HOME/.local/share/regalia-bench/journal-$(date +%Y%m%d-%H%M%S)}"
SERIAL="${HSM_PICO_SERIAL:-ESP41D722E2}"
PIN="${HSM_USER_PIN:-648219}"
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
export HSM_PKCS11_MODULE="$MODULE"
UART="${HSM_UART:-$(ls /dev/serial/by-id/*Debug_Probe*-if01 2>/dev/null | head -1)}"
PYBIN="${HSM_PYSERIAL_PYTHON:-python3}"
KEYGENS="${HSM_JCUT_KEYGENS:-4}"
# A cut placed uniformly in this window (ms). MEASURED 2026-09-23 on upstream firmware: one EC P-256
# keygen, login included, takes ~12.5 s. Starting the window after the first one completes means
# every cut has at least one ACKNOWLEDGED write to lose; a window inside the first keygen (the old
# 1.5-9 s) could never exercise LOST_ACKED_WRITE at all.
DMIN="${HSM_JCUT_DMIN_MS:-14000}"; DMAX="${HSM_JCUT_DMAX_MS:-40000}"
BACK_WAIT="${HSM_JCUT_BACK_WAIT:-60}"
VIDPID="${HSM_PICO_VIDPID:-2e8a:10fd}"

say(){ printf '  %s\n' "$*"; }
on_usb(){ lsusb -d "$VIDPID" >/dev/null 2>&1; }
cue(){ printf '\a\n  >>>>>>>>>>  %s  <<<<<<<<<<\n\n' "$*" > /dev/tty 2>/dev/null || printf '  >>> %s\n' "$*"; }
# manual: "off" returns once the device has LEFT USB, "on" once it is BACK on USB (re-attached).
power(){
    if [ "$POWER_MODE" = qrexec ]; then qrexec-client-vm dom0 "regalia.PicoPower+$1"; return; fi
    case "$1" in
        status) on_usb && echo "manual: $VIDPID present on USB" || { echo "manual: $VIDPID not on USB"; return 1; } ;;
        off) cue "PULL THE PICO'S CABLE NOW"
             for _ in $(seq 1 600); do on_usb || { echo OFF; return 0; }; sleep 0.1; done
             echo "the Pico was still on USB 60s after the cue"; return 1 ;;
        on)  cue "PLUG IT BACK IN, THEN RE-ATTACH FROM DOM0 (qvm-usb attach dev-regalia sys-usb:<id>)"
             until on_usb; do sleep 0.5; done; echo "ATTACHED (manual)" ;;
    esac
}
slot(){ hsm_slot_id_for "$SERIAL" 2>/dev/null; }
p11(){ local s; s="$(slot)"; [ -n "$s" ] || return 9; timeout 40 pkcs11-tool --module "$MODULE" --slot "$s" "$@"; }
answers(){ p11 -I >/dev/null 2>&1; }
labels(){ p11 --login --pin "$PIN" -O --type privkey 2>/dev/null | sed -n 's/^ *label: *//p'; }

mkdir -p "$OUT"
say "output: $OUT"

# ---- PRECONDITIONS: each of these has produced a confident wrong answer on this bench ----------
[ -r "$MODULE" ] || { echo "REFUSING: no PKCS#11 module at $MODULE" >&2; exit 2; }
[ -n "$UART" ] && [ -e "$UART" ] || { echo "REFUSING: no Debug Probe UART found (set HSM_UART)" >&2; exit 2; }
[ -r "$UART" ] && [ -w "$UART" ] || { echo "REFUSING: $UART is not readable (dialout group, or: sudo chmod o+rw $(readlink -f "$UART"))" >&2; exit 2; }
"$PYBIN" -c 'import serial' 2>/dev/null || { echo "REFUSING: pyserial missing for $PYBIN (set HSM_PYSERIAL_PYTHON)" >&2; exit 2; }
[ "$POWER_MODE" = manual ] || command -v qrexec-client-vm >/dev/null || { echo "REFUSING: not a Qubes qube, no power control" >&2; exit 2; }
# ONLY A REGISTERED DISPOSABLE CARD. The serial resolves the slot; nothing here defaults to slot 0.
command -v hsm_assert_staging_card >/dev/null 2>&1 \
    || { echo "REFUSING: the staging registry gate is unavailable (hsm-reader-select.sh)" >&2; exit 2; }
hsm_assert_staging_card "$SERIAL" || exit 2
answers || { echo "REFUSING: $SERIAL does not answer before the first cut" >&2; exit 2; }
power status > "$OUT/power-status.txt" 2>&1 || { echo "REFUSING: the power service does not answer" >&2; cat "$OUT/power-status.txt" >&2; exit 2; }
say "power: $(tail -1 "$OUT/power-status.txt")"

# THE BOOT LOG IS THE ONLY WAY TO TELL "NO DAMAGE" FROM "DAMAGE, REPAIRED". Prove it arrives before
# spending cuts on a channel that is silent: one cycle's boot must print SOMETHING.
capture(){ "$PYBIN" - "$UART" "$1" <<'EOPY' &
import serial, sys
s = serial.Serial(sys.argv[1], 115200, timeout=0.5)
with open(sys.argv[2], "ab", buffering=0) as f:
    while True:
        try:
            b = s.read(4096)
        except serial.SerialException:
            break
        if b:
            f.write(b)
EOPY
CAP_PID=$!; }
CAP_PID=""
cleanup(){ [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null; [ -n "${WL_PID:-}" ] && kill -- "-$WL_PID" 2>/dev/null; [ "$POWER_MODE" = qrexec ] && { power on >/dev/null 2>&1 || true; }; }
trap cleanup EXIT
trap 'exit 130' INT TERM

{
    echo "power=$POWER_MODE"
    echo "serial=$SERIAL cycles=$CYCLES keygens=$KEYGENS window_ms=$DMIN-$DMAX"
    echo "tooling=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)"
    echo "firmware_note=${HSM_JCUT_FIRMWARE:-unrecorded}"
} > "$OUT/run.meta"

declare -A TALLY=()
for c in $(seq 1 "$CYCLES"); do
    D="$OUT/cycle-$(printf '%03d' "$c")"; mkdir -p "$D"
    # CAPACITY: remove this rig's own keys from earlier cycles, never anything else.
    for l in $(labels | grep -E '^jcut-' ); do p11 --login --pin "$PIN" --delete-object --type privkey --label "$l" >/dev/null 2>&1; p11 --login --pin "$PIN" --delete-object --type pubkey --label "$l" >/dev/null 2>&1; done
    TAG="$(( ($(date +%s) + c) % 4096 ))"
    capture "$D/uart.log"
    : > "$D/acked"
    setsid bash -c '
        for j in $(seq 1 '"$KEYGENS"'); do
            id="$(printf "%04x" $(( ('"$TAG"' * 16 + j) % 65536 )))"
            if timeout 30 pkcs11-tool --module "'"$MODULE"'" --slot "$1" --login --pin "'"$PIN"'" \
                 --keypairgen --key-type EC:prime256v1 --id "$id" --label "jcut-'"$TAG"'-$j" >/dev/null 2>&1; then
                echo "jcut-'"$TAG"'-$j" >> "'"$D"'/acked"
            fi
        done' _ "$(slot)" > "$D/workload.log" 2>&1 &
    WL_PID=$!
    WL_T0=$(date +%s%N)
    DELAY=$(( DMIN + ( (RANDOM << 15 | RANDOM) % (DMAX - DMIN + 1) ) ))
    sleep "$(printf '%d.%03d' $((DELAY / 1000)) $((DELAY % 1000)))"
    if ! power off > "$D/power-off.txt" 2>&1; then
        say "cycle $c: ABANDONED — the power service would not cut"; kill -- "-$WL_PID" 2>/dev/null; break
    fi
    # AN ACK THAT RACED THE CUT COUNTS ONLY IF IT WAS WRITTEN BEFORE THE CUT RETURNED. Freeze the list
    # now; anything the dying worker appends later is not an acknowledgement the card made.
    cp "$D/acked" "$D/acked.at-cut"
    CUT_MS=$(( ($(date +%s%N) - WL_T0) / 1000000 ))
    kill -- "-$WL_PID" 2>/dev/null; wait "$WL_PID" 2>/dev/null; WL_PID=""
    sleep 3
    power on > "$D/power-on.txt" 2>&1 || say "cycle $c: power-on did not re-attach ($(tail -1 "$D/power-on.txt"))"
    back=""
    for _ in $(seq 1 "$BACK_WAIT"); do answers && { back=1; break; }; sleep 1; done
    sleep 2; kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; CAP_PID=""
    restored=0; grep -aq 'flash redo restored' "$D/uart.log" 2>/dev/null && restored=1
    if [ -z "$back" ]; then
        verdict=WEDGED
    else
        labels > "$D/labels.after"
        lost="$(grep -vxF -f "$D/labels.after" "$D/acked.at-cut" | tr '\n' ' ')"
        if [ -n "$lost" ]; then verdict=LOST_ACKED_WRITE; echo "$lost" > "$D/lost"
        elif [ "$restored" = 1 ]; then verdict=RECOVERED_BY_JOURNAL
        else verdict=CLEAN; fi
    fi
    TALLY[$verdict]=$(( ${TALLY[$verdict]:-0} + 1 ))
    printf '{"cycle":%d,"cue_ms":%d,"cut_ms":%d,"acked_at_cut":%d,"journal_restored":%d,"uart_bytes":%d,"verdict":"%s"}\n' \
        "$c" "$DELAY" "$CUT_MS" "$(wc -l < "$D/acked.at-cut")" "$restored" "$(stat -c %s "$D/uart.log" 2>/dev/null || echo 0)" \
        "$verdict" | tee -a "$OUT/results.jsonl" | sed 's/^/  /'
    # A SILENT BOOT LOG MAKES "CLEAN" UNINTERPRETABLE. Stop after the first cycle rather than score 20.
    if [ "$c" = 1 ] && [ ! -s "$D/uart.log" ]; then
        say "STOPPING: the UART carried nothing across a boot, so CLEAN and RECOVERED cannot be told apart."
        say "  Check the probe's UART is wired to the board's stdio UART and the build has PICO_STDIO_UART=ON."
        exit 3
    fi
    if [ "$verdict" = WEDGED ]; then
        say "cycle $c: the card did not come back within ${BACK_WAIT}s — stopping, the state is the evidence"
        say "  inspect over SWD before anything power-cycles it again"
        break
    fi
done

{ for k in "${!TALLY[@]}"; do echo "$k=${TALLY[$k]}"; done; } | sort | tee "$OUT/summary.txt" | sed 's/^/  /'
