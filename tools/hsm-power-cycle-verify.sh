#!/usr/bin/env bash
# hsm-power-cycle-verify.sh — decide whether a uhubctl "port off" ACTUALLY removes power from the
# card, or merely disconnects its data lines.
#
#   ./tools/hsm-power-cycle-verify.sh [reps]
#
# WHY THIS IS NOT OBVIOUS, AND WHY THE OBVIOUS TEST IS WRONG.
#
# With the port commanded off the card stops answering APDUs. That is NOT evidence of power removal:
# a hub that disables only the data lines produces exactly the same symptom. This bench has already
# published one retraction built on that confusion — a card that "came back in 7 s from a power cut"
# turned out to have undergone a host-side USB re-enumeration while never losing power at all.
#
# `ioreg` presence is worse than useless here: the IOKit device object LINGERS after the port goes
# off, so "still present" and "enumerated at +0.00s" are stale-registry artifacts, not measurements.
#
# THE DISCRIMINATOR IS TIME-TO-ANSWER, AGAINST A POSITIVE CONTROL.
#
#   * A full firmware boot (bootrom -> init -> flash scan -> tusb_init -> CCID ready) takes seconds.
#     A rescue-applet reboot forces exactly that, and is the positive control: it is a known reset.
#   * A data-only reconnect skips all of it — the firmware never restarted — so the card answers
#     again almost immediately.
#
# So: cycle VBUS and time it, reboot via APDU and time it, with the SAME poller. If the VBUS cycle
# takes about as long as the known reboot, the chip restarted. If it is much faster, it never did.
#
# The two are measured back to back, alternating, so host-side drift cannot favour one.
set -uo pipefail

REPS="${1:-2}"
L="${HSM_UHUBCTL_LOC:-1-1.3}"
P="${HSM_UHUBCTL_PORT:-3}"
OFF_SECS="${HSM_OFF_SECS:-8}"

say(){ printf '%s\n' "$*"; }

# Time from now until the card answers an APDU. Polls as fast as sc-hsm-tool allows (~0.5 s), which
# is ample against the seconds-scale difference being tested for.
time_to_answer(){
    local t0 out
    t0=$(python3 -c 'import time;print(f"{time.time():.4f}")')
    while :; do
        out="$(perl -e 'alarm 20; exec @ARGV' -- sc-hsm-tool 2>&1)"
        if grep -qi '^Version' <<< "$out"; then
            python3 -c "import time;print(f'{time.time()-$t0:.2f}')"
            return 0
        fi
        # Give up rather than hang forever; the caller prints this as a failure.
        if [ "$(python3 -c "import time;print(int(time.time()-$t0))")" -ge 60 ]; then
            echo "TIMEOUT"; return 1
        fi
    done
}

say "Positive control = rescue-applet reboot (a KNOWN full firmware boot)."
say "Test            = uhubctl port off/on for ${OFF_SECS}s on hub $L port $P."
say ""

reboot_apdu=()
vbus=()

for i in $(seq 1 "$REPS"); do
    # --- positive control: force a real firmware boot -------------------------------------------
    perl -e 'alarm 45; exec @ARGV' -- opensc-tool \
        -s "00:A4:04:00:08:A0:58:3F:C1:9B:7E:4F:21" -s "80:1F:00:00" >/dev/null 2>&1
    t="$(time_to_answer)"
    reboot_apdu+=("$t")
    say "  rep $i  rescue reboot  -> answered in ${t}s"
    sleep 3

    # --- test: cut the port ----------------------------------------------------------------------
    uhubctl -e -l "$L" -p "$P" -a off >/dev/null 2>&1
    sleep "$OFF_SECS"
    uhubctl -e -l "$L" -p "$P" -a on  >/dev/null 2>&1
    t="$(time_to_answer)"
    vbus+=("$t")
    say "  rep $i  VBUS cycle     -> answered in ${t}s"
    sleep 3
done

say ""
python3 - "${reboot_apdu[*]}" "${vbus[*]}" <<'EOP'
import sys, statistics
def parse(s): return [float(x) for x in s.split() if x != "TIMEOUT"]
reb, vb = parse(sys.argv[1]), parse(sys.argv[2])
if not reb or not vb:
    print("  INCONCLUSIVE — a measurement timed out."); raise SystemExit(2)
r, v = statistics.mean(reb), statistics.mean(vb)
print(f"  known full boot (rescue reboot) : {r:.2f}s   {reb}")
print(f"  uhubctl port off/on             : {v:.2f}s   {vb}")
print()
if v >= 0.6 * r:
    print("  VERDICT: the VBUS cycle costs about as much as a known full boot.")
    print("  The firmware RESTARTED, so the port cut is doing something real — consistent with")
    print("  power actually being removed. Recovery-by-power-alone is testable on this bench.")
else:
    print("  VERDICT: the VBUS cycle is MUCH faster than a known full boot.")
    print("  The firmware did NOT restart — the hub is disconnecting DATA while leaving the board")
    print("  powered. Any 'recovered by power cycle' result on this bench would be a re-enumeration,")
    print("  exactly the error already retracted in UPSTREAM-WDSEL-SCOPE.md. Do not run the soak;")
    print("  the card needs a genuinely switchable supply, or hands.")
EOP
