#!/usr/bin/env bash
# hsm-capture-then-recover.sh — photograph a wedge, THEN clear it. Drop-in for HSM_RECOVER_CMD.
#
#   HSM_RECOVER_CMD="$PWD/tools/hsm-capture-then-recover.sh" tools/hsm-reboot-soak.sh 120 90
#
# WHY. The soak and the scenarios call a recovery command the moment a card fails to return, and
# recovery is what destroys the evidence: a rescue reset power-cycles the SRAM domains, taking the
# dirty sector cache and flash_pages with it. Every wedge cleared without a snapshot is a wedge
# spent for nothing — and on this bench they arrive at roughly one in sixty reboots, so there is no
# spare supply of them.
#
# This wrapper inserts the read-only snapshot in front of the real ladder. It:
#   * writes a pristine capture per wedge (deferred examination, so OpenOCD never runs its abort
#     path and the sticky bits survive to be read);
#   * records the POWMAN_DBGMODE state, because a run is only interpretable if you know which arm
#     of the A/B experiment produced it;
#   * then hands over to the ordinary recovery so the soak continues unattended.
#
# It never decides not to recover. An unattended run that stops to preserve evidence is an
# unattended run that has stopped; if a wedge deserves preserving, run with HSM_RECOVER_NO_RESCUE=1
# and watch it.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${HSM_WEDGE_DUMP_DIR:-$HOME/.local/share/akash-hsm-staging/wedges}"
mkdir -p "$DIR" 2>/dev/null
STAMP="$(date +%Y%m%d-%H%M%S)"
SNAP="$DIR/wedge-$STAMP.snapshot.txt"

# DO NOT PHOTOGRAPH THE SAME WEDGE TWICE.
#
# hsm-reboot-soak.sh already snapshots every wedge when HSM_WEDGE_SNAPSHOT is set, before its
# severity probe touches anything. If this wrapper then takes its own, one wedge leaves two files
# and anything counting snapshots over-reports. MEASURED 2026-08-09: a 56-reboot run with 3 wedges
# produced 5 snapshots, and the run was first summarised as "2 stalled-bus, 3 USB-only" — five
# wedges out of three. The true split was 2 USB-only and 1 stalled-bus.
#
# The second snapshot is also worth less: it is taken after the severity probe has already issued
# `reset run`, so it no longer describes the wedge as it occurred.
if [ -n "${HSM_WEDGE_SNAPSHOT:-}" ]; then
    printf '      wedge already photographed by the soak — not duplicating\n'
    # HSM_WEDGE_DUMP_DIR travels on THIS path too. Not duplicating the SNAPSHOT is the point; the
    # ladder's fs-tail dump in the bootrom window is the other half of the evidence and the soak
    # does not take it. Without this, every wedge the soak had already photographed lost its flash
    # half — silently, since the run still ends with a recovered card.
    HSM_WEDGE_DUMP_DIR="$DIR" exec "$HERE/hsm-swd-powman-recover.sh"
fi

{
    echo "# wedge $STAMP"
    echo "# tooling  $(git -C "$HERE/.." rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "# dbgmode  $("$HERE/hsm-powman-dbgmode.sh" status 2>/dev/null | grep -oE 'POWMAN_DBGMODE\(bit 2\) = (on|off)' | awk '{print $NF}')"
} > "$SNAP"

# The snapshot starts its own server with deferred examination; it must run before anything else
# touches the target.
perl -e 'alarm 180; exec @ARGV' -- "$HERE/hsm-wedge-snapshot.sh" >> "$SNAP" 2>&1 || true
verdict="$(grep -aoE '^VERDICT=[A-Z_]+' "$SNAP" | head -1)"
printf '      wedge captured: %s -> %s\n' "${verdict:-VERDICT=UNCAPTURED}" "$SNAP"

# Hand over to the real ladder. HSM_WEDGE_DUMP_DIR makes it dump the fs tail in the bootrom window
# after a rescue, which is the on-flash half of the evidence.
HSM_WEDGE_DUMP_DIR="$DIR" exec "$HERE/hsm-swd-powman-recover.sh"
