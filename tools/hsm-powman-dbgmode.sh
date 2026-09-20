#!/usr/bin/env bash
# hsm-powman-dbgmode.sh — set, clear, or read RP-AP CTRL.POWMAN_DBGMODE on the RP2350.
#
#   tools/hsm-powman-dbgmode.sh status | on | off
#
# WHAT IT IS FOR. This is the causal discriminator for the stalled-bus wedge, not a fix.
#
# The leading hypothesis is that the wedge is an AHB transaction to the switched-core domain while
# that domain is powered down or mid-transition — the firmware's own `chip_reset_now(deep)`
# POWMAN-power-cycles it. `POWMAN_DBGMODE` is described in the SDK register header as:
#
#     "This prevents the power manager from powering down and resetting the switched-core power
#      domain. It is intended for DFT and for debugging the power manager after the chip has
#      booted. It cannot be used to force initial power on because it simultaneously deasserts
#      the reset."
#
# So the experiment is: run the SAME workload with the bit set and with it clear.
#
#   * wedges normally, stops wedging with DBGMODE set
#         -> strong evidence the switched-core power-down/reset path is NECESSARY for the bug.
#   * still wedges with DBGMODE set, and the snapshot shows SWCORE and both SRAM domains healthy
#         -> "the domain lost power" no longer explains it. Move the investigation to the
#            outstanding AHB transaction and the bus fabric.
#
# Either outcome is worth having; the second is arguably more valuable because it would redirect
# the whole investigation.
#
# CAVEAT WORTH STATING BEFORE ANYONE RUNS A SOAK WITH IT. Suppressing the switched-core power-down
# changes the behaviour under test. A reliability figure measured with this bit set is NOT a figure
# about the shipped configuration, and must never be quoted as one. This is a diagnostic, and runs
# using it should be labelled as such.
#
# Register: RP-AP CTRL (AP 0x80000, offset 0x00), bit 2 (0x00000004).
# Bit 31 of the same register is RESCUE_RESTART — do not disturb it.
set -uo pipefail

OCD_PORT="${OCD_PORT:-4444}"
OCD_BIN="${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}"
RP_AP="${RP_AP:-0x80000}"
DBGMODE_BIT=$(( 1 << 2 ))
ACTION="${1:-status}"

ocd(){ printf '%s\nexit\n' "$1" | perl -e 'alarm 40; exec @ARGV' -- nc localhost "$OCD_PORT" 2>&1 | LC_ALL=C tr -d '\000'; }
say(){ printf '  %s\n' "$*"; }

pgrep -f "$(basename "$OCD_BIN")" >/dev/null 2>&1 || {
    say "OpenOCD is not running — starting it with deferred examination"
    "$OCD_BIN" -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
        -c "rp2350.cm0 configure -defer-examine; rp2350.cm1 configure -defer-examine" \
        -c "adapter speed ${ADAPTER_SPEED:-5000}" > /tmp/ocd-dbgmode.log 2>&1 &
    sleep 9
}

read_ctrl(){ LC_ALL=C grep -aoE '^0x[0-9a-f]{8}' <<< "$(ocd "rp2350.dap apreg $RP_AP 0x00")" | head -1; }

cur="$(read_ctrl)"
[ -n "$cur" ] || { echo "RP-AP CTRL is unreadable — is the probe attached?" >&2; exit 2; }

is_set(){ [ $(( $1 & DBGMODE_BIT )) -ne 0 ] && echo on || echo off; }

case "$ACTION" in
  status)
      say "RP-AP CTRL = $cur   POWMAN_DBGMODE(bit 2) = $(is_set $(( cur )))"
      ;;
  on|off)
      # Read-modify-write, and preserve every other bit. RESCUE_RESTART is bit 31 of this same
      # register: writing a blanket value here would reset the chip.
      if [ "$ACTION" = on ]; then new=$(( cur | DBGMODE_BIT )); else new=$(( cur & ~DBGMODE_BIT )); fi
      printf '  RP-AP CTRL %s -> 0x%08x  (POWMAN_DBGMODE %s)\n' "$cur" "$new" "$ACTION"
      ocd "rp2350.dap apreg $RP_AP 0x00 $(printf '0x%08x' $new)" >/dev/null 2>&1
      back="$(read_ctrl)"
      say "readback: $back   POWMAN_DBGMODE = $(is_set $(( back )))"
      if [ "$(is_set $(( back )))" != "$ACTION" ]; then
          echo "  WARNING: the bit did not take. Do not run the A/B experiment on this result." >&2
          exit 1
      fi
      # `[ x ] && say ...` as the last statement makes the script exit 1 whenever the test is
      # false — i.e. `off` would report failure after succeeding. Use a real conditional.
      if [ "$ACTION" = on ]; then
          say "NOTE: this suppresses the switched-core power-down. Any reliability number measured"
          say "  now is a DIAGNOSTIC figure, not one about the shipped configuration."
      fi
      ;;
  *)  echo "usage: $0 status|on|off" >&2; exit 2 ;;
esac
