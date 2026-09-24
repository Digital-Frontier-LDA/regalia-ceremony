#!/usr/bin/env bash
# nitrokey-acceptance.sh — accept or reject a Nitrokey HSM 2 BEFORE it is trusted with anything,
# by testing for the 2025 batch defect (regalia#482: DENK0400664; Nitrokey support thread 6994,
# Nitrokey/nitrokey-pro-firmware#100).
#
#   sudo -v && qubes/scripts/nitrokey-acceptance.sh                  # the only Nitrokey on USB
#   sudo -v && qubes/scripts/nitrokey-acceptance.sh --usb 1-1        # one of several, by USB port path
#   qubes/scripts/nitrokey-acceptance.sh --enumerations 20 --apdus 4000
#
# NON-DESTRUCTIVE. No PIN, no SO PIN, no initialisation, no key operation: only USB re-enumeration
# and unauthenticated APDUs (SELECT the SmartCard-HSM applet, GET CHALLENGE). Safe on a
# factory-fresh PRODUCTION unit, which is exactly when it should run: on arrival, before commissioning.
#
# WHAT THE DEFECT LOOKS LIKE, AND WHAT THIS CHECKS (each measured on DENK0400664 vs DENK0404144):
#   1 serial   the USB serial string ALTERNATES between the real `DENK…` and the malformed
#              `01A001000000000` from one enumeration to the next. So the device is re-enumerated N
#              times (USB `authorized` toggle, no replug) and the serial must be the same well-formed
#              value every time.
#   2 ATR      on a bad enumeration the ATR truncates to 3 bytes. Every enumeration must give the full
#              24-byte SmartCard-HSM ATR (3b:de:96:…).
#   3 stamina  on a GOOD enumeration the bad unit worked for 242 APDU exchanges, then went dead until
#              re-enumerated. The unit must answer thousands of GET CHALLENGEs, every one 90 00.
# One failure anywhere rejects the unit. The defect is intermittent, so a PASS is evidence and not
# proof. That is why the counts default well above where the bad unit failed.
set -euo pipefail
# Tests point this at a fake sysfs tree; on a real host it is always the kernel's.
USB_DEVICES="${NITROKEY_USB_DEVICES:-/sys/bus/usb/devices}"
ENUMS=10 APDUS=2000 USBPATH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --usb) USBPATH="${2:?}"; shift 2 ;;
    --enumerations) ENUMS="${2:?}"; shift 2 ;;
    --apdus) APDUS="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
# Positive integers only: 0 enumerations or 0 exchanges would ACCEPT a unit nothing was asked of.
for v in "$ENUMS" "$APDUS"; do
  [[ "$v" =~ ^[1-9][0-9]*$ ]] || { echo "--enumerations and --apdus must be positive integers (got '$v')" >&2; exit 2; }
done
for t in opensc-tool sudo; do command -v "$t" >/dev/null || { echo "$t is required" >&2; exit 2; }; done
sudo -n true 2>/dev/null || { echo "needs sudo for the USB re-enumeration; run 'sudo -v' first" >&2; exit 2; }

say(){ printf '%s %s\n' "$(date -u +%T)" "$*"; }
FAILS=0
fail(){ say "  FAIL: $*"; FAILS=$((FAILS + 1)); }

# ---- which device: by USB port path, never by serial (a defective unit can report the wrong one) ----
if [ -z "$USBPATH" ]; then
  found=()
  for d in "$USB_DEVICES"/*; do
    [ "$(cat "$d/idVendor" 2>/dev/null):$(cat "$d/idProduct" 2>/dev/null)" = "20a0:4230" ] && found+=("$(basename "$d")")
  done
  [ "${#found[@]}" -eq 1 ] || { echo "found ${#found[@]} Nitrokey HSMs on USB (${found[*]:-none}); pick one with --usb" >&2; exit 2; }
  USBPATH="${found[0]}"
fi
DEV="$USB_DEVICES/$USBPATH"
[ "$(cat "$DEV/idVendor" 2>/dev/null):$(cat "$DEV/idProduct" 2>/dev/null)" = "20a0:4230" ] \
  || { echo "$USBPATH is not a Nitrokey HSM (20a0:4230)" >&2; exit 2; }
say "Nitrokey HSM at USB $USBPATH: bcdDevice $(cat "$DEV/bcdDevice"), serial string '$(tr -d ' ' < "$DEV/serial" 2>/dev/null)'"
say "  opensc $(opensc-tool --info 2>/dev/null | sed -n 's/^OpenSC \([0-9.]*\).*/\1/p' | head -1)"

# The PC/SC reader name carries the USB serial string the device reported THIS time.
# The list is captured before it is searched: a pipe from opensc-tool under pipefail can report its
# producer's failure (or a SIGPIPE) as the search's, and hsm-lint-predicates.sh refuses that shape.
reader_index(){ local serial readers; serial="$(tr -d ' ' < "$DEV/serial" 2>/dev/null)"
  [ -n "$serial" ] || return 1
  readers="$(opensc-tool -l 2>/dev/null || true)"
  awk -v s="$serial" 'index($0, "(" s) { print $1; exit }' <<< "$readers"; }
wait_reader(){ local r; for _ in $(seq 1 20); do r="$(reader_index || true)"; [ -n "$r" ] && { echo "$r"; return 0; }; sleep 1; done; return 1; }

# ---- 1 + 2: re-enumerate, and read the serial and the ATR every time --------------------------------
say "CHECK 1+2 — $ENUMS re-enumerations: the serial must never change and the ATR must be the full 24 bytes"
FIRST_SERIAL=""
for n in $(seq 1 "$ENUMS"); do
  echo 0 | sudo tee "$DEV/authorized" >/dev/null; sleep 1
  echo 1 | sudo tee "$DEV/authorized" >/dev/null; sleep 2
  serial="$(tr -d ' ' < "$DEV/serial" 2>/dev/null || true)"
  [ -n "$FIRST_SERIAL" ] || FIRST_SERIAL="$serial"
  reader="$(wait_reader || true)"
  atr="$( [ -n "$reader" ] && opensc-tool --reader "$reader" -a 2>/dev/null | tail -1 || true)"
  bytes=$(( $(printf '%s' "$atr" | tr -cd ':' | wc -c) + 1 )); [ -n "$atr" ] || bytes=0
  line="  enumeration $n: serial '$serial', ATR $bytes bytes"
  if [ "$serial" = "01A001000000000" ]; then fail "$line — the MALFORMED serial of the batch defect"
  elif ! [[ "$serial" =~ ^DENK[0-9]{7}0000$ ]]; then fail "$line — not a well-formed Nitrokey HSM serial"
  elif [ "$serial" != "$FIRST_SERIAL" ]; then fail "$line — changed from '$FIRST_SERIAL'"
  elif [ -z "$reader" ]; then fail "$line — no PC/SC reader appeared"
  elif [ "$bytes" != 24 ] || [[ "$atr" != 3b:de:96:* ]]; then fail "$line — truncated or foreign ATR '$atr'"
  else say "$line, $atr" ; fi
done

# ---- 3: stamina — thousands of unauthenticated exchanges on ONE enumeration -------------------------
say "CHECK 3 — $APDUS GET CHALLENGE exchanges without re-enumerating (the bad unit died after 242)"
reader="$(wait_reader || true)"
if [ -z "$reader" ]; then
  fail "no reader to run the stamina check on"
else
  SELECT="00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00"
  done_ok=0 batch=250
  while [ "$done_ok" -lt "$APDUS" ]; do
    n=$(( APDUS - done_ok < batch ? APDUS - done_ok : batch ))
    args=(--reader "$reader" -s "$SELECT"); for _ in $(seq 1 "$n"); do args+=(-s "00 84 00 00 08"); done
    out="$(timeout 120 opensc-tool "${args[@]}" 2>&1 || true)"
    ok="$(grep -c 'SW1=0x90, SW2=0x00' <<< "$out" || true)"
    ok=$(( ok > 0 ? ok - 1 : 0 ))                 # the SELECT's own 90 00 is not a challenge
    done_ok=$(( done_ok + ok ))
    if [ "$ok" -lt "$n" ]; then
      fail "exchange $((done_ok + 1)) failed after $done_ok good ones: $(grep -m1 -iE 'error|failed|dead|timeout|not present|SW1=0x[^9]' <<< "$out" || echo 'no response')"
      break
    fi
  done
  [ "$done_ok" -ge "$APDUS" ] && say "  $done_ok/$APDUS exchanges answered 90 00"
fi

if [ "$FAILS" -eq 0 ]; then
  say "ACCEPTED: $FIRST_SERIAL at USB $USBPATH — stable serial over $ENUMS enumerations, full ATR every time, $APDUS/$APDUS exchanges"
  exit 0
fi
say "REJECTED: $FAILS check(s) failed. Do not commission this unit; see regalia#482 for the RMA path"
exit 1
