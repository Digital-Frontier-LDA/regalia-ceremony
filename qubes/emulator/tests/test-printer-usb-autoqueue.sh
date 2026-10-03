#!/usr/bin/env bash
# test-printer-usb-autoqueue.sh — pick_printer() offers to create a CUPS queue when the disposable
# has none and a printer is attached by USB. The driver is matched on the device's IEEE-1284
# make-and-model (no model hard-coded); only a usb:// device is ever used; the device URI and the
# driver name reach lpadmin as checked plain arguments. Fake lpstat/lpinfo/lpadmin/sudo; the
# lpinfo output is shaped like CUPS 2.4 with Debian's printer-driver-brlaser installed.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
printf '#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n' > "$T/bin/sudo"
cat > "$T/bin/lpstat" <<'SH'
#!/bin/bash
q="$(cat "$STATE/queue" 2>/dev/null)"
case "${1:-}" in
  -p) [ -n "$q" ] && printf 'printer %s is idle.  enabled since today\n\tready to print\n' "$q";;   # real lpstat adds status lines
  -v) [ -n "$q" ] && echo "device for $q: $(cat "$STATE/uri")";;
esac; exit 0
SH
cat > "$T/bin/lpinfo" <<'SH'
#!/bin/bash
[ "${LC_ALL:-}" = C ] || { echo "Gerät: URI = usb://translated"; exit 0; }   # long form is translated
if [ "$*" = "--include-schemes usb -l -v" ]; then cat "$STATE/devices"; exit 0; fi
if [ "$1 $2" = "--exclude-schemes everywhere,driverless" ] && [ "$3" = --make-and-model ] && [ "$5" = -m ]; then
  # Like cups-driverd: every driver whose make-and-model CONTAINS the needle (case-insensitive).
  echo "$4" >> "$STATE/mm-asked"
  printf '%s\n' \
    "drv:///brlaser.drv/brl1200.ppd Brother HL-1200 series, using brlaser v6" \
    "drv:///brlaser.drv/brl2550d.ppd Brother DCP-L2550DW series, using brlaser v6" \
    "drv:///brlaser.drv/brl2550x.ppd Brother DCP-L2550DWX series, using brlaser v6" \
    "drv:///brlaser.drv/brl2560d.ppd Brother DCP-L2560DW series, using brlaser v6" \
    | grep -iF -- "$4"
fi; exit 0
SH
cat > "$T/bin/lpadmin" <<'SH'
#!/bin/bash
printf '%s\n' "$@" > "$STATE/lpadmin-args"
while [ $# -gt 0 ]; do case "$1" in -p) echo "$2" > "$STATE/queue"; shift;; -v) echo "$2" > "$STATE/uri"; shift;; esac; shift; done
SH
chmod +x "$T/bin"/*

BROTHER='Device: uri = usb://Brother/DCP-L2550DW%20series?serial=U64123A8N123456
        class = direct
        info = Brother DCP-L2550DW series
        make-and-model = Brother DCP-L2550DW series
        device-id = MFG:Brother;CMD:PJL,PCL,PCLXL,URF;MDL:DCP-L2550DW series;CLS:PRINTER;
        location = '
NETWORK='Device: uri = ipp://localhost:60000/ipp/print
        class = network
        info = Brother DCP-L2550DW series (IPP over USB)
        make-and-model = Brother DCP-L2550DW series
        device-id =
        location = 
Device: uri = socket
        class = network
        info = AppSocket/HP JetDirect
        make-and-model = Unknown
        device-id =
        location = '

# $1 = lpinfo -l -v output, $2 = what is typed; prints the transcript, then PRINTER=<value>
drive(){
  rm -rf "$T/state"; mkdir -p "$T/state"; printf '%s\n' "$1" > "$T/state/devices"
  printf '%b' "$2" | PATH="$T/bin:$PATH" STATE="$T/state" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1
    pick_printer; echo "PRINTER=$PRINTER"' 2>&1
}

hdr "no queue + a USB Brother: offered, created with the matching brlaser driver, then used"
out="$(drive "$BROTHER" 'y\n\n')"
grep -q "USB printer: Brother DCP-L2550DW series" <<< "$out" && P "the printer is named" || F "not offered: $out"
[ "$(sed -n 2p "$T/state/lpadmin-args" 2>/dev/null)" = vault-usb ] && P "queue vault-usb created" || F "no queue created"
grep -qx 'usb://Brother/DCP-L2550DW%20series?serial=U64123A8N123456' "$T/state/lpadmin-args" && P "with the USB device URI" || F "wrong URI"
grep -qx 'drv:///brlaser.drv/brl2550d.ppd' "$T/state/lpadmin-args" && P "with the DCP-L2550DW driver (not everywhere, not the L2560DW)" || F "wrong driver: $(cat "$T/state/lpadmin-args")"
grep -qx 'printer-is-shared=false' "$T/state/lpadmin-args" && P "not shared" || F "queue may be shared"
grep -q "^PRINTER=vault-usb$" <<< "$out" && P "Enter uses the only queue" || F "the new queue was not selected: $(tail -1 <<< "$out")"

hdr "declined: nothing is created"
out="$(drive "$BROTHER" 'n\n\n')"
[ ! -e "$T/state/lpadmin-args" ] && grep -q "^PRINTER=$" <<< "$out" && P "no queue, no printer" || F "a queue was created after 'n'"

hdr "only network devices (IPP-over-USB, socket): never offered"
out="$(drive "$NETWORK" '\n')"
grep -q "no USB printer detected" <<< "$out" && [ ! -e "$T/state/lpadmin-args" ] && P "not offered" || F "a network device was offered: $out"

hdr "a USB URI with shell characters and no space: refused"
out="$(drive "${BROTHER/serial=U64123A8N123456/serial=a;\`touch_$T/pwned\`}" 'y\n\n')"
grep -q "odd USB printer URI" <<< "$out" && [ ! -e "$T/state/lpadmin-args" ] && P "refused" || F "odd URI accepted: $out"

hdr "a make-and-model with a terminal escape: refused, never printed"
out="$(drive "${BROTHER/make-and-model = Brother/make-and-model = $(printf '\033]52;c;eA==\a')Brother}" 'y\n\n')"
grep -q "odd printer make-and-model" <<< "$out" && ! grep -q $'\033]52' <<< "$out" && [ ! -e "$T/state/lpadmin-args" ] && P "refused, escape not echoed" || F "escape passed: $(cat -v <<< "$out")"

hdr "a model that is only a prefix of a driver's (HL-12 vs HL-1200): no driver proposed"
out="$(drive "${BROTHER//DCP-L2550DW series/HL-12}" 'y\n\n')"
grep -q "no installed driver names it exactly" <<< "$out" && [ ! -e "$T/state/lpadmin-args" ] && P "HL-1200's driver not taken" || F "prefix match accepted: $out"

hdr "a make-and-model with no model name: refused"
out="$(drive "${BROTHER//Brother DCP-L2550DW series/Brother}" 'y\n\n')"
grep -q "has no model name" <<< "$out" && [ ! -e "$T/state/lpadmin-args" ] && P "refused" || F "vendor-only name accepted: $out"

hdr "a USB URI with shell characters: refused"
out="$(drive "${BROTHER/serial=U64123A8N123456/serial=\$(touch $T/pwned)}" 'y\n\n')"
grep -q "odd USB printer URI" <<< "$out" && [ ! -e "$T/state/lpadmin-args" ] && [ ! -e "$T/pwned" ] && P "refused, nothing run" || F "odd URI accepted: $out"

hdr "a USB printer no installed driver lists: says so, creates nothing"
out="$(drive "${BROTHER//DCP-L2550DW/HL-9999X}" 'y\n\n')"
grep -q "no installed driver names it exactly" <<< "$out" && [ ! -e "$T/state/lpadmin-args" ] && P "reported" || F "unsupported model not reported: $out"

hdr "one queue (with a status line): '-' skips printing"
out="$(drive "$BROTHER" 'y\n-\n')"
[ -e "$T/state/lpadmin-args" ] && grep -q "^PRINTER=$" <<< "$out" && P "queue created, then skipped" || F "'-' did not skip: $(tail -1 <<< "$out")"

hdr "a queue already exists: no setup offered, the existing queue is used"
rm -rf "$T/state"; mkdir -p "$T/state"; printf '%s\n' "$BROTHER" > "$T/state/devices"; echo mine > "$T/state/queue"; echo 'usb://X/Y' > "$T/state/uri"
out="$(printf 'mine\n' | PATH="$T/bin:$PATH" STATE="$T/state" bash -c 'source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; pick_printer; echo "PRINTER=$PRINTER"' 2>&1)"
[ ! -e "$T/state/mm-asked" ] && grep -q "^PRINTER=mine$" <<< "$out" && P "existing queue used" || F "setup ran over an existing queue: $out"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
