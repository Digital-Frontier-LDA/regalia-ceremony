#!/usr/bin/env bash
# test-ceremony-pick-printer-uri.sh — ceremony.sh's own pick_printer() USB-only gate must
# FAIL CLOSED for ANY non-local device-uri. This is the SOLE destination check when
# preflight.sh is absent or the queue is added after preflight, so a broken gate here means
# a plaintext Shamir paper share + QR go over the wire (smb/ipp/lpd/ipps/http) off the
# air-gapped vault qube. go-nogo.sh and preflight.sh have their own (correct, anchored)
# guard exercised by test-printer-network-uri.sh; this harness exercises pick_printer()
# DIRECTLY by sourcing ceremony.sh and feeding it a chosen queue whose device-uri we fake.
#
# Runs natively, no daemons: we fake `lpstat` (a queue with a chosen device-uri) and drive
# pick_printer() with the queue name on stdin, then assert whether it accepted (PRINTER set)
# or refused (PRINTER cleared) the queue. Regression guard for the greedy-sed scheme-strip
# bug where `sed -E 's/.*: *//'` turned smb://host/path into //host/path and the `/*` case
# arm treated it as a safe local absolute-path device.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
CEREMONY="$SCRIPTS/ceremony.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

FAKE="$(mktemp -d)"
trap 'rm -rf "$FAKE"' EXIT
# fake CUPS: one queue named "nas" whose device-uri comes from $EMU_PRINTER_URI
cat > "$FAKE/lpstat" <<'LPSTAT'
#!/usr/bin/env bash
uri="${EMU_PRINTER_URI:-usb://Brother/HL}"
case "${1:-}" in
  -p) printf 'printer nas is idle.  enabled since today\n';;
  -v) printf 'device for nas: %s\n' "$uri";;
  *)  exit 0;;
esac
exit 0
LPSTAT
chmod +x "$FAKE/lpstat"

# Drive pick_printer() in an isolated subshell and echo back the resulting PRINTER value.
# We answer the "queue name" prompt with "nas" on stdin. CEREMONY_SIMULATE=1 lets the
# fake lpstat live on PATH without tripping the stub-shadow guard (pick_printer doesn't
# use it, but sourcing keeps things quiet).
run_pick() {
  local uri="$1"
  (
    export EMU_PRINTER_URI="$uri"
    export PATH="$FAKE:$PATH"
    export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
    # shellcheck disable=SC1090
    source "$CEREMONY" >/dev/null 2>&1
    pick_printer <<< "nas" >/dev/null 2>&1
    printf '%s' "${PRINTER:-}"
  )
}

# Assert pick_printer REFUSES the queue (network/off-air-gap destination) -> PRINTER cleared.
expect_refuse() {
  local uri="$1" label="$2" got
  got="$(run_pick "$uri")"
  if [ -z "$got" ]; then
    P "pick_printer refuses $label ($uri) — PRINTER cleared, no print over the wire"
  else
    F "pick_printer ACCEPTED $label ($uri) as PRINTER='$got' — plaintext share would print over the wire"
  fi
}

# Assert pick_printer ACCEPTS the queue (usb/local) -> PRINTER set to the queue name.
expect_accept() {
  local uri="$1" label="$2" got
  got="$(run_pick "$uri")"
  if [ "$got" = "nas" ]; then
    P "pick_printer accepts $label ($uri) as USB/local"
  else
    F "pick_printer wrongly rejected local $label ($uri) — PRINTER='$got'"
  fi
}

hdr "network device-uris must be REFUSED by pick_printer (fail closed)"
expect_refuse "smb://nas/printer"          "an SMB share"
expect_refuse "ipp://10.0.0.5/printers/x"  "an IPP network printer"
expect_refuse "ipps://10.0.0.5/printers/x" "an IPPS network printer"
expect_refuse "lpd://10.0.0.5/queue"       "an LPD network printer"
expect_refuse "http://10.0.0.5/printer"    "an HTTP network printer"
expect_refuse "bluetooth://AA-BB-CC/dev"   "a Bluetooth printer"
expect_refuse "socket://10.0.0.5:9100"     "a raw socket printer"

hdr "control: usb/local device-uris are still ACCEPTED (no over-reject)"
expect_accept "usb://Brother/HL-L2350DW" "a USB Brother laser"
expect_accept "/dev/usb/lp0"             "an absolute-path local device"
expect_accept "file:/tmp/out.prn"        "a local file backend"
expect_accept "cups-pdf:/"               "the cups-pdf backend"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
