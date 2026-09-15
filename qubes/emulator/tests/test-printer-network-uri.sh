#!/usr/bin/env bash
# test-printer-network-uri.sh — the "USB-only printer" GO gate must FAIL CLOSED for ANY
# non-local device-uri, not just the handful in a blocklist. A leftover CUPS queue on
# smb:// or bluetooth:// would send a plaintext Shamir paper share over the wire off the
# air-gapped vault qube. go-nogo.sh and preflight.sh must agree with ceremony.sh's actual
# print path, which ALLOWLISTS only usb:// (plus local file:/cups-pdf:/absolute-path).
# Runs natively, no daemons: we fake `lpstat` (a queue with a chosen device-uri) and `ip`
# (air-gap probe), and assert the gate's verdict. This is the regression guard for the
# blocklist->allowlist fix.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
GN="$SCRIPTS/go-nogo.sh"
PRE="$SCRIPTS/preflight.sh"
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

FAKE="$(mktemp -d)"
trap 'rm -rf "$FAKE"' EXIT
# air-gap probe: pretend no default route (air-gapped) so preflight's network check passes
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE/ip"; chmod +x "$FAKE/ip"
# fake CUPS: one queue (name from $EMU_PRINTER_NAME, default "nas") whose device-uri
# comes from $EMU_PRINTER_URI. CUPS queue names may legally contain a colon, so the
# name is parameterized to prove a colon-in-name cannot bypass the URI allowlist.
cat > "$FAKE/lpstat" <<'LPSTAT'
#!/usr/bin/env bash
uri="${EMU_PRINTER_URI:-usb://Brother/HL}"
name="${EMU_PRINTER_NAME:-nas}"
case "${1:-}" in
  -p) printf 'printer %s is idle.  enabled since today\n' "$name";;
  -v) printf 'device for %s: %s\n' "$name" "$uri";;
  *)  exit 0;;
esac
exit 0
LPSTAT
chmod +x "$FAKE/lpstat"
export PATH="$FAKE:$PATH"

# Assert that a given device-uri is treated as a NETWORK printer (NO-GO) by both gates.
expect_network() {
  local uri="$1" label="$2"
  local out
  out="$(EMU_PRINTER_URI="$uri" "$GN" --need printer 2>&1 || true)"
  if grep -qi "a NETWORK printer queue exists" <<< "$(echo "$out")" \
     && ! grep -qi "a USB/local print queue is present" <<< "$out"; then
    P "go-nogo flags $label ($uri) as a NETWORK printer"
  else
    F "go-nogo treated $label ($uri) as USB/local — plaintext share would go over the wire"
    echo "$out" | grep -iE 'printer|usb|network' | sed 's/^/        /'
  fi
  out="$(EMU_PRINTER_URI="$uri" bash "$PRE" 2>&1 || true)"
  if grep -qi "a NETWORK printer queue exists" <<< "$(echo "$out")" \
     && ! grep -qi "no network printer queues" <<< "$out"; then
    P "preflight flags $label ($uri) as a NETWORK printer"
  else
    F "preflight treated $label ($uri) as usb/local — plaintext share would go over the wire"
    echo "$out" | grep -iE 'printer|usb|network' | sed 's/^/        /'
  fi
}

# Assert that a given device-uri is accepted as USB/local (no over-reject).
expect_local() {
  local uri="$1" label="$2"
  local out
  out="$(EMU_PRINTER_URI="$uri" "$GN" --need printer 2>&1 || true)"
  if grep -qi "a USB/local print queue is present" <<< "$(echo "$out")" \
     && ! grep -qi "a NETWORK printer queue exists" <<< "$out"; then
    P "go-nogo accepts $label ($uri) as USB/local"
  else
    F "go-nogo wrongly rejected local $label ($uri)"
    echo "$out" | grep -iE 'printer|usb|network' | sed 's/^/        /'
  fi
}

hdr "smb:// and bluetooth:// queues must be caught as NETWORK printers"
expect_network "smb://nas/printer"        "an SMB share"
expect_network "bluetooth://AA-BB-CC/dev" "a Bluetooth printer"

hdr "the already-blocked backends stay blocked (no regression)"
expect_network "ipp://10.0.0.5/printers/x" "an IPP network printer"
expect_network "socket://10.0.0.5:9100"    "a raw socket printer"

hdr "control: a real usb:// queue is still accepted (no over-reject)"
expect_local "usb://Brother/HL-L2350DW" "a USB Brother laser"

hdr "a colon in the queue name must NOT bypass the URI allowlist"
# CUPS queue names may contain a colon (e.g. "office:2"). A name matcher anchored on a
# colon-free queue name discards this line entirely, so a genuinely networked printer
# slips past the gate and the ceremony prints a plaintext share over the wire.
export EMU_PRINTER_NAME="office:2"
expect_network "ipp://10.0.0.5/printers/x" "an IPP printer on a colon-named queue"
expect_network "smb://nas/printer"          "an SMB share on a colon-named queue"
expect_local   "usb://Brother/HL-L2350DW"   "a USB queue with a colon in the name"
unset EMU_PRINTER_NAME

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
