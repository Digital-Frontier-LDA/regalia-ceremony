#!/usr/bin/env bash
# preflight-dom0.sh — run in Qubes **dom0** before a real ceremony.
# preflight.sh checks the vault qube from the INSIDE; this asserts the qube's Qubes-level
# state from dom0, which the qube cannot see (netvm, template, memory ballooning, etc.).
#
#   bash preflight-dom0.sh <vault-qube-name>     # e.g. bash preflight-dom0.sh vault
#
# Read-only: it inspects qvm-prefs and prints PASS/FAIL. Touches no secrets.

set -uo pipefail
VM="${1:-}"; [ -n "$VM" ] || { echo "usage: preflight-dom0.sh <vault-qube-name>"; exit 2; }
fail=0
ok(){ printf '  \033[32mOK\033[0m   %s\n' "$1"; }
warn(){ printf '  \033[33mWARN\033[0m %s\n' "$1"; }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
pref(){ qvm-prefs "$VM" "$1" 2>/dev/null; }

command -v qvm-prefs >/dev/null || { echo "not in dom0 (qvm-prefs not found)"; exit 2; }
qvm-prefs "$VM" >/dev/null 2>&1 || { echo "no such qube: $VM"; exit 2; }

echo "== Qubes state for '$VM' =="
nv="$(pref netvm)"
[ -z "$nv" ] && ok "netvm is empty (air-gapped)." || bad "netvm='$nv' — must be empty for a real ceremony."

prov="$(pref provides_network)"
[ "$prov" = "False" ] && ok "provides_network=False." || warn "provides_network=$prov."

tmpl="$(pref template 2>/dev/null || true)"
[ -n "$tmpl" ] && ok "template=$tmpl (expected: vault-tools)." || warn "no template (StandaloneVM?) — confirm it is the vault image."

# Fixed RAM: dynamic memory ballooning lets dom0 reclaim/inspect qube pages. Pin it.
maxmem="$(pref maxmem)"
[ "$maxmem" = "0" ] && ok "maxmem=0 (memory ballooning DISABLED — fixed RAM)." \
                    || bad "maxmem=$maxmem — set 'qvm-prefs $VM maxmem 0' to disable ballooning."

# DispVM is preferred (no persistent /home). Warn if it's a plain AppVM.
cls="$(pref klass 2>/dev/null || true)"
case "$cls" in
  DispVM) ok "class=DispVM (no persistent private storage).";;
  *) warn "class=${cls:-AppVM} — prefer a DisposableVM so nothing persists; if AppVM, document why.";;
esac

# No autostart, and confirm it's currently the only thing you'll run.
[ "$(pref autostart)" = "False" ] && ok "autostart=False." || warn "autostart=True — disable it."

echo "== dom0 host =="
# Reads /proc/swaps by default; SWAPS_FILE overrides it so this is testable off-dom0 (CI mock).
SWAPS_FILE="${SWAPS_FILE:-/proc/swaps}"
# Fail CLOSED: if we cannot read the swaps table we cannot assert swap is off, and a live dom0
# swap could page a qube's RAM to disk — so an unreadable/missing table is a FAIL, not a pass.
if [ ! -r "$SWAPS_FILE" ]; then
  bad "cannot read $SWAPS_FILE — cannot verify dom0 swap is OFF (a live swap could page out qube RAM)."
elif [ "$(grep -c . "$SWAPS_FILE")" -gt 1 ]; then
  bad "dom0 has ACTIVE swap — the qube's RAM could be paged out by dom0. Disable/encrypt dom0 swap."
else ok "dom0 has no active swap."; fi

echo
if [ "$fail" -eq 0 ]; then echo "DOM0 PREFLIGHT OK — also run /opt/vault-ceremony/preflight.sh inside $VM."; else
  echo "DOM0 PREFLIGHT FAILED — fix the FAIL items before a real ceremony."; fi
exit "$fail"
