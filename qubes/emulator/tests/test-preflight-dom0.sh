#!/usr/bin/env bash
# test-preflight-dom0.sh — CI gate for the dom0-ORCHESTRATION side of the ceremony (the one seam the rest of
# the emulator suite can't cover: what dom0 must assert about the air-gapped vault qube BEFORE the ceremony).
# No Qubes needed — a mock `qvm-prefs` + a mock /proc/swaps drive scripts/preflight-dom0.sh through its
# netvm=''/maxmem=0(no-ballooning)/DispVM asserts, proving dom0 REFUSES a misconfigured vault and PASSES a
# hardened one. Mirrors how the real ceremony runs `preflight-dom0.sh vault` in dom0.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$(cd "$HERE/../../scripts" && pwd)}"
PF="$SCRIPTS/preflight-dom0.sh"
[ -f "$PF" ] || { echo "missing $PF"; exit 2; }

STUB="$(mktemp -d)"; trap 'rm -rf "$STUB"' EXIT
# Mock qvm-prefs: `qvm-prefs vault` = existence check (exit 0); `qvm-prefs vault <pref>` = echo the pref.
# Each pref is overridable via a MOCK_* env var; defaults describe a correctly-hardened vault.
cat > "$STUB/qvm-prefs" <<'MOCK'
#!/usr/bin/env bash
VM="$1"; PREF="${2:-}"
[ "$VM" = "vault" ] || { echo "no such qube: $VM" >&2; exit 1; }
[ -z "$PREF" ] && exit 0
case "$PREF" in
  netvm)            printf '%s' "${MOCK_NETVM-}";;
  provides_network) echo "${MOCK_PROVIDES_NETWORK:-False}";;
  template)         echo "${MOCK_TEMPLATE:-vault-tools}";;
  maxmem)           echo "${MOCK_MAXMEM:-0}";;
  klass)            echo "${MOCK_KLASS:-DispVM}";;
  autostart)        echo "${MOCK_AUTOSTART:-False}";;
  *) : ;;
esac
MOCK
chmod +x "$STUB/qvm-prefs"
: > "$STUB/noswap"   # empty => dom0 has no active swap

fails=0
say(){ printf '\033[1m### %s\033[0m\n' "$1"; }
run(){ PATH="$STUB:$PATH" SWAPS_FILE="$STUB/noswap" bash "$PF" vault 2>&1; }
# assert: $1 desc, $2 expected exit (0=pass,1=fail), $3 substring the output MUST contain (or "")
expect(){
  local desc="$1" exp_rc="$2" must="$3"; local out rc
  out="$(run)"; rc=$?
  if [ "$rc" -ne "$exp_rc" ]; then printf '  \033[31mFAIL\033[0m %s (rc=%s, expected %s)\n' "$desc" "$rc" "$exp_rc"; fails=1; return; fi
  if [ -n "$must" ] && ! grep -qiF -- "$must" <<<"$out"; then printf '  \033[31mFAIL\033[0m %s (output missing %q)\n' "$desc" "$must"; fails=1; return; fi
  printf '  \033[32mPASS\033[0m %s\n' "$desc"
}

say "a correctly-hardened vault qube (netvm='', maxmem=0, DispVM, no dom0 swap) PASSES"
expect "hardened vault passes dom0 preflight (exit 0)" 0 "DOM0 PREFLIGHT OK"

say "a vault with a NETWORK path is REFUSED (air-gap violation)"
MOCK_NETVM="sys-firewall" expect "netvm set => FAIL, exit 1" 1 "must be empty"

say "a vault with memory BALLOONING enabled is REFUSED (dom0 could reclaim/inspect qube RAM)"
MOCK_MAXMEM="4000" expect "maxmem!=0 => FAIL, exit 1" 1 "ballooning"

say "dom0 with ACTIVE swap is REFUSED (qube RAM could be paged out by dom0)"
# two-line swaps file => >1 line => active swap detected
printf 'Filename\tType\tSize\n/swapfile\tfile\t2097148\n' > "$STUB/withswap"
out="$(PATH="$STUB:$PATH" SWAPS_FILE="$STUB/withswap" bash "$PF" vault 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && grep -qiF 'ACTIVE swap' <<<"$out"; then printf '  \033[32mPASS\033[0m active dom0 swap => FAIL, exit 1\n'; else printf '  \033[31mFAIL\033[0m active dom0 swap not caught (rc=%s)\n' "$rc"; fails=1; fi

say "an UNREADABLE swaps table FAILS CLOSED (cannot assert swap is off)"
out="$(PATH="$STUB:$PATH" SWAPS_FILE="$STUB/does-not-exist" bash "$PF" vault 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && grep -qiF 'cannot read' <<<"$out"; then printf '  \033[32mPASS\033[0m unreadable swaps table => FAIL, exit 1 (fail-closed)\n'; else printf '  \033[31mFAIL\033[0m unreadable swaps table not failed-closed (rc=%s)\n' "$rc"; fails=1; fi

echo
[ "$fails" -eq 0 ] && echo "PREFLIGHT-DOM0 MOCK: all dom0-orchestration asserts enforced" || { echo "PREFLIGHT-DOM0 MOCK: FAILURES"; exit 1; }
