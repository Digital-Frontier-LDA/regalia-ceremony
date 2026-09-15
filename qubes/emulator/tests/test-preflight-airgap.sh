#!/usr/bin/env bash
# test-preflight-airgap.sh — the air-gap check is the single most important control of the
# whole ceremony. It must FAIL CLOSED: if the route tool (`ip`/iproute2) is missing or not on
# PATH, preflight.sh must NOT silently conclude "no default route (air-gapped)". A swallowed
# missing-binary error becoming a false-safe verdict would let a networked qube pass, and
# go-nogo.sh would inherit a false GO. Runs natively, no daemons needed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PRE="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/preflight.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# Build a sandbox PATH that contains the coreutils preflight needs but deliberately NOT `ip`,
# so `ip` is genuinely absent (we can't remove an entry from a real PATH, so we curate one).
SBOX="$(mktemp -d)"
trap 'rm -rf "$SBOX"' EXIT
for u in bash sh env grep cat ls wc tr sed timeout printf head; do
  p="$(command -v "$u" 2>/dev/null)" && ln -sf "$p" "$SBOX/$u"
done
# sanity: `ip` must not be resolvable under the sandbox PATH
if PATH="$SBOX" command -v ip >/dev/null 2>&1; then
  F "sandbox PATH still resolves 'ip' — test harness is broken"; printf '  %d passed, %d failed\n' "$pass" "$fail"; exit 1
fi

hdr "ip/iproute2 MISSING -> air-gap must FAIL CLOSED (no false 'air-gapped' verdict)"
out="$(PATH="$SBOX" CEREMONY_SIMULATE=1 bash "$PRE" 2>&1)"; rc=$?
echo "$out" | grep -iE 'air-gap|ip ' | sed 's/^/     /'
if grep -qi "no default route (air-gapped)" <<< "$out"; then
  F "preflight reported 'no default route (air-gapped)' while 'ip' was absent — FALSE SAFE"
else
  P "preflight did NOT claim air-gapped when the route tool was missing"
fi
if grep -qiE 'FAIL.*(air-?gap|iproute2|.ip.)' <<< "$out"; then
  P "preflight emits a FAIL when it cannot verify the air-gap"
else
  F "preflight did not FAIL on a missing route tool (cannot verify air-gap)"
fi
[ "$rc" -ne 0 ] && P "preflight exits non-zero with the route tool missing" || F "preflight exited 0 despite being unable to verify air-gap"

hdr "control: with 'ip' present and no default route -> reports air-gapped OK (no over-reject)"
printf '#!/usr/bin/env bash\nexit 0\n' > "$SBOX/ip"; chmod +x "$SBOX/ip"
out2="$(PATH="$SBOX" CEREMONY_SIMULATE=1 bash "$PRE" 2>&1)"
if grep -qi "no default route (air-gapped)" <<< "$out2"; then
  P "still reports air-gapped OK when 'ip' exists and shows no default route"
else
  F "regression: air-gap OK path no longer reached when 'ip' is present"
fi
rm -f "$SBOX/ip"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
