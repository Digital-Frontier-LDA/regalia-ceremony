#!/usr/bin/env bash
# test-preflight-live-iface.sh — a live, non-loopback interface carrying a routable
# (global-scope) address is a network path regardless of whether a default route exists.
# For a set-once, real-money ceremony the vault qube must FAIL preflight in that state, not
# merely WARN. Regression guard for the quorum-confirmed downgrade at preflight.sh line 32:
# a global-scope IPv4 with no default gateway was reported as WARN, so preflight exited 0 and
# go-nogo inherited a false GO while secrets could be exfiltrated to any directly-connected
# peer. Runs natively, no daemons needed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PRE="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/preflight.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# Curated sandbox PATH (same technique as test-preflight-airgap.sh): give preflight the
# coreutils it needs plus a scripted `ip`, so we control exactly what the route/addr tools say.
SBOX="$(mktemp -d)"
trap 'rm -rf "$SBOX"' EXIT
for u in bash sh env grep cat ls wc tr sed timeout printf head; do
  p="$(command -v "$u" 2>/dev/null)" && ln -sf "$p" "$SBOX/$u"
done

# Fake `ip`: NO default route (the qube's NetVM pushes no gateway) but a live LAN interface
# with a global-scope IPv4 (e.g. 192.0.2.x). This is the exact exfiltration-capable state the
# quorum flagged: reachable subnet peers, no default route.
cat > "$SBOX/ip" <<'FAKEIP'
#!/usr/bin/env bash
case "$*" in
  *"route show default"*)  exit 0 ;;                                  # empty => no default route
  *"addr show scope global"*) printf '    inet 192.0.2.5/24 scope global eth0\n'; exit 0 ;;
  *) exit 0 ;;
esac
FAKEIP
chmod +x "$SBOX/ip"

# Isolate the "== Air-gap ==" section: the missing template tools (age/sops/...) also FAIL in
# this curated sandbox, which would confound a whole-run exit-code assertion. Scope the checks
# to the air-gap section so we test the warn->bad downgrade itself, not unrelated tool FAILs.
airgap_section(){ printf '%s\n' "$1" | sed -n '/== Air-gap ==/,/== Leak controls ==/p'; }

hdr "live global-scope interface, no default route -> air-gap must FAIL (not WARN)"
out="$(PATH="$SBOX" CEREMONY_SIMULATE=1 bash "$PRE" 2>&1)"
sec="$(airgap_section "$out")"
echo "$sec" | sed 's/^/     /'

if grep -qiE 'FAIL.*global-scope' <<< "$sec"; then
  P "air-gap section emits a FAIL for the live global-scope interface"
else
  F "air-gap section did NOT FAIL on a live global-scope interface (exfiltration path unguarded)"
fi

if grep -qiE 'WARN.*global-scope' <<< "$sec"; then
  F "air-gap section still only WARNs on the live interface (defect unfixed)"
else
  P "air-gap section no longer downgrades the live interface to a WARN"
fi

hdr "control: truly air-gapped (no default route, only loopback) still passes air-gap section"
cat > "$SBOX/ip" <<'FAKEIP2'
#!/usr/bin/env bash
case "$*" in
  *"route show default"*)  exit 0 ;;   # no default route
  *"addr show scope global"*) exit 0 ;; # no global-scope address (loopback is scope host)
  *) exit 0 ;;
esac
FAKEIP2
chmod +x "$SBOX/ip"
out2="$(PATH="$SBOX" CEREMONY_SIMULATE=1 bash "$PRE" 2>&1)"
if grep -qi "no default route (air-gapped)" <<< "$out2" && ! grep -qiE 'FAIL.*global-scope' <<< "$out2"; then
  P "air-gap section stays OK when only loopback is present (no over-reject)"
else
  F "regression: air-gap section wrongly FAILs a genuinely air-gapped qube"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
