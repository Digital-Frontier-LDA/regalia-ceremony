#!/usr/bin/env bash
# test-escrow-tools.sh — the PIN escrow tools the archive disc carries (scripts/escrow/):
#   - pin_escrow_mac.py: the key on stdin only; KCV and MAC deterministic; select takes the highest
#     escrow whose MAC verifies across git history, so a deleted or MAC-replaced file cannot roll
#     recovery back, and it copies out exactly the verified bytes; the next sequence counts every
#     escrow ever committed;
#   - pin-escrow.sh refuses to run from inside the checkout it writes to (the disc's copy is the
#     producer);
#   - step_archive refuses to stage a disc without both tools.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
MAC="$SCRIPTS/escrow/pin_escrow_mac.py"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
KEY="$(printf '5a%.0s' {1..16})"   # a stand-in 32-hex key, built at runtime
g(){ git -C "$T/repo" -c user.name=t -c user.email=t@t "$@" >/dev/null 2>&1; }
put(){ printf '%s' "$2" > "$T/repo/escrow/$1"; python3 "$MAC" mac "$T/repo/escrow/$1" <<< "${3:-$KEY}" > "$T/repo/escrow/$1.mac"; }

hdr "the tools are present and executable"
for t in pin-escrow.sh pin_escrow_mac.py; do [ -x "$SCRIPTS/escrow/$t" ] && P "escrow/$t" || F "escrow/$t missing or not executable"; done

hdr "KCV and MAC"
k1="$(python3 "$MAC" kcv <<< "$KEY")"; k2="$(python3 "$MAC" kcv <<< "${KEY^^}")"
[[ "$k1" =~ ^[0-9a-f]{16}$ ]] && [ "$k1" = "$k2" ] && P "the KCV is 16 hex and ignores letter case" || F "KCV $k1 / $k2"
python3 "$MAC" kcv <<< "nothex" >/dev/null 2>&1 && F "a malformed key was accepted" || P "a malformed key is refused"

hdr "selection over git history"
mkdir -p "$T/repo/escrow"; g init -q
put pins-0001.age stale; g add -A; g commit -qm one
put pins-0002.age current; g add -A; g commit -qm two
sel(){ rm -f "$T/out"; python3 "$MAC" select "$T/repo" "$T/out" <<< "$KEY" 2>"$T/err"; }
[ "$(sel)" = pins-0002.age ] && [ "$(cat "$T/out")" = current ] && P "the highest verified escrow, exact bytes" || F "selected $(cat "$T/out" 2>/dev/null)"
[ "$(stat -c %a "$T/out")" = 600 ] && P "the copy is 0600" || F "copy mode $(stat -c %a "$T/out")"
g rm -q escrow/pins-0002.age escrow/pins-0002.age.mac; g commit -qm delete
[ "$(sel)" = pins-0002.age ] && [ "$(cat "$T/out")" = current ] && grep -q "NOTE pins-0002.age" "$T/err" \
  && P "deleting the newest pair does not roll recovery back (reported)" || F "after deletion: $(cat "$T/out" 2>/dev/null)"
put pins-0003.age forged "$(printf '00%.0s' {1..16})"; g add -A; g commit -qm forged
[ "$(sel)" = pins-0002.age ] && grep -q "SKIPPED pins-0003.age" "$T/err" && P "a forged escrow is skipped and reported" || F "forged escrow selected"
[ "$(python3 "$MAC" highest "$T/repo")" = 3 ] && P "the next sequence counts deleted escrows too (highest = 3, not 1)" || F "highest $(python3 "$MAC" highest "$T/repo")"
put pins-0004.age genuine; g add -A; g commit -qm four
printf 'f%.0s' {1..64} > "$T/repo/escrow/pins-0004.age.mac"; g add -A; g commit -qm "replace only the mac"
[ "$(sel)" = pins-0004.age ] && [ "$(cat "$T/out")" = genuine ] && P "replacing only the .mac does not hide the earlier valid pair" || F "after a MAC-only replacement: $(cat "$T/out" 2>/dev/null)"

hdr "the producer refuses to run from the checkout it writes to"
mkdir -p "$T/repo/tools"; cp "$SCRIPTS/escrow/pin-escrow.sh" "$SCRIPTS/escrow/pin_escrow_mac.py" "$T/repo/tools/"
: > "$T/repo/escrow/breakglass.recipient"; printf 'x' > "$T/repo/escrow/breakglass.recipient"; printf '%s\n' "$k1" > "$T/repo/escrow/escrow-mac.kcv"
out="$(cd "$T/repo" && bash tools/pin-escrow.sh < /dev/null 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "archive disc" <<< "$out" && P "the repository copy refuses and names the disc's copy" || F "rc=$rc: $out"

hdr "the archive step refuses a disc without the escrow tools"
mkdir -p "$T/scripts"; cp "$SCRIPTS"/ceremony.sh "$T/scripts/"
out="$(
  # shellcheck disable=SC1091
  source "$T/scripts/ceremony.sh" >/dev/null 2>&1
  ask(){ return 0; }; pause(){ :; }
  # shellcheck disable=SC2034  # read by the sourced ceremony.sh
  PRINTER=""
  HERE="$T/scripts"; init_work >/dev/null 2>&1
  step_archive 2>&1; echo "RC=$?"
)"
grep -q "RC=1" <<< "$out" && grep -q "PIN escrow tools" <<< "$out" && P "no escrow tools, no disc" || F "$(tail -5 <<< "$out")"

echo; echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
