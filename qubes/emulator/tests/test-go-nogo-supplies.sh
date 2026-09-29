#!/usr/bin/env bash
# test-go-nogo-supplies.sh — the supplies gate that replaced go-nogo's free-text checklist (owner,
# 2026-09-29: "too many interpretations possible"). Each item is one yes/no question with a number in
# it, derived from CEREMONY_SHARES; any "no" is a STOP; without a terminal it cannot be confirmed and
# is a STOP. Driven through a real pty (script), as in the vault's xterm.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GN="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/go-nogo.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
command -v script >/dev/null || { echo "  SKIP: util-linux 'script' not available"; exit 0; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# Only the supplies section is asserted: preflight's verdict on this host is irrelevant here.
# The typed answer is not echoed, so each verdict lands on its question's line: split them apart.
section(){ sed $'s/\033\\[[0-9;]*m//g' | tr -d '\r' | sed -n '/Supplies on the table/,/=  NO-GO  =\|=  GO  =/p' \
  | sed 's/\[y\/N\] *\(GO\|STOP\)/[y\/N]\n  \1/'; }
drive(){ printf "$2" | CEREMONY_SHARES="$1" timeout 120 script -qec "bash '$GN' --need supplies" /dev/null 2>&1 | section; }

hdr "all five confirmed (6 shares): five GO lines with the counts in them"
out="$(drive 6 'y\ny\ny\ny\ny\n')"
[ "$(grep -c '^  GO ' <<< "$out")" = 5 ] && P "five items confirmed" || F "confirmed: $(grep -c '^  GO ' <<< "$out"): $out"
grep -q "At least 8 BLANK archive discs" <<< "$out" && grep -q "6 holographic seal stickers" <<< "$out" && P "counts follow 6 shares (8 discs, 6 seals)" || F "counts wrong: $out"
grep -q "NOT CONFIRMED" <<< "$out" && F "an item was not confirmed" || P "nothing unconfirmed"

hdr "3-of-5: the counts follow CEREMONY_SHARES"
out="$(drive 5 'y\ny\ny\ny\ny\n')"
grep -q "At least 7 BLANK archive discs" <<< "$out" && grep -q "5 holographic seal stickers" <<< "$out" && P "7 discs, 5 seals" || F "counts do not follow 5 shares: $out"

hdr "one 'no' (the seals): that item is a STOP, the others still asked"
out="$(drive 6 'y\nn\ny\ny\ny\n')"
grep -q "STOP NOT CONFIRMED: 6 holographic seal stickers" <<< "$out" && [ "$(grep -c '^  GO ' <<< "$out")" = 4 ] && P "seals STOP, four GO" || F "a 'no' was not a STOP: $out"

hdr "Enter alone is 'no' (the default must not confirm anything)"
out="$(drive 6 '\n\n\n\n\n')"
[ "$(grep -c 'NOT CONFIRMED' <<< "$out")" = 5 ] && P "all five STOP" || F "Enter confirmed something: $out"

hdr "no terminal: STOP, never a silent pass"
out="$(CEREMONY_SHARES=6 setsid bash "$GN" --need supplies </dev/null 2>&1 | sed $'s/\033\\[[0-9;]*m//g')"
grep -q "supplies must be confirmed at a terminal" <<< "$out" && P "refused without a terminal" || F "no-terminal run: $(grep -i supplies <<< "$out")"

hdr "a non-numeric share count is refused"
out="$(drive six 'y\ny\ny\ny\ny\n'; CEREMONY_SHARES=six setsid bash "$GN" --need supplies </dev/null 2>&1 | sed $'s/\033\\[[0-9;]*m//g')"
grep -q "CEREMONY_SHARES='six' is not a number" <<< "$out" && P "refused" || F "bad count accepted"

hdr "the old free-text sheet is gone"
grep -q "Operator decisions to CONFIRM" "$GN" && F "the old sheet is still there" || P "removed"
grep -qi "touch policy = ALWAYS" "$GN" && F "touch=ALWAYS still printed" || P "no touch=ALWAYS"

hdr "YubiKey touch policy: anything but never is refused before the card is touched"
for tp in always cached; do
  o="$( ( source "$(dirname "$GN")/ceremony.sh" >/dev/null 2>&1; CEREMONY_YUBI_TOUCH_POLICY=$tp step_yubikey_ops </dev/null; echo "RC=$?" ) 2>&1 | sed $'s/\033\\[[0-9;]*m//g')"
  grep -q "RC=1" <<< "$o" && grep -q "must be never" <<< "$o" && P "touch=$tp refused" || F "touch=$tp accepted: $(tail -3 <<< "$o")"
done

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
