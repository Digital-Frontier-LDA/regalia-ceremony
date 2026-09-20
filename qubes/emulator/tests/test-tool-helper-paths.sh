#!/usr/bin/env bash
# test-tool-helper-paths.sh — every helper the bench tools reach for must exist IN THIS CHECKOUT.
#
# THE DEFECT THIS PINS. These tools were written in the monorepo, where the ceremony lived under
# ceremony/qubes/scripts/. Published here it is qubes/scripts/, and the defaults kept the old
# prefix: hsm-cycle-test.sh --full, hsm-staging-restore.sh, hsm-staging-pin.sh, most of
# hsm-scenarios.sh, repro-397-import-loop.sh and commission-card.sh all named files that do not
# exist in this repository. Nothing failed at review time — each would have failed on a bench,
# mid-run, after touching a card, with a "no such file" for a script the operator can see in the
# repo they are standing in.
#
# So the property is not "the paths look right" but "resolve every helper name the tools ask for,
# and open it". A published repository whose tools reach outside it is not a functional repository.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

hdr "every hsm_ceremony_script name resolves to a readable file"
# shellcheck source=/dev/null
. "$REPO/tools/hsm-ceremony-scripts.sh"
names="$(grep -rhoE 'hsm_ceremony_script [a-zA-Z0-9._-]+' "$REPO/tools" | awk '{print $2}' | sort -u)"
if [ -z "$names" ]; then
  F "no hsm_ceremony_script calls found — this scan cannot be passing for the right reason"
else
  for n in $names; do
    p="$(hsm_ceremony_script "$n")"
    if [ -r "$p" ]; then P "$n -> ${p#"$REPO"/}"; else F "$n resolves to $p, which does not exist"; fi
  done
fi

hdr "no tool hardcodes the retired monorepo layout"
# Only the resolver itself may name ceremony/qubes/scripts, as a fallback for a monorepo checkout.
offenders="$(grep -rlE '\$\{?REPO(_ROOT)?\}?/ceremony/qubes/scripts' "$REPO/tools" 2>/dev/null \
             | grep -v 'hsm-ceremony-scripts.sh' || true)"
if [ -z "$offenders" ]; then
  P "no tool reaches for ceremony/qubes/scripts directly"
else
  F "these still name the monorepo path directly:"
  printf '%s\n' "$offenders" | sed 's|^|      |'
fi

hdr "scripts referenced by the host role exist too"
# commission-card.sh resolves its helpers across both layouts; the names must still be present.
for n in hsm-devaut-id.js hsm-devaut-read.sh derive-akash-address.py; do
  if [ -r "$REPO/qubes/scripts/$n" ]; then P "qubes/scripts/$n"; else F "qubes/scripts/$n is missing"; fi
done

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
