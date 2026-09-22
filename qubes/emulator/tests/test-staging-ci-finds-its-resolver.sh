#!/usr/bin/env bash
# test-staging-ci-finds-its-resolver.sh — the DEFAULT path to hsm-reader-select.sh must work.
#
# WHY THIS EXISTS SEPARATELY. test-hsm-staging-ci.sh always passes HSM_READER_SELECT, because it
# drives the battery through a symlink where $0-relative paths cannot resolve. So every test
# exercised the INJECTED path and none exercised the default — and the default was wrong:
# $HERE is qubes/scripts, two levels up is the repository root, and both fallbacks used three,
# which is its parent. A gate run on 2026-09-22 reported
#
#     hw_bench_pins  SKIP  the reader resolver is unavailable, so no bench-wide census was taken
#
# and the targeting silently fell back to single-card defaults on a bench with two cards attached.
#
# A seam that makes code testable can also make its production path untested, which is worse than
# having neither. This row is the production path.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
REPO="$(cd "$SCRIPTS/../.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

hdr "the default path resolves, from the script's own location"
# Exactly the expression the battery uses, evaluated with $HERE as the battery computes it.
CI="$SCRIPTS/hsm-staging-ci.sh"
[ -r "$CI" ] || { echo "no hsm-staging-ci.sh at $CI" >&2; exit 1; }
expr_line="$(grep -m1 '_rs="\${HSM_READER_SELECT:-' "$CI")"
[ -n "$expr_line" ] || F "could not find the resolver default in hsm-staging-ci.sh"
resolved="$(HERE="$SCRIPTS" bash -c "unset HSM_READER_SELECT; $expr_line"'; printf "%s" "$_rs"')"
if [ -f "$resolved" ]; then
  P "the default points at a file that exists: $resolved"
else
  F "the default points at nothing: $resolved"
fi
[ "$(cd "$(dirname "$resolved")" && pwd)" = "$REPO/tools" ] \
  && P "…and it is the repository's own tools/hsm-reader-select.sh" \
  || F "it resolves outside the repository: $(cd "$(dirname "$resolved")" 2>/dev/null && pwd)"

hdr "the fallback expression resolves there too"
fb_line="$(grep -m1 '\[ -f "\$_rs" \] || _rs=' "$CI")"
[ -n "$fb_line" ] || F "no fallback expression found"
fb="$(HERE="$SCRIPTS" bash -c "unset HSM_READER_SELECT; _rs=/nonexistent; $fb_line"'; printf "%s" "$_rs"')"
[ -f "$fb" ] && P "the fallback also lands on a real file: $fb" || F "the fallback lands on nothing: $fb"

hdr "sourcing the default actually defines the functions the battery calls"
# The point is not the path but what it provides: the census step checks for hsm_reader_indices.
for fn in hsm_reader_indices hsm_reader_for; do
  if bash -c '. "$1" >/dev/null 2>&1; command -v "$2" >/dev/null 2>&1' _ "$resolved" "$fn"; then
    P "$fn is defined after sourcing it"
  else
    F "$fn is NOT defined; the battery would take its 'resolver unavailable' skip"
  fi
done

hdr "…so the census step would not take its bail-out"
# hw_bench_pins skips when command -v hsm_reader_indices fails. That skip is correct behaviour
# for a host without the resolver and WRONG as the permanent state of the repository.
if bash -c '. "$1" >/dev/null 2>&1; command -v hsm_reader_indices >/dev/null 2>&1' _ "$resolved"; then
  P "with the default path, the bench-wide PIN census can run"
else
  F "the census would always skip, and 'no card was found to be low' would be indistinguishable from 'no card was looked at'"
fi

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
