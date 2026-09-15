#!/usr/bin/env bash
# test-go-nogo-preflight-warn-surface.sh — when preflight PASSES WITH WARNINGS, the day-of
# go/no-go gate must surface those WARN/FAIL advisories in its consolidated GO summary.
# preflight.sh always colorizes its advisories (`  \033[33mWARN\033[0m ...`), so the ESC[33m
# sequence sits between the two-space prefix and the word WARN. A grep anchored on
# `  (WARN|FAIL)` (two literal spaces immediately followed by WARN) therefore matches NOTHING
# on real colored output, and the operator sees "GO preflight.sh passed" with every non-fatal
# advisory (low entropy, HISTFILE set, core-dump limit, no print queue) silently dropped —
# at the single gate they rely on. This test drives the REAL scripts/go-nogo.sh with a stub
# preflight that emits colored pass-with-warnings output and asserts the advisories surface.
# Hermetic + native: no emulator/daemons needed (preflight is stubbed, --need is empty so all
# hardware probes are advisory and the verdict stays GO).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GN_SRC="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/go-nogo.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

WORK="$(mktemp -d)"
cleanup(){ rm -rf "$WORK"; }
trap cleanup EXIT

# Copy the REAL go-nogo.sh next to a STUB preflight.sh so `"$HERE/preflight.sh"` resolves to
# our stub. The stub reproduces preflight's exact colored advisory format and exits 0
# (pass-with-warnings), which routes go-nogo through its line-56 surfacing branch.
cp "$GN_SRC" "$WORK/go-nogo.sh"
chmod +x "$WORK/go-nogo.sh"
cat > "$WORK/preflight.sh" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
echo "== Entropy =="
warn "low entropy (12) — wiggle the mouse / wait before generating keys."
echo "== Leak controls =="
warn "HISTFILE is set (/root/.bash_history) — unset it / use a no-history shell."
echo
printf '\033[32mPREFLIGHT OK\033[0m — review the SECRETS.md section, then run by hand.\n'
exit 0
STUB
chmod +x "$WORK/preflight.sh"

hdr "preflight passes-with-warnings -> go-nogo must surface the WARN advisories in its GO summary"
# --need empty => every hardware probe is advisory (warn only), so the verdict stays GO and we
# isolate exactly the preflight-surfacing behaviour under test.
out="$("$WORK/go-nogo.sh" 2>&1 || true)"

grep -qi "preflight.sh passed" <<< "$(echo "$out")" \
  && P "go-nogo reported preflight passed (reached the surfacing branch)" \
  || F "go-nogo did not report preflight passed"

if grep -qi "low entropy (12)" <<< "$out"; then
  P "the 'low entropy' WARN advisory is surfaced in the GO summary"
else
  F "the 'low entropy' WARN advisory was DROPPED — operator never sees it (ANSI-anchor bug)"
fi

if grep -qi "HISTFILE is set" <<< "$out"; then
  P "the 'HISTFILE is set' WARN advisory is surfaced in the GO summary"
else
  F "the 'HISTFILE is set' WARN advisory was DROPPED — operator never sees it (ANSI-anchor bug)"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
