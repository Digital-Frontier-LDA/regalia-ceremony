#!/usr/bin/env bash
# test-go-nogo-one-script.sh — preflight.sh and go-nogo.sh were one check in two scripts, with two
# output styles, and the self-tests had to be typed one by one (owner, 2026-09-30: "could be merged
# into a single script ... that could call all selftests"; "I preferred the output of preflight").
# Asserts: preflight.sh is gone and nothing calls it; --env-only is the environment gate ceremony.sh
# runs; a full run runs every self-test; a broken tool is a FAIL and a NO-GO; every item line reads
# OK, WARN or FAIL, and the last line is GO or NO-GO.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
REPO="$(cd "$SCRIPTS/../.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
plain(){ sed $'s/\033\\[[0-9;]*m//g'; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# Fake only the air-gap probe, as the other harnesses do; SIMULATE downgrades the host's swap etc.
mkdir -p "$T/bin"; printf '#!/usr/bin/env bash\nexit 0\n' > "$T/bin/ip"; chmod +x "$T/bin/ip"
run(){ PATH="$T/bin:$PATH" CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 HISTFILE=/root/.bash_history \
         timeout 300 bash "$@" 2>&1 | plain; }

hdr "one script: preflight.sh is gone and nothing calls it"
[ ! -e "$SCRIPTS/preflight.sh" ] && P "no preflight.sh next to go-nogo.sh" || F "preflight.sh still exists"
callers="$(grep -rnE --exclude=test-go-nogo-one-script.sh '(\$HERE|\$SCRIPTS|/opt/vault-ceremony)/preflight\.sh' "$REPO/qubes" "$REPO/tools" "$REPO/debian" 2>/dev/null || true)"
[ -z "$callers" ] && P "no script runs preflight.sh" || F "still called: $callers"
grep -q '"$HERE/go-nogo.sh" --env-only' "$SCRIPTS/ceremony.sh" \
  && P "ceremony.sh gates on go-nogo.sh --env-only before any secret" || F "ceremony.sh does not run the environment gate"

grep -q 'timeout 60 python3 "$HERE/hsm-random.py"' "$SCRIPTS/go-nogo.sh" \
  && P "the HSM RNG read is bounded (60 s, as in ceremony.sh)" || F "the HSM RNG read has no timeout: a hung token stalls the report"

hdr "--env-only: the environment alone, in preflight's words"
out="$(run "$SCRIPTS/go-nogo.sh" --env-only)"
grep -q '^== Air-gap ==' <<< "$out" && P "has the air-gap section" || F "no air-gap section: $out"
grep -qE '^PREFLIGHT (OK|FAILED)' <<< "$out" && P "ends in PREFLIGHT OK / FAILED" || F "no PREFLIGHT verdict: $out"
grep -q 'Self-tests' <<< "$out" && F "--env-only ran the self-tests" || P "no self-tests in --env-only"

hdr "full run: every self-test, and the environment's WARNs in the same report"
out="$(run "$SCRIPTS/go-nogo.sh")"
for t in dice-entropy entropy-mix payload-qr seed-to-pkcs12 "share form" "case label" "PIN card"; do
  grep -qE "^  OK   $t" <<< "$out" && P "self-test ran and passed: $t" || F "no OK line for $t"
done
if age-keygen -pq 2>/dev/null | grep -q '^AGE-SECRET-KEY-PQ-1'; then
  grep -qE '^  OK   age .* makes post-quantum keys' <<< "$out" && P "the post-quantum age check ran and passed" || F "no post-quantum age line"
else
  grep -qE '^  FAIL age cannot make a post-quantum key' <<< "$out" && P "an old age is a FAIL (this host has no age >= 1.3)" || F "old age not reported"
fi
grep -q '^  WARN HISTFILE is set' <<< "$out" && P "an environment WARN appears directly in the report" || F "environment WARN missing"
bad_lines="$(grep -E '^  [A-Z.]+ ' <<< "$out" | grep -vE '^  (OK  |WARN|FAIL) ' || true)"
[ -z "$bad_lines" ] && P "every item line reads OK, WARN or FAIL" || F "other markers: $bad_lines"
last="$(grep -v '^$' <<< "$out" | tail -1)"
grep -qE '^(GO|NO-GO) — ' <<< "$last" && P "the last line is the verdict: ${last%% —*}" || F "last line is not a verdict: $last"

hdr "a broken tool is a FAIL and a NO-GO, whatever --need says"
mkdir -p "$T/repo/qubes" "$T/repo/tools"
cp -r "$SCRIPTS" "$T/repo/qubes/scripts"
cp "$REPO/tools/ceremony-python.sh" "$T/repo/tools/" 2>/dev/null || true
printf 'import sys\nprint("dice-entropy selftest: chi-square check broke")\nsys.exit(1)\n' > "$T/repo/qubes/scripts/dice-entropy.py"
out="$(run "$T/repo/qubes/scripts/go-nogo.sh"; echo "rc=${PIPESTATUS[0]}")"
grep -q '^  FAIL dice-entropy self-test FAILED' <<< "$out" && P "the broken self-test is a FAIL" || F "broken self-test not reported: $out"
grep -q 'chi-square check broke' <<< "$out" && P "its own output is shown" || F "its output is hidden"
grep -q '^NO-GO — ' <<< "$out" && P "verdict is NO-GO" || F "a broken tool still gave GO"

echo; echo "go-nogo one script: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
