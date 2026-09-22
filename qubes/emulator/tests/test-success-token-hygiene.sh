#!/usr/bin/env bash
# test-success-token-hygiene.sh — a FAILURE message must not contain the SUCCESS token.
#
# WHY. The import scripts signal success with the literal token IMPORT-OK, and their callers
# detect it by grepping:
#
#     grep -q "IMPORT-OK" <<< "$out"        # hsm-import-key.sh, hsm-auto-import.sh
#
# So a failure message that mentions the token — "Refusing to report IMPORT-OK on an unreadable
# listing", "key import did not report IMPORT-OK" — makes a refusal read as a successful import to
# the very code that checks. Found 2026-09-22 when this suite's own assertion for "it prints no
# IMPORT-OK on failure" matched the refusal's own wording.
#
# The rule is narrow: the token may appear on a SUCCESS line, in a grep that looks for it, or in a
# comment explaining any of this. Anywhere else in a script that emits it, it is a hazard.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

TOKEN='IMPORT-OK'

hdr "no err/warn line in any script carries the success token"
bad=""
for f in "$SCRIPTS"/*.sh; do
  # Lines that PRINT a failure: err ... / printf ... >&2 / echo ... >&2
  hits="$(grep -nE '^[[:space:]]*(err|warn|die)[[:space:]]|>&2' "$f" 2>/dev/null | grep -F -- "$TOKEN" || true)"
  # A comment is not a printed line.
  hits="$(grep -vE '^[0-9]+:[[:space:]]*#' <<< "$hits" || true)"
  [ -n "$hits" ] && bad="$bad
  $(basename "$f"): $hits"
done
if [ -z "$bad" ]; then
  P "no failure path prints '$TOKEN'"
else
  F "these failure messages contain the success token, so a caller grepping for it reads them as success:$bad"
fi

hdr "the token is still emitted on success, or the callers have nothing to find"
emitters=0
for f in "$SCRIPTS"/*.sh; do
  grep -qE "^[[:space:]]*ok[[:space:]]+\"$TOKEN\"|^[[:space:]]*ok[[:space:]]+\"[^\"]*$TOKEN" "$f" 2>/dev/null && emitters=$((emitters+1))
done
[ "$emitters" -ge 1 ] && P "$emitters script(s) print '$TOKEN' on the success path" \
  || F "nothing emits '$TOKEN' any more — the callers that grep for it would never see success"

hdr "and the callers do grep for it, which is why this matters"
greppers="$(grep -lE "grep -q.*$TOKEN" "$SCRIPTS"/*.sh 2>/dev/null | wc -l | tr -d ' ')"
[ "${greppers:-0}" -ge 1 ] && P "$greppers script(s) detect success by grepping for it" \
  || F "nothing greps for '$TOKEN'; if that is now true, this whole rule can go"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
