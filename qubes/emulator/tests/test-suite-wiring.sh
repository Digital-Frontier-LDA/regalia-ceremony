#!/usr/bin/env bash
# test-suite-wiring.sh — every test file in tests/ must be referenced by run-tests.sh.
#
# WHY THIS EXISTS. On 2026-09-11 four test files in this directory were run by nothing at all:
# test-hsm-reader-select.sh, test-preflight-airgap.sh, test-preflight-live-iface.sh and
# test_scan_dangling_link.py. No runner line, no workflow step. Two of them guard the air-gap
# check that their own headers call the single most important control of the whole ceremony, and
# all four passed — so this was not a set of known-failing exclusions, it was silent non-coverage.
# It was found only because a new assertion was added to one of them and did not appear in a full
# run. "A test file exists" and "a test runs" are different claims; only the second protects
# anything, and nothing here was checking the second.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$HERE/../run-tests.sh"
[ -f "$RUNNER" ] || { echo "missing $RUNNER" >&2; exit 1; }

pass=0; fail=0
printf '\n\033[1m### every test file is referenced by run-tests.sh\033[0m\n'

# Count the population explicitly and assert it is non-empty. A glob that matches nothing would
# otherwise make this suite pass by examining zero files — an instrument that cannot fail is not
# an instrument.
n=0
for f in "$HERE"/test-*.sh "$HERE"/test_*.py; do
  [ -e "$f" ] || continue
  b="$(basename "$f")"
  [ "$b" = "test-suite-wiring.sh" ] && continue   # this file is referenced by the line that runs it
  n=$((n + 1))
  if grep -q -- "$b" "$RUNNER"; then
    pass=$((pass + 1))
  else
    printf '  \033[31mFAIL\033[0m %s is never run by run-tests.sh\n' "$b"
    fail=$((fail + 1))
  fi
done

if [ "$n" -lt 20 ]; then
  printf '  \033[31mFAIL\033[0m only %s test files were examined — the glob is wrong, not the suite clean\n' "$n"
  fail=$((fail + 1))
else
  printf '  \033[32mPASS\033[0m %s test files examined, %s referenced\n' "$n" "$pass"
fi

printf '\n\033[1m### the CI trigger must cover the directories these tests are written against\033[0m\n'
# A GATE WHOSE TRIGGER DOES NOT COVER ITS SUBJECT IS NOT A GATE — the workflow says so itself, in
# the comment that added doc/** after three documents reached main unmapped. The same hole was open
# for tools/**: five suites here have their subject under tools/, including the #185 transcript
# redaction control, so a PR changing only the tool ran none of the tests written against it. That
# is how hsm_serial_at_reader came to return 141 on success with a test file that nothing executed.
WF="$HERE/../../../.github/workflows/emulator.yml"
if [ ! -f "$WF" ]; then
  printf '  \033[31mFAIL\033[0m cannot find the workflow at %s — this check cannot be evaluated\n' "$WF"
  fail=$((fail + 1))
else
  # Which top-level directories do these tests actually point at? Derived from the files, not
  # hardcoded, so a test added against a new tree is caught instead of silently uncovered.
  # COMMENTS ARE INCLUDED ON PURPOSE, and that is a weaker claim than it looks — say so rather than
  # imply the scan measures code. Measured 2026-09-11: with comments this derives
  # qubes/ doc/ tools/; with comment lines stripped it derives ONLY tools/, because these
  # shell suites build their subject paths from variables ("$REPO/tools/...", "$HERE/../../scripts")
  # rather than writing them literally. A literal-path scan therefore cannot see what most of them
  # touch, and restricting it to code would shrink this check to almost nothing.
  #
  # Including prose is sound HERE because of the direction of the error: over-including a directory
  # adds CI minutes, while under-including one lets a defect land — which is exactly what happened to
  # #400. A comment naming a tree is weak evidence the suite cares about that tree, and weak evidence
  # is the right bar when being wrong costs minutes in one direction and a red main in the other.
  # THE ALPHABET IS THE TOP-LEVEL TREES, NOTHING ELSE. `salt` was in it while the workflow has no
  # salt/** trigger — and there is no top-level salt/ either, so a path like qubes/salt/... derived
  # BOTH qubes and salt and failed this check for a subtree that is already covered. `hsm-host-role`
  # was missing, so removing that trigger would not have been noticed even though two suites have
  # their subject there.
  #
  # A SEGMENT ANYWHERE IN A PATH COUNTS. The old pattern refused to match after a '/', so a suite
  # naming "$HERE/../../../hsm-host-role/files/assert-no-dkek.sh" — which is how every one of these
  # reaches outside qubes/emulator/ — derived nothing at all. Over-including a tree costs CI
  # minutes; under-including one lets a defect land, which is the error this file exists to stop.
  TREES='tools|qubes|debian|hardware|doc|hsm-host-role'
  dirs="$(grep -ohE "(^|[^a-zA-Z0-9_.-])($TREES)/[a-zA-Z0-9_./-]+" \
            "$HERE"/test-*.sh "$HERE"/test_*.py 2>/dev/null \
          | grep -oE "(^|[^a-zA-Z0-9_.-])($TREES)/" | grep -oE "($TREES)/" | sort -u | sed 's|/$||')"
  if [ -z "$dirs" ]; then
    printf '  \033[31mFAIL\033[0m no subject directories were derived — the scan is broken, not the trigger complete\n'
    fail=$((fail + 1))
  else
    for d in $dirs; do
      if grep -qE "^[[:space:]]*-[[:space:]]*\"?$d/\*\*\"?[[:space:]]*$" "$WF"; then
        printf '  \033[32mPASS\033[0m the trigger covers %s/** \n' "$d"
        pass=$((pass + 1))
      else
        printf '  \033[31mFAIL\033[0m tests here are written against %s/ but the workflow does not trigger on %s/**\n' "$d" "$d"
        fail=$((fail + 1))
      fi
    done
  fi
fi

printf '\n\033[1m### a test that scans the whole repo needs a trigger that covers the whole repo\033[0m\n'
# THE DIRECTORY CHECK ABOVE IS NOT ENOUGH. It derives subject directories from paths the tests name,
# and a test that scans by FILE TYPE names none: test-doc-map.sh does
# `find "$ROOT" -name .git -prune -o -name '*.md' -print`, so its subject is every markdown file in
# the repository and no directory pattern expresses that.
#
# It cost a red main in the monorepo this was extracted from: a markdown-only change cited a tool
# by a path that did not exist, touched no directory the workflow watched, and matched none of its patterns —
# so the gate that exists to catch exactly that never ran, and the defect landed. doc/** and tools/**
# were each added to that trigger after the same lesson; this is its general form.
for _ext in $(grep -hoE "\-name '\*\.[a-z]+'" "$HERE"/test-*.sh 2>/dev/null \
              | grep -oE '[a-z]+' | grep -v name | sort -u); do
  # Only repo-wide scans count. A find rooted at a specific subtree is covered by the directory rule.
  # A `... | while read` loop runs in a SUBSHELL, so every pass/fail increment inside it is
  # discarded when the loop ends. Caught by falsifying this very check: with **/*.md removed from
  # the trigger it printed two FAIL lines, reported "0 failed", and exited 0 — a check that shows
  # a failure and passes anyway, which is the shape this whole file exists to prevent.
  # A `for` over a command substitution runs in the CURRENT shell; these are test-*.sh names with
  # no spaces, so word splitting is safe here.
  # SINGLE QUOTES for the pattern. Double-quoted, the \$( ... ) reached bash as a command
  # substitution — the run printed `REPO: command not found`, the grep matched nothing, and the loop
  # body never executed, so the check silently examined zero files while still reporting 69 passed.
  for _f in $(grep -lE 'find "?\$(ROOT|REPO)' "$HERE"/test-*.sh 2>/dev/null); do
    grep -qE "\-name '\*\.$_ext'" "$_f" || continue
    if grep -qE "^[[:space:]]*-[[:space:]]*\"?\*\*/\*\.$_ext\"?[[:space:]]*$" "$WF"; then
      printf '  \033[32mPASS\033[0m %s scans every *.%s, and the trigger covers **/*.%s\n' "$(basename "$_f")" "$_ext" "$_ext"
      pass=$((pass + 1))
    else
      printf '  \033[31mFAIL\033[0m %s scans every *.%s in the repo, but the workflow does not trigger on **/*.%s — a file of that type anywhere can break it with this gate never running\n' "$(basename "$_f")" "$_ext" "$_ext"
      fail=$((fail + 1))
    fi
  done
done

printf '\n\033[1m### every suite run-tests.sh executes directly is executable\033[0m\n'
# run-tests.sh runs suites as "$HERE/tests/name.sh" || rc=1, so a suite committed without its execute bit
# fails in CI with "Permission denied" -- one line, no RESULT, no name in any failure summary -- while
# passing for anyone who runs it as `bash name.sh`. That is how test-hsm-swd-role-gate.sh sat red in
# CI for #431 and green locally. The bit is checked on the checkout, which is what the runner executes.
_x_seen=0
while IFS= read -r _suite; do
  [ -n "$_suite" ] || continue
  _x_seen=$((_x_seen + 1))
  if [ -x "$HERE/$_suite" ]; then
    pass=$((pass + 1))
  else
    printf '  \033[31mFAIL\033[0m %s is executed directly by run-tests.sh but is not executable (git update-index --chmod=+x)\n' "$_suite"
    fail=$((fail + 1))
  fi
done <<EOF
$(grep -oE '^"\$HERE/tests/[A-Za-z0-9_.-]+\.sh"' "$RUNNER" | sed 's#^"\$HERE/tests/##; s#"$##' | sort -u)
EOF
# An extraction that matched nothing would check nothing and pass; refuse that as loudly as a failure.
if [ "$_x_seen" -eq 0 ]; then
  printf '  \033[31mFAIL\033[0m found no directly-executed suites in run-tests.sh — the extraction pattern no longer matches\n'
  fail=$((fail + 1))
else
  printf '  \033[32mPASS\033[0m %s directly-executed suites checked for the execute bit\n' "$_x_seen"
fi

printf '\n\033[1m### a missing dependency fails CI instead of skipping (#166, #167)\033[0m\n'
# A step test that exits 0 because a tool is missing is green in CI for a test that never ran. The one way to skip is
# skip_dep, which REQUIRE_EMULATOR_DEPS=1 (set on CI's run-tests.sh line) turns into a failure. Matching the spellings
# of a skip missed the next one written another way, so tools/emulator-green-exits.py reads each test as bash does
# (strings, heredocs and comments set aside) and reports EVERY exit that can be green before the end: exit 0, a bare
# exit, exit $x. The deliberate ones are in qubes/emulator/green-exits.allow, one entry per line, each with its reason.
GX="$HERE/../../../tools/emulator-green-exits.py"; GXA="$HERE/../green-exits.allow"
gx(){ python3 -I "$GX" "$@" >"$_gx_out" 2>&1; }
_gx_dir="$(mktemp -d)"; _gx_out="$_gx_dir/out"
gx --allow "$GXA" "$HERE"/*.sh; _rc=$?
case "$_rc" in
  0) printf '  \033[32mPASS\033[0m no emulator test can exit green before it ran, outside skip_dep and the allowlist\n'; pass=$((pass + 1));;
  1) printf '  \033[31mFAIL\033[0m an exit that can be green before the test ran (use skip_dep, or allowlist it with a reason):\n%s\n' "$(cat "$_gx_out")"
     fail=$((fail + 1));;
  *) printf '  \033[31mFAIL\033[0m the green-exit scan could not judge the tests (rc %s): %s\n' "$_rc" "$(cat "$_gx_out")"; fail=$((fail + 1));;
esac
# The scan's own fixtures: every spelling a review found the old regex missed is reported, and what is not an early
# green exit is not. Each body ends with a line of code, as a test does, so its exit is not the last line.
_gx_case(){ # _gx_case WANT_RC LABEL: the fixture on stdin, scanned alone (with $_gx_allow, when set)
  local want="$1" label="$2" f="$_gx_dir/fixture.sh" rc
  { cat; echo 'echo end'; } > "$f"
  if [ -n "${_gx_allow:-}" ]; then gx --allow "$_gx_allow" "$f"; else gx "$f"; fi; rc=$?
  if [ "$rc" = "$want" ]; then printf '  \033[32mPASS\033[0m %s\n' "$label"; pass=$((pass + 1))
  else printf '  \033[31mFAIL\033[0m %s: rc %s, want %s: %s\n' "$label" "$rc" "$want" "$(cat "$_gx_out")"; fail=$((fail + 1)); fi
}
_gx_case 1 'reported: { echo "SKIP"; exit 0; }' <<'X'
command -v ykman >/dev/null 2>&1 || { echo "SKIP: ykman not installed"; exit 0; }
X
_gx_case 1 'reported: echo "  (skipping: ...)"; exit 0' <<'X'
echo "  (skipping: no ykman here)"; exit 0
X
_gx_case 1 'reported: the message to stderr (>&2)' <<'X'
command -v ykman >/dev/null 2>&1 || { echo "ykman not installed" >&2; exit 0; }
X
_gx_case 1 'reported: a lower-case "skip"' <<'X'
command -v ykman >/dev/null 2>&1 || { echo "skip: ykman not installed"; exit 0; }
X
_gx_case 1 'reported: printf instead of echo' <<'X'
command -v ykman >/dev/null 2>&1 || { printf 'SKIP %s\n' ykman; exit 0; }
X
_gx_case 1 'reported: single quotes' <<'X'
command -v ykman >/dev/null 2>&1 || { echo 'SKIP: ykman not installed'; exit 0; }
X
_gx_case 1 'reported: || exit 0 with no message' <<'X'
command -v ykman >/dev/null 2>&1 || exit 0
X
_gx_case 1 'reported: an if-block over several lines' <<'X'
if ! command -v ykman >/dev/null 2>&1; then
  echo "ykman not installed"
  exit 0
fi
X
_gx_case 1 'reported: a bare exit' <<'X'
command -v ykman >/dev/null 2>&1 || { echo "ykman not installed"; exit; }
X
_gx_case 1 'reported: exit with a variable status' <<'X'
[ -x /opt/vault-bin/age ] || exit "$ok"
X
_gx_case 0 'not reported: a non-zero exit' <<'X'
[ -r "$IMPORT" ] || { echo "no $IMPORT" >&2; exit 1; }
X
_gx_case 0 'not reported: skip_dep, and its own definition' <<'X'
skip_dep(){ # a missing dependency
  if [ "${REQUIRE_EMULATOR_DEPS:-0}" = 1 ]; then echo "  FAIL: $1"; exit 1; fi
  echo "  SKIP: $1"; exit 0
}
command -v ykman >/dev/null 2>&1 || { skip_dep "ykman not installed"; }
X
_gx_case 0 'not reported: exit 0 in a stub written by printf, a heredoc, a $( ) and a comment' <<'X'
printf '#!/bin/sh\nexit 0\n' > "$T/shim/gpgconf"
out="$(bash -c "echo \"$(printf 'exit 0')\"")"
cat > "$T/shim/pcscd" <<'EOS'
#!/bin/sh
exit 0
EOS
: # exit 0 here is prose
X
GX_LAST="$_gx_dir/last.sh"; printf 'echo run\n[ "$fail" -eq 0 ] || exit 1\nexit 0\n' > "$GX_LAST"
if gx "$GX_LAST"; then printf '  \033[32mPASS\033[0m not reported: a final exit 0\n'; pass=$((pass + 1))
else printf '  \033[31mFAIL\033[0m a final exit 0 was reported: %s\n' "$(cat "$_gx_out")"; fail=$((fail + 1)); fi
printf 'fixture.sh\texit 0\tthe fixture of an allowlisted line\n' > "$_gx_dir/allow"; _gx_allow="$_gx_dir/allow"
_gx_case 0 'an allowlisted line: accepted' <<'X'
exit 0
X
_gx_case 1 'the same line twice with one entry: the second is reported' <<'X'
exit 0
exit 0
X
_gx_case 1 'a stale entry (its line gone): reported' <<'X'
echo nothing here exits
X
_gx_allow=""
_gx_case 2 'a file that ends inside a string: refused, not passed' <<'X'
echo "never closed
exit 0
X
rm -rf -- "$_gx_dir"
_gated=$(grep -lE '\{ skip_dep "|^[[:space:]]*skip_dep "|\|\| skip_dep "' "$HERE"/*.sh 2>/dev/null | grep -v "/$(basename "$0")$" | wc -l | tr -d ' ')
_defs=$(for f in "$HERE"/*.sh; do [ "$f" -ef "$0" ] && continue; awk '/^skip_dep\(\)\{/{p=1} p{print} p&&/^\}$/{exit}' "$f" | cksum; done | grep -v '^4294967295 0$' | sort | uniq -c)
_defined=$(printf '%s\n' "$_defs" | awk 'NF{n+=$1} END{print n+0}')
if [ "$_gated" -lt 20 ]; then        # 24 scripts at #167: a scan that finds none checks nothing
  printf '  \033[31mFAIL\033[0m only %s scripts call skip_dep (24 did at #167): the pattern no longer matches, or gates were removed\n' "$_gated"
  fail=$((fail + 1))
elif [ "$_gated" != "$_defined" ]; then
  printf '  \033[31mFAIL\033[0m %s scripts call skip_dep but %s define it\n' "$_gated" "$_defined"; fail=$((fail + 1))
elif [ "$(printf '%s\n' "$_defs" | grep -c .)" != 1 ]; then
  printf '  \033[31mFAIL\033[0m the %s skip_dep definitions are not all the same text (one would exit 0 under CI):\n%s\n' "$_defined" "$_defs"
  fail=$((fail + 1))
else
  printf '  \033[32mPASS\033[0m %s scripts gate their dependencies through skip_dep, each defining it identically\n' "$_gated"; pass=$((pass + 1))
fi
if [ -f "$WF" ] && grep -qE '^[[:space:]]*sudo env [^#]*REQUIRE_EMULATOR_DEPS=1[^#]* qubes/emulator/run-tests\.sh' "$WF"; then
  printf '  \033[32mPASS\033[0m CI runs run-tests.sh with REQUIRE_EMULATOR_DEPS=1\n'; pass=$((pass + 1))
else
  printf '  \033[31mFAIL\033[0m CI does not run run-tests.sh with REQUIRE_EMULATOR_DEPS=1: every skip_dep is a silent green there\n'
  fail=$((fail + 1))
fi

printf '\n  %d checks passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
