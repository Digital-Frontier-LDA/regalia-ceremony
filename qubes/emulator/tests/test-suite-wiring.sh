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
WF="$HERE/../../../../.github/workflows/ceremony-emulator.yml"
if [ ! -f "$WF" ]; then
  printf '  \033[31mFAIL\033[0m cannot find the workflow at %s — this check cannot be evaluated\n' "$WF"
  fail=$((fail + 1))
else
  # Which top-level directories do these tests actually point at? Derived from the files, not
  # hardcoded, so a test added against a new tree is caught instead of silently uncovered.
  # COMMENTS ARE INCLUDED ON PURPOSE, and that is a weaker claim than it looks — say so rather than
  # imply the scan measures code. Measured 2026-09-11: with comments this derives
  # ceremony/ doc/ kms/ tools/; with comment lines stripped it derives ONLY tools/, because these
  # shell suites build their subject paths from variables ("$REPO/tools/...", "$HERE/../../scripts")
  # rather than writing them literally. A literal-path scan therefore cannot see what most of them
  # touch, and restricting it to code would shrink this check to almost nothing.
  #
  # Including prose is sound HERE because of the direction of the error: over-including a directory
  # adds CI minutes, while under-including one lets a defect land — which is exactly what happened to
  # #400. A comment naming a tree is weak evidence the suite cares about that tree, and weak evidence
  # is the right bar when being wrong costs minutes in one direction and a red main in the other.
  dirs="$(grep -ohE '(^|[^a-zA-Z0-9_/.-])(tools|ceremony|doc|kms|salt|infra)/[a-zA-Z0-9_./-]+' \
            "$HERE"/test-*.sh "$HERE"/test_*.py 2>/dev/null \
          | grep -oE '(tools|ceremony|doc|kms|salt|infra)/' | sort -u | tr -d '/')"
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
# It cost a red main. #400 added kms/OPENPGP-COMPATIBILITY.md citing `tools/custody_manifest.py`
# (the file is at kms/tools/...), touched only kms/**, and matched none of the workflow's patterns —
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

printf '\n  %d checks passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
