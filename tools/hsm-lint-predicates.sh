#!/usr/bin/env bash
# hsm-lint-predicates.sh — find shell predicates that can INVERT themselves. No hardware required.
#
#   tools/hsm-lint-predicates.sh [file ...]      # defaults to the repo's shell scripts
#
# THE BUG THIS EXISTS TO PREVENT.
#
#     set -o pipefail
#     card_answers(){ sc-hsm-tool 2>&1 | grep -qi '^Version'; }
#
# `grep -q` exits the moment it matches. That closes the pipe; the producer gets SIGPIPE and dies
# with 141; `pipefail` then reports 141 as the pipeline's status. So the predicate returns FALSE
# *because* it matched. It is not flaky — it is inverted, and it inverts only when the producer is
# still writing, which is exactly when there is a lot to say.
#
# MEASURED 2026-08-08 against a card answering normally in the same second:
#     with pipefail: FALSE (rc=141) x5     without pipefail: TRUE x5
#
# It cost more than any firmware defect here. card_answers() was the only way the recovery ladder
# recognised success, so the ladder could not see a healthy card: it ran its full remedy sequence
# against working hardware and then reported that a human had to walk to the bench. Every
# unexplained reset of a good card was this.
#
# THE FIX, and why the obvious one is not enough:
#
#     out="$(producer)"; grep -q PAT <<< "$out"       # correct: a here-string is a temp file,
#                                                     # there is no producer left to signal
#     out="$(producer)"; printf '%s' "$out" | grep -q PAT   # STILL WRONG for large output —
#                                                           # printf is a producer too
#
# Detection is textual and deliberately blunt: this reports a RISK, not a proven inversion. A
# pipeline whose producer always fits in the pipe buffer will not invert today, but it is one
# verbose day away from doing so, and the failure is silent and inverted when it comes.
set -u

pass=0; risk=0
P(){ printf '  \033[32mOK\033[0m   %s\n' "$1"; pass=$((pass+1)); }
R(){ printf '  \033[31mRISK\033[0m %s\n' "$1"; risk=$((risk+1)); }

if [ "$#" -gt 0 ]; then
    FILES=("$@")
else
    REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    FILES=()
    while IFS= read -r f; do FILES+=("$f"); done < <(
        # hsm-host-role/ is in this list because its two scripts are the DEPLOY-BLOCKING ones —
        # assert-no-dkek.sh and commission-card.sh decide whether a card goes into service. A
        # self-inverting predicate there is the most expensive place in the repo to have one, and
        # it was the one tree the scan did not look at.
        find "$REPO/tools" "$REPO/qubes" "$REPO/debian" "$REPO/hardware" "$REPO/hsm-host-role" \
             -name '*.sh' -type f 2>/dev/null | sort)
fi

echo "checking ${#FILES[@]} shell scripts for self-inverting predicates"
echo

# AN EMPTY POPULATION IS A BROKEN RUN, NOT A CLEAN ONE. $REPO is derived from BASH_SOURCE, so a copy
# of this script run from elsewhere resolves it to "/", finds no *.sh, and exits 0 having examined
# NOTHING — measured while taking a baseline for this very change, where it printed "0 clean, 0 at
# risk" and returned success. A gate that passes hardest when it is most broken is the failure mode
# this whole file exists to warn about, one level up.
if [ "${#FILES[@]}" -lt 20 ] && [ "$#" -eq 0 ]; then
    printf '  \033[31mBROKEN\033[0m only %s shell scripts were found — this scan examined almost nothing.\n' "${#FILES[@]}" >&2
    printf '  Expected the repo tree under tools/, qubes/, debian/ and hardware/. Run it from the repo, or pass files explicitly.\n' >&2
    exit 2
fi

# A SOURCED LIBRARY INHERITS THE CALLER'S pipefail, AND THIS LINTER USED TO SKIP IT.
# The gate below was "does THIS file set pipefail", so a file that sets none was never scanned.
# tools/hsm-reader-select.sh sets none — it is a library, sourced into hsm-staging-ci.sh and
# hsm-fleet-drill.sh, which both set `set -uo pipefail`. Its functions therefore run UNDER pipefail
# while the linter considered them out of scope, and that is how hsm_serial_at_reader shipped
# returning 141 on success (fixed 2026-09-11) past a linter written for exactly this bug.
#
# So build the set of files that are sourced by a pipefail script and scan those too. The match is
# by basename anywhere in the sourcing file, not only on the `.`/`source` line, because the path is
# usually assembled into a variable first (`_rs="$HERE/../tools/hsm-reader-select.sh"; . "$_rs"`)
# and a source line that names no file cannot be resolved textually. Blunt on purpose, like the
# rest of this tool: over-including a file costs one extra scan.
PIPEFAIL_FILES=()
for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    grep -qE '^[[:space:]]*set[[:space:]].*pipefail' "$f" 2>/dev/null && PIPEFAIL_FILES+=("$f")
done

inherits_pipefail(){ # $1 = a file that sets no pipefail itself
    local b; b="$(basename "$1")"
    local c srcline var
    for c in "${PIPEFAIL_FILES[@]}"; do
        # Named directly on a source line: `. "$HERE/../tools/lib.sh"`.
        grep -qE '(^|[[:space:]])(\.|source)[[:space:]]+[^;&|]*'"$(printf '%s' "$b" | sed 's/\./\\./g')" "$c" 2>/dev/null && return 0
        # Or sourced through a variable: `_rs="$HERE/../tools/lib.sh"` … `. "$_rs"`. Resolve it by
        # taking the variable names that appear in source statements and looking at what they were
        # assigned. Matching the basename ANYWHERE in the file instead would pull in every script a
        # pipefail script merely MENTIONS — it flagged hsm-staging-restore.sh, which the battery
        # EXECUTES as its own process with `set -u`, so it does not inherit pipefail at all. A
        # linter that cannot tell "sourced into" from "run by" reports risks that cannot fire, and
        # those are the findings people learn to scroll past.
        while IFS= read -r srcline; do
            var="$(printf '%s' "$srcline" | sed -nE 's/.*(\.|source)[[:space:]]+"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?.*/\2/p')"
            [ -n "$var" ] || continue
            grep -E "^[[:space:]]*(local[[:space:]]+)?$var=" "$c" 2>/dev/null | grep -qF "$b" && return 0
        done < <(grep -E '(^|[[:space:]])(\.|source)[[:space:]]+"?\$' "$c" 2>/dev/null)
    done
    return 1
}

for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    # Only code that runs under pipefail can suffer the inversion — whether it set it or inherited it.
    _why="sets pipefail"
    if ! grep -qE '^[[:space:]]*set[[:space:]].*pipefail' "$f" 2>/dev/null; then
        inherits_pipefail "$f" || continue
        _why="sourced by a pipefail script"
    fi

    # Pipelines feeding an early-exiting grep. `grep -q`/`-l` stop reading at the first match;
    # `grep -c` and a bare grep read to EOF and are safe.
    #
    # Comment lines are excluded — this file and the recovery script both DISCUSS the antipattern
    # at length, and a linter that flags the explanation of a bug as the bug is just noise.
    # grep -q/-l is not the only consumer that quits early. An `awk` program that calls `exit` on a
    # match closes the pipe exactly the same way — that IS the defect found in hsm-reader-select.sh:
    # the serial sat on line 3 of pkcs15-tool's 30 lines of card I/O, awk exited, the tool took
    # SIGPIPE, and the function returned 141 with the right answer on stdout. `grep -m N` quits after
    # N matches and `sed ... q` after its address, so they belong here too; both happen to be unused
    # in this tree today, which is the moment to add them rather than after the first one appears.
    #
    # An `exit` inside an END block is SAFE and must not be flagged: END runs only after the input is
    # fully consumed, so there is no producer left to signal. hsm_slot_index_for relies on exactly
    # that to report not-found, so flagging it would push a correct construction toward a worse one.
        # `||` IS NOT A PIPE. The patterns below match a single `|` whose left neighbour is not also a
    # `|`, because `cmd || grep -qaF pat file` has no pipeline at all — grep reads a FILE and there is
    # no producer to SIGPIPE. That false positive was this linter's only finding on main, so the one
    # line it reported could never invert, and the real defect (an awk early exit in a sourced
    # library) was in a file it did not scan. A linter with one false positive and one blind spot
    # reads exactly like a linter that is passing.
    hits="$(grep -nE '(^|[^|])\|[[:space:]]*(LC_ALL=C[[:space:]]+)?grep[[:space:]]+-[a-zA-Z]*[ql]|(^|[^|])\|[[:space:]]*grep[[:space:]]+-[a-zA-Z]*m[[:space:]]*[0-9]|(^|[^|])\|[[:space:]]*awk[^|]*exit|(^|[^|])\|[[:space:]]*sed[^|]*;[[:space:]]*q' "$f" 2>/dev/null \
            | grep -v '<<<' | grep -vE '^[0-9]+:[[:space:]]*#' | grep -v 'END[[:space:]]*{' || true)"
    if [ -z "$hits" ]; then
        P "$(basename "$f") [$_why]"
        continue
    fi

    # SEVERITY, because a flat count is not actionable. What decides whether the inversion actually
    # fires is whether the producer is still writing when grep quits:
    #
    #   HIGH — an external command feeds the pipe. It is a separate process with its own buffering
    #          and it can be slow or verbose. This is the shape that was MEASURED inverting 5/5 on
    #          sc-hsm-tool, and `ioreg`/`opensc-tool`/`uhubctl` are the same shape.
    #   LOW  — `echo`/`printf` replaying a variable already in memory. A shell builtin with a small
    #          write; it usually finishes first. Still worth fixing, but it is not what breaks a
    #          bench at 2am.
    # `echo`/`printf` may sit behind any prefix (`elif`, `if [ x ] &&`, `! `), so match the
    # producer immediately left of the pipe rather than the start of the line — otherwise a
    # builtin replay gets graded HIGH and the severity stops meaning anything.
    # The builtin-replay exemption is about the PRODUCER, so it must look left of the pipe only —
    # and it must not accidentally keep an awk/sed hit out of the HIGH bucket merely because that
    # line does not contain the word "grep".
    high="$(printf '%s\n' "$hits" | grep -vE '(echo|printf)[^|]*\|[[:space:]]*(LC_ALL=C[[:space:]]+)?(grep|awk|sed)' || true)"
    n_all="$(printf '%s\n' "$hits" | grep -c .)"
    n_high="$(printf '%s\n' "$high" | grep -c . || true)"
    if [ "${n_high:-0}" -gt 0 ]; then
        R "$(basename "$f") — ${n_high} HIGH (external producer), $((n_all - n_high)) low"
        printf '%s\n' "$high" | sed 's/^/         /' | head -8
    else
        R "$(basename "$f") — ${n_all} low (builtin replaying a variable)"
    fi
done

echo
printf '  %d clean, %d at risk\n' "$pass" "$risk"
if [ "$risk" -gt 0 ]; then
    echo
    echo "  Each RISK line is 'producer | grep -q' inside a script using pipefail."
    echo "  Rewrite as:  out=\"\$(producer)\"; grep -q PAT <<< \"\$out\""
    echo "  A here-string has no producer process, so nothing can be SIGPIPEd and the"
    echo "  pipeline status cannot be poisoned."
    exit 1
fi
