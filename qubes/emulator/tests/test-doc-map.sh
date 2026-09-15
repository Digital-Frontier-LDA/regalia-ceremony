#!/usr/bin/env bash
# test-doc-map.sh — the README's document map must point at documents that exist, and every
# document must be reachable from it.
#
# WHY. The documents here are many and no single one explains the whole system — deliberately, since
# requirements, plans and drill records have very different lifetimes. That makes the MAP the entry
# point, and a map is the one artifact whose decay is invisible: it keeps rendering perfectly while
# pointing at a file somebody moved.
#
# The second half matters more than the first. A dangling link is annoying; an UNREACHABLE document
# is worse, because it is where a stale claim survives — nobody reads it, so nobody notices it now
# contradicts the ratified plan.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

README="$ROOT/README.md"
[ -r "$README" ] || { echo "  (skipping: no README at $README)"; exit 0; }

hdr "The map exists at all"
grep -q 'document map' "$README" \
  && P "README carries a document map" \
  || F "no document map — a pile of files and no entry point"

hdr "Every path the map names EXISTS"
missing=""
# Paths appear as `doc/…` or `bench/…` inside backticks in the map table.
for ref in $(grep -oE '`(doc|bench|ceremony|hardware|hsm-host-role)/[A-Za-z0-9._/-]+`' "$README" | tr -d '`' | sort -u); do
  # a trailing / denotes a directory
  case "$ref" in
    */) [ -d "$ROOT/$ref" ] || missing="$missing $ref" ;;
    *)  [ -e "$ROOT/$ref" ] || missing="$missing $ref" ;;
  esac
done
[ -z "$missing" ] && P "every referenced path resolves" \
                  || F "the map points at things that do not exist:$missing"

hdr "Every backticked repo path in EVERY markdown doc resolves"
# The check above covers the README's map table; this one sweeps ALL markdown in the repo
# (README.md, doc/**, qubes/**/*.md, hardware/**) for backticked repo-relative
# paths — the same decay one level down: a doc pointing at a script somebody renamed.
# Matching is anchored on the repo's top-level directories, so commands, env vars and
# `example-service:`-prefixed consumer-repo paths can never match. Spans containing a glob,
# a <placeholder> or a YYYY-MM-DD-style date template are examples, not paths, and are
# skipped. Fast and deterministic: one grep per file, both loops sorted.
broken=""
while IFS= read -r md; do
  rel="${md#"$ROOT"/}"
  while IFS= read -r ref; do
    ref="${ref%%#*}"                                   # drop a trailing #anchor
    ref="$(printf '%s' "$ref" | sed 's/[.,;:]*$//')"   # sentence punctuation inside the backticks
    case "$ref" in
      *\**|*\<*|*YYYY*) continue ;;                  # glob / placeholder / date-template example, not a concrete path
      # `hardware/<name>.h` is a PICO SDK C INCLUDE, not a repo path. The collision is real and
      # unavoidable: this repo has a top-level `hardware/` directory (docs about the HSM bench) and
      # the Pico SDK's headers are included as `hardware/powman.h`, `hardware/watchdog.h`. The
      # firmware notes in hardware/pico-hsm/ necessarily quote the include exactly as it appears in
      # the C, so this check reported them as broken links and the whole host suite went red.
      #
      # Narrow on purpose: only `hardware/*.h`, and only because this repo contains NO C headers
      # under hardware/ (verified 2026-08-08), so the exclusion cannot mask a genuine broken link.
      # If a real header is ever added there, this needs revisiting rather than widening.
      hardware/*.h) continue ;;
      */) [ -d "$ROOT/$ref" ] || broken="$broken $rel->$ref" ;;
      *)  [ -e "$ROOT/$ref" ] || broken="$broken $rel->$ref" ;;
    esac
  done < <(grep -oE '`(doc|bench|ceremony|hardware|hsm-host-role|tools)/[A-Za-z0-9._/#-]+`' "$md" | tr -d '`' | sort -u)
done < <(find "$ROOT" -name .git -prune -o -name '*.md' -print | sort)
[ -z "$broken" ] && P "every backticked repo path in every markdown doc resolves" \
                 || F "broken repo paths in docs:$broken"

hdr "Every doc/ file is REACHABLE from the map"
# The failure this catches: a document written, never linked, and quietly going stale.
unreached=""
for f in "$ROOT"/doc/*.md; do
  [ -f "$f" ] || continue
  b="doc/$(basename "$f")"
  grep -qF "$b" "$README" || unreached="$unreached $(basename "$f")"
done
if [ -z "$unreached" ]; then
  P "every doc/*.md is referenced from the README"
else
  F "written but unreachable from the map:$unreached"
  printf '     An unlinked document is where a superseded claim survives unread.\n'
fi

hdr "The status vocabulary is defined, not assumed"
# MEASURED / MODELLED / DECIDED are used throughout REQUIREMENTS.md and mean different things.
# If the README stops explaining them, a reader will treat them as synonyms — which is exactly the
# overclaim this project keeps having to correct.
for w in MEASURED MODELLED DECIDED; do
  grep -q "$w" "$README" && P "'$w' is explained in the README" || F "'$w' is used in the docs but never defined"
done

hdr "The precedence rule is stated"
# Most documents predate the 2026-08-01 ratification. Without an explicit rule, a reader has no
# way to know which document wins when two disagree.
grep -qiE 'those two win|PLAN.md.*win|predate' "$README" \
  && P "the README says which document wins on a conflict" \
  || F "no precedence rule — older docs contradict the ratified plan with no way to tell"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
