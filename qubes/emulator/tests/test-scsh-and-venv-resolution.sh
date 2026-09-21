#!/usr/bin/env bash
# test-scsh-and-venv-resolution.sh — two interpreters the card path depends on, and the bad
# failures they produced when they were assumed rather than resolved.
#
# SMART CARD SHELL. The tarball unpacks as scsh-3.18.77/scsh-3.18.77/ — scriptrunner is in the
# INNER directory — and both callers defaulted to the outer one. The import then ran
# `./scriptrunner` from inside a `cd` to a directory that does not contain it, and the drill
# reported "key import failed:" with an EMPTY reason while the real message went to stderr.
# Measured 2026-09-21 mid-drill on DENK0404144. A missing interpreter is not an import failure,
# and reporting it as one sends whoever reads the transcript looking at the card.
#
# THE CEREMONY VENV. A drill run from a shell without the venv on PATH reported
# "python 'mnemonic'/'shamir-mnemonic' packages missing — SLIP-39 arm skipped": an UNVERIFIED on
# requirement B5's arm caused by nothing but PATH.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# The real layout: an outer directory whose scriptrunner is one level down.
mkdir -p "$T/scsh-3.18.77/scsh-3.18.77"
printf '#!/bin/sh\nexit 0\n' > "$T/scsh-3.18.77/scsh-3.18.77/scriptrunner"
chmod +x "$T/scsh-3.18.77/scsh-3.18.77/scriptrunner"

hdr "the nested tarball layout resolves to the directory that HAS scriptrunner"
for f in hsm-import-key.sh hsm-auto-import.sh; do
  # Run the resolution the script does, in isolation, against the real layout.
  got="$(SCSH_HOME="$T/scsh-3.18.77" bash -c '
      SCSH_HOME="$1"
      [ -x "$SCSH_HOME/scriptrunner" ] || [ ! -x "$SCSH_HOME/scsh-3.18.77/scriptrunner" ] \
        || SCSH_HOME="$SCSH_HOME/scsh-3.18.77"
      printf "%s" "$SCSH_HOME"' _ "$T/scsh-3.18.77")"
  [ "$got" = "$T/scsh-3.18.77/scsh-3.18.77" ] \
    && P "$f's resolution finds the inner directory" \
    || F "$f's resolution returned $got"
  grep -q 'scsh-3.18.77/scriptrunner" \]' "$SCRIPTS/$f" \
    && P "…and $f actually contains it" || F "$f does not resolve the nested layout"
done
# A SCSH_HOME that already points at the right place must be left alone.
got="$(bash -c '
    SCSH_HOME="$1"
    [ -x "$SCSH_HOME/scriptrunner" ] || [ ! -x "$SCSH_HOME/scsh-3.18.77/scriptrunner" ] \
      || SCSH_HOME="$SCSH_HOME/scsh-3.18.77"
    printf "%s" "$SCSH_HOME"' _ "$T/scsh-3.18.77/scsh-3.18.77")"
[ "$got" = "$T/scsh-3.18.77/scsh-3.18.77" ] \
  && P "an SCSH_HOME that already names the right directory is not descended into twice" \
  || F "a correct SCSH_HOME was rewritten to $got"

hdr "a missing Smart Card Shell is REFUSED, with the reason and the fix"
# Every required argument is present and readable, so the ONLY thing missing is the interpreter.
: > "$T/f.p12"; : > "$T/f.crt"; : > "$T/f.pbe"; : > "$T/fake-module.so"
printf 'x' > "$T/pw"; printf 'x' > "$T/dkekpw"; printf '648219' > "$T/pin"
# --slot IS GIVEN. The interpreter check sits after the slot guard — deliberately, so that a
# missing Smart Card Shell cannot pre-empt the question of WHICH card is about to be written to —
# so a bench with two tokens attached refuses on the slot before it ever looks for scriptrunner.
out="$(SCSH_HOME="$T/nothing-here" bash "$SCRIPTS/hsm-import-key.sh" \
        --p12 "$T/f.p12" --pw-file "$T/pw" --id 1 --label x --cert "$T/f.crt" \
        --dkek "$T/f.pbe" --dkek-pw "$T/dkekpw" --pin-file "$T/pin" \
        --reader 0 --slot 0 --module "$T/fake-module.so" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "it fails (exit $rc) rather than running ./scriptrunner from the wrong place" \
  || F "it continued without an interpreter"
grep -q 'no Smart Card Shell at' <<<"$out" && P "…naming what is missing and where it looked" \
  || F "the refusal does not say what is missing: $(tail -2 <<<"$out")"
grep -q 'export SCSH_HOME=' <<<"$out" && P "…and the exact export that fixes it" \
  || F "the refusal does not say how to fix it"
grep -q 'the card is not at fault' <<<"$out" \
  && P "…and says plainly this is not a card failure" || F "it still reads as an import failure"

hdr "the drill resolves the ceremony venv instead of trusting PATH"
grep -q 'ceremony_python_prefer mnemonic shamir_mnemonic' "$SCRIPTS/hsm-recovery-drill.sh" \
  && P "hsm-recovery-drill.sh resolves the venv before its SLIP-39 arm asks python3" \
  || F "the drill still depends on the caller's PATH — B5's arm skips for no reason but that"
grep -n 'ceremony_python_prefer' "$SCRIPTS/hsm-recovery-drill.sh" | head -1 | cut -d: -f1 > "$T/resolve_line"
grep -n 'import mnemonic, shamir_mnemonic' "$SCRIPTS/hsm-recovery-drill.sh" | head -1 | cut -d: -f1 > "$T/use_line"
if [ "$(cat "$T/resolve_line")" -lt "$(cat "$T/use_line")" ]; then
  P "…and it resolves BEFORE the check, not after (line $(cat "$T/resolve_line") < $(cat "$T/use_line"))"
else
  F "the resolution happens after the check that needs it"
fi

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
