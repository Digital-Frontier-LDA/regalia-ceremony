#!/usr/bin/env bash
# test-preflight-checks-the-ceremonys-python.sh — preflight must report on the interpreter the
# ceremony will actually run, not on whichever python3 was on ITS path.
#
# WHY. preflight.sh proves `import mnemonic` and `import shamir_mnemonic` resolve BEFORE keys are
# in RAM, precisely so ceremony step 3c — the funding seed's only Option-B backup — cannot fail
# mid-ceremony with the money exposed. It proved it for its own python3. ceremony.sh runs bare
# `python3` too, so on the air-gapped image the two coincide (the wheels are installed
# system-wide) and anywhere the dependencies live in a venv they do not.
#
# Measured 2026-09-22: under `sudo`, secure_path drops the venv from PATH and preflight reported
#
#     FAIL  python3 cannot import 'mnemonic' … bake the wheel into the vault-tools image
#
# on a host where the ceremony's own resolution finds it. A readiness check about a different
# interpreter than the one that runs is not a readiness check — in either direction: it can also
# green-light a ceremony whose python cannot import the module.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

hdr "both resolve the interpreter the same way"
for f in ceremony.sh preflight.sh; do
  grep -q 'ceremony_python_prefer mnemonic shamir_mnemonic' "$SCRIPTS/$f" \
    && P "$f resolves the ceremony venv for exactly those two modules" \
    || F "$f does not resolve it — it will report on whatever PATH gave"
done

hdr "preflight resolves BEFORE it checks"
resolve="$(grep -n 'ceremony_python_prefer' "$SCRIPTS/preflight.sh" | head -1 | cut -d: -f1)"
check="$(grep -n "import \$m" "$SCRIPTS/preflight.sh" | head -1 | cut -d: -f1)"
if [ -n "$resolve" ] && [ -n "$check" ] && [ "$resolve" -lt "$check" ]; then
  P "the resolution is at line $resolve, the import check at $check"
else
  F "preflight checks the modules before resolving the interpreter (resolve=$resolve check=$check)"
fi

hdr "they pick the SAME interpreter, run the same way"
# The real assertion: source each script's resolution in a shell whose PATH does NOT have the
# venv, and compare what `command -v python3` becomes. Sourcing the whole of ceremony.sh is not
# possible here (it is a wizard), so the resolution block is extracted and run.
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
extract(){ sed -n '/^_cp="\$(cd "\$(dirname "\${BASH_SOURCE\[0\]}")\/\.\.\/\.\."/,/^unset _cp$/p' "$1"; }
for f in ceremony.sh preflight.sh; do
  extract "$SCRIPTS/$f" > "$T/$f.block"
  [ -s "$T/$f.block" ] || F "could not extract $f's resolution block"
done
if [ -s "$T/ceremony.sh.block" ] && [ -s "$T/preflight.sh.block" ]; then
  if diff -q "$T/ceremony.sh.block" "$T/preflight.sh.block" >/dev/null; then
    P "the two resolution blocks are byte-identical, so they cannot drift"
  else
    # Not fatal on its own — what matters is the interpreter they land on.
    P "the blocks differ textually; comparing the interpreter they select instead"
  fi
  # THE BLOCK MUST BE SOURCED FROM WHERE THE SCRIPT LIVES. It resolves tools/ceremony-python.sh
  # relative to ${BASH_SOURCE[0]}, so sourcing a copy out of a temp directory makes that path
  # wrong, the resolution silently does nothing, and both sides "agree" on the system python —
  # a comparison that passes no matter what either script does. The copies go next to the real
  # scripts, and the row first proves the resolution actually moved PATH.
  select_with(){ # select_with <block file placed in $SCRIPTS>
    PATH=/usr/bin:/bin bash -c 'source "$1"; command -v python3' _ "$1" 2>/dev/null
  }
  cp "$T/ceremony.sh.block"  "$SCRIPTS/.probe-ceremony.block"
  cp "$T/preflight.sh.block" "$SCRIPTS/.probe-preflight.block"
  a="$(select_with "$SCRIPTS/.probe-ceremony.block")"
  b="$(select_with "$SCRIPTS/.probe-preflight.block")"
  rm -f "$SCRIPTS/.probe-ceremony.block" "$SCRIPTS/.probe-preflight.block"
  # THE PROPERTY IS "CAN IT IMPORT THEM", NOT "IS IT DIFFERENT FROM /usr/bin/python3". An earlier
  # version inferred that selecting the bare interpreter meant the resolution had done nothing —
  # false wherever the wheels are installed system-wide, as they are on the CI runner and on the
  # air-gapped image this check is written for. It failed there for being right.
  if [ -z "$a" ] || [ -z "$b" ]; then
    F "one of the blocks selected no interpreter at all (ceremony='$a' preflight='$b')"
  elif [ "$a" != "$b" ]; then
    F "they select different interpreters: ceremony=$a preflight=$b"
  else
    P "from the same bare PATH both select $a"
    if "$a" -c 'import mnemonic, shamir_mnemonic' >/dev/null 2>&1; then
      P "…and that interpreter can import both modules, which is the property preflight reports on"
    else
      # Not a failure of the resolution: this host genuinely has the modules nowhere. preflight
      # must then FAIL at its import check, which the last section asserts it can still reach.
      P "(no interpreter on this host has both modules; preflight will fail at its import check, as it should)"
    fi
  fi
fi

hdr "a host with no venv still reaches the import check and fails THERE"
# prefer, not require: the resolution must not abort preflight on a host that has no venv at all,
# or the message telling the operator to bake the wheel into the image never prints.
grep -q 'ceremony_python_require' "$SCRIPTS/preflight.sh" \
  && F "preflight REQUIRES the venv; a host without one never reaches the import check that explains itself" \
  || P "preflight prefers rather than requires, so the import check still speaks"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
