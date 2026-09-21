#!/usr/bin/env bash
# test-ceremony-python-resolver.sh — the interpreter search that six suites' results depend on.
#
# THE BUG THIS PINS. run-tests.sh hard-coded ~/.local/share/akash-hsm-venv; dev-image-bootstrap.sh
# creates /opt/dev-bin/regalia-venv. Nothing looked where the installer writes, so the tier ran
# against the system python3 and six suites failed with messages about missing modules. The
# resolver must (a) know every location, (b) accept a venv only when its interpreter can actually
# IMPORT the modules — a bin/python3 that exists is not evidence — and (c) refuse when none can.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RES="$HERE/../../../tools/ceremony-python.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ -r "$RES" ] || { echo "no ceremony-python.sh at $RES" >&2; exit 1; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# Two fake venvs: one whose interpreter imports the module, one whose interpreter does not.
mkvenv(){  # mkvenv <dir> <yes|no>
  mkdir -p "$1/bin"
  if [ "$2" = yes ]; then printf '#!/bin/sh\nexit 0\n' > "$1/bin/python3"
  else printf '#!/bin/sh\nexit 1\n' > "$1/bin/python3"; fi
  chmod +x "$1/bin/python3"
}
mkvenv "$T/good" yes
mkvenv "$T/bad" no
# A HOME with the historical layout, so the search covers the paths the repo used to hard-code.
mkdir -p "$T/home/.local/share"; mkvenv "$T/home/.local/share/akash-hsm-venv" yes

hdr "a venv is accepted on what it can IMPORT, not on existing"
out="$(HOME="$T/nohome" CEREMONY_VENV="$T/bad" bash -c ". '$RES'; ceremony_python_find definitely_not_a_module" 2>&1)"
case "$out" in
  "$T/bad/bin") F "a venv whose interpreter cannot import the module was accepted anyway";;
  *) P "an interpreter that fails the import is passed over";;
esac
out="$(HOME="$T/nohome" CEREMONY_VENV="$T/good" bash -c ". '$RES'; ceremony_python_find anything" 2>&1)"
[ "$out" = "$T/good/bin" ] && P "the one that imports it is chosen" || F "did not choose the good venv: $out"

hdr "every historical location is still searched"
out="$(HOME="$T/home" bash -c "unset CEREMONY_VENV; . '$RES'; ceremony_python_find anything" 2>&1)"
[ "$out" = "$T/home/.local/share/akash-hsm-venv/bin" ] \
  && P "the old hard-coded path .local/share/akash-hsm-venv is found with no CEREMONY_VENV set" \
  || F "the historical path was not searched: $out"

hdr "under sudo, the INVOKING user's venv is searched too"
# $HOME is /root under sudo. Without SUDO_USER the developer's venv is unreachable and the tier
# runs against the system interpreter — which is exactly how this failed on the qualification box.
out="$(HOME="$T/nohome" SUDO_USER="$(id -un)" bash -c "unset CEREMONY_VENV; . '$RES'; declare -f ceremony_python_find" 2>&1)"
grep -q 'SUDO_USER' <<<"$out" && P "the search consults SUDO_USER's home" || F "SUDO_USER is not consulted"

hdr "when nothing can import them, it REFUSES and says how to build one"
out="$(HOME="$T/nohome" bash -c "unset CEREMONY_VENV; . '$RES'; ceremony_python_require definitely_not_a_module" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "require fails (exit $rc) rather than continuing against a python that cannot run the suites" \
  || F "require returned 0 with no usable interpreter — the tier would report environment failures as code failures"
grep -q 'pip install --require-hashes -r qubes/requirements.txt' <<<"$out" \
  && P "…and the refusal carries the exact command that fixes it" || F "the refusal does not say how to fix it"
grep -q '/opt/dev-bin/regalia-venv' <<<"$out" \
  && P "…naming the path the installer actually creates" || F "the refusal does not name the installer's venv"
out="$(HOME="$T/nohome" bash -c "unset CEREMONY_VENV; . '$RES'; ceremony_python_prefer definitely_not_a_module; echo rc=\$?" 2>&1)"
grep -q 'rc=0' <<<"$out" && P "prefer stays quiet and succeeds (callers with their own errors keep theirs)" \
  || F "prefer failed: $out"

hdr "the tier itself refuses rather than running against the wrong interpreter"
grep -q 'ceremony_python_require' "$HERE/../run-tests.sh" \
  && P "run-tests.sh requires the pinned dependencies before it runs a suite" \
  || F "run-tests.sh does not require them — it can still fall through to the system python3"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
