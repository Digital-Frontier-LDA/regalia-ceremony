#!/usr/bin/env bash
# test-python-isolation.sh — a file in the working directory, or a PYTHON* variable, must not be what
# the ceremony's Python runs. Two halves: the static rule over every script (tools/python-isolation-
# lint.sh), and the generators and the PIN checker actually RUN beside planted modules.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
REPO="$(cd "$HERE/../../.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

hdr "the static rule holds for every script"
out="$("$REPO/tools/python-isolation-lint.sh" 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "no script runs python3 -c / - / -m without -I, or a script by path without -E" || F "findings: $(tail -6 <<< "$out")"

hdr "the rule bites: each form, written without its flag, is a finding"
mkdir -p "$T/repo/tools" "$T/repo/x"; cp "$REPO/tools/python-isolation-lint.sh" "$T/repo/tools/"
git -C "$T/repo" init -q
i=0
while IFS= read -r line; do
  i=$((i+1)); printf '#!/usr/bin/env bash\n%s\n' "$line" > "$T/repo/x/case.sh"; git -C "$T/repo" add -A >/dev/null
  out="$("$T/repo/tools/python-isolation-lint.sh" 2>&1)"; rc=$?
  [ "$rc" = 1 ] && grep -q "x/case.sh:2" <<< "$out" && P "a finding: $line" || F "not caught: $line"
done <<'CASES'
key="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
python3 - "$1" <<'PY'
python3 -m venv /opt/x
python3 "$HERE/tool.py" --flag
python3 tools/thing.py
x="$(printf '%s' "$a" | python3 -c "import sys")"
python3 -u -c 'print(1)'
"$py" -c 'import importlib'
"$PYBIN" - "$UART" <<'EOPY'
"${PYTHON}" "$CAPTURE" "$1"
CASES
while IFS= read -r line; do
  printf '#!/usr/bin/env bash\n%s\n' "$line" > "$T/repo/x/case.sh"; git -C "$T/repo" add -A >/dev/null
  out="$("$T/repo/tools/python-isolation-lint.sh" 2>&1)"; rc=$?
  [ "$rc" = 0 ] && P "not a finding: $line" || F "refused: $line ($out)"
done <<'CASES'
key="$(python3 -I -c 'import secrets; print(secrets.token_hex(16))')"
python3 -I - "$1" <<'PY'
python3 -E "$HERE/tool.py" --flag
python3 -I "$HERE/tool.py"
"$py" -I -c 'import importlib'
"$PYBIN" -E "$CAPTURE" "$1"
"$copy" -c 3 "$file"
cp -L "$copyright" "$root/licenses/x.copyright"
if imports "$py" "$module"; then :; fi
# python3 -c 'a comment is not code'
command -v python3 >/dev/null || exit 2
apt-get install -y python3 python3-pip
CASES

hdr "run beside planted modules: the generators and the PIN checker use the real ones"
# Modules that would be imported from the working directory or PYTHONPATH if the interpreter were not
# isolated. Each leaves a marker when imported; secrets also returns a KNOWN value.
mkdir -p "$T/planted"
printf 'open(%s, "w").close()\ndef token_bytes(n):\n    return b"\\x00" * n\ndef token_hex(n):\n    return "00" * n\ndef choice(s):\n    return s[0]\n' "'$T/secrets-imported'" > "$T/planted/secrets.py"
printf 'open(%s, "w").close()\nraise SystemExit(0)\n' "'$T/datetime-imported'" > "$T/planted/datetime.py"
gen(){ ( cd "$T/planted" && PYTHONPATH="$T/planted" bash -c 'source "$1" >/dev/null 2>&1; gen_secret "$2"' _ "$SCRIPTS/ceremony.sh" "$1" ); }
v="$(gen hex:32)";       [[ "$v" =~ ^[0-9A-F]{32}$ ]] && [ "$v" != "$(printf '0%.0s' {1..32})" ] && P "gen_secret hex:32 is not the planted module's value" || F "hex:32 from the planted module: $v"
v="$(gen digits:10)";    [[ "$v" =~ ^[0-9]{10}$ ]] && [ "$v" != 0000000000 ] && P "gen_secret digits:10 is not the planted module's value" || F "digits:10 from the planted module: $v"
v="$(gen paper:20)";     [[ "$v" =~ ^[A-Z2-9]{20}$ ]] && [ "$v" != AAAAAAAAAAAAAAAAAAAA ] && P "gen_secret paper:20 is not the planted module's value" || F "paper:20 from the planted module: $v"
v="$(gen recovery:256)"; [[ "$v" =~ ^([cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}$ ]] && [ "${v:0:8}" != cccccccc ] && P "gen_secret recovery:256 is not the planted module's value" || F "recovery:256 from the planted module: $v"
[ ! -e "$T/secrets-imported" ] && P "the planted secrets.py was never imported" || F "the planted secrets.py was imported"
# The PIN checker imports datetime and then reads a PIN from a file descriptor: a planted datetime.py
# would run inside the process that is about to hold the PIN.
why="$( cd "$T/planted" && PYTHONPATH="$T/planted" bash -c 'source "$1" >/dev/null 2>&1; weak_pin_reason 0101199012' _ "$SCRIPTS/ceremony.sh" )"
grep -q "contains a date" <<< "$why" && [ ! -e "$T/datetime-imported" ] && P "weak_pin_reason ran the real datetime (and still finds a date) beside a planted one" || F "the planted datetime.py was imported, or the checker changed: $why"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
