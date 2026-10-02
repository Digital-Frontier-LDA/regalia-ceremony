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
out="$("$REPO/tools/python-isolation-lint.sh" --list 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "no script runs Python un-isolated: a program on the command line, standard input or by module name without -I; a script by path without -Es; a Python program through its #! line" || F "findings: $(tail -6 <<< "$out")"
# A linter that checked nothing also exits 0. It must have read the scripts that matter.
for s in qubes/scripts/ceremony.sh qubes/scripts/go-nogo.sh qubes/scripts/escrow/pin-escrow.sh hsm-host-role/files/commission-card.sh qubes/scripts/hsm-staging-ci.sh tools/ceremony-python.sh; do
  grep -qx "$s" <<< "$out" && P "checked: $s" || F "the linter did not read $s"
done
n="$(grep -c '\.sh$' <<< "$out")"; [ "$n" -ge 50 ] && P "$n scripts checked" || F "only $n scripts checked"

hdr "the rule bites: each form, written without its flag, is a finding"
mkdir -p "$T/repo/tools" "$T/repo/x"; cp "$REPO/tools/python-isolation-lint.sh" "$T/repo/tools/"
git -C "$T/repo" init -q
verdict(){ printf '#!/usr/bin/env bash\n%b\n' "$1" > "$T/repo/x/case.sh"; git -C "$T/repo" add -A >/dev/null
  out="$("$T/repo/tools/python-isolation-lint.sh" 2>&1)"; rc=$?; }
while IFS= read -r line; do
  verdict "$line"
  [ "$rc" = 1 ] && grep -q "x/case.sh:" <<< "$out" && P "a finding: $line" || F "not caught: $line"
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
python3 -X utf8 -c 'print(1)'
python3 -u tools/thing.py
python3 /tmp/helper
python3 -W ignore "$HERE/tool.py"
python3 -uB - <<'PY'
python3 -E "$HERE/tool.py"
python3 -E -c 'print(1)'
python3 -uc 'print(1)'
python3 -mvenv /opt/x
/usr/bin/python3 -c 'print(1)'
/opt/dev-bin/regalia-venv/bin/python -c 'import cvc'
"$VENV/bin/python3" "$HERE/tool.py"
python3.13 -c 'print(1)'
"${HSM_PYSERIAL_PYTHON:-python3}" -c 'import serial'
timeout 5 "$PYBIN" -c 'import serial'
python3 <<'EOF'
python3 < program.txt
cat program.txt | python3
printf '%s' "$program" | python3 > out.txt
python3 \\\n  -c 'print(1)'
python3 \\\n  "$HERE/tool.py"
"$HERE/ceremony-teardown.py" --workdir "$WORK"
if ! out="$("$HERE/preflight-environment.py" 2>&1)"; then :; fi
./tools/thing.py --flag
python3 -c 'import cvc'   # isolation-exempt:
CASES
while IFS= read -r line; do
  verdict "$line"
  [ "$rc" = 0 ] && P "not a finding: $line" || F "refused: $line ($(head -1 <<< "$out"))"
done <<'CASES'
key="$(python3 -I -c 'import secrets; print(secrets.token_hex(16))')"
python3 -I - "$1" <<'PY'
python3 -Es "$HERE/tool.py" --flag
python3 -E -s "$HERE/tool.py"
python3 -I "$HERE/tool.py"
"$py" -I -c 'import importlib'
"$PYBIN" -Es "$CAPTURE" "$1"
python3 -X utf8 -I -c 'print(1)'
python3 -u -Es tools/thing.py
python3 -IB - <<'PY'
/usr/bin/python3 -I -c 'print(1)'
printf '%s' "$program" | python3 -I > out.txt
python3 \\\n  -I -c 'print(1)'
python3 -c 'import cvc'   # isolation-exempt: its harness supplies cvc through PYTHONPATH
echo "python3 is required for the seed backup"
warn "then: zbarimg --raw photo.jpg | payload-qr.py --verify-scan payload.age"
"$copy" -c 3 "$file"
cp -L "$copyright" "$root/licenses/x.copyright"
if imports "$py" "$module"; then :; fi
# python3 -c 'a comment is not code'
command -v python3 >/dev/null || exit 2
py="$(command -v python3 2>/dev/null)" || return 1
apt-get install -y python3 python3-pip
CASES
# It says so when it could not run, instead of reporting "no findings".
out="$(cd "$T" && mkdir -p notgit/tools && cp "$REPO/tools/python-isolation-lint.sh" notgit/tools/ && GIT_CEILING_DIRECTORIES="$T" notgit/tools/python-isolation-lint.sh 2>&1)"; rc=$?
[ "$rc" = 2 ] && grep -q "nothing was checked" <<< "$out" && P "outside a git tree it exits 2 and says nothing was checked" || F "outside a git tree: rc=$rc $out"

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

hdr "a script run by path ignores the user's site-packages too (-E alone would not)"
# site.py reads PYTHONUSERBASE whatever -E says, and a .pth file there runs code at start-up: measured,
# `python3 -E script.py` printed PLANTED and a zero check value. -s is what stops it.
ub="$T/userbase"; sp="$ub/lib/python$(python3 -I -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"; mkdir -p "$sp"
printf 'import os; open(%s, "w").close()\n' "'$T/pth-ran'" > "$sp/x.pth"
key="$(printf 'E5%.0s' {1..16})"
clean="$(python3 -I "$SCRIPTS/escrow/pin_escrow_mac.py" kcv <<< "$key" 2>/dev/null)" || clean="$(python3 -Es "$SCRIPTS/escrow/pin_escrow_mac.py" kcv <<< "$key")"
( PYTHONUSERBASE="$ub" python3 -E "$SCRIPTS/escrow/pin_escrow_mac.py" kcv <<< "$key" >/dev/null 2>&1 ); [ -e "$T/pth-ran" ] && P "the premise: with -E alone, a .pth under PYTHONUSERBASE runs" || F "the premise does not hold on this Python: -E alone already ignored the user site"
rm -f "$T/pth-ran"
got="$(PYTHONUSERBASE="$ub" python3 -Es "$SCRIPTS/escrow/pin_escrow_mac.py" kcv <<< "$key")"
[ ! -e "$T/pth-ran" ] && [ -n "$got" ] && [ "$got" = "$clean" ] && P "with -Es it does not, and the check value is the clean one" || F "a user-site .pth ran under -Es, or the value changed: $got / $clean"
grep -q 'python3 -Es "$HERE/pin_escrow_mac.py"' "$SCRIPTS/escrow/pin-escrow.sh" && grep -q 'python3 -Es "$HERE/ceremony-teardown.py"' "$SCRIPTS/ceremony.sh" \
  && grep -q 'python3 -Es "$HERE/preflight-environment.py"' "$SCRIPTS/go-nogo.sh" \
  && P "the escrow MAC tool, the teardown verdict and the profile verdict are started with -Es (the last two used to run through their #! line)" || F "a verdict or MAC tool is not started with -Es"
# sle4442-manager holds a share and the card PSC; it is a Python program on PATH with a #! line.
mkdir -p "$T/sle"; printf '#!/usr/bin/env python3\nimport sys\nprint("ran", sys.flags.ignore_environment, sys.flags.no_user_site)\n' > "$T/sle/sle4442-manager"; chmod +x "$T/sle/sle4442-manager"
out="$(PATH="$T/sle:$PATH" bash -c 'source "$1" >/dev/null 2>&1; sle4442 info' _ "$SCRIPTS/ceremony.sh" 2>&1)"
[ "$out" = "ran 1 1" ] && P "sle4442-manager, a Python program, is started through its interpreter with -Es" || F "sle4442-manager was not isolated: $out"
printf '#!/usr/bin/env bash\necho "stand-in $*"\n' > "$T/sle/sle4442-manager"
out="$(PATH="$T/sle:$PATH" bash -c 'source "$1" >/dev/null 2>&1; sle4442 info' _ "$SCRIPTS/ceremony.sh" 2>&1)"
[ "$out" = "stand-in info" ] && P "a stand-in that is not Python (the suites' model) still runs as it is" || F "a non-Python sle4442-manager did not run: $out"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
