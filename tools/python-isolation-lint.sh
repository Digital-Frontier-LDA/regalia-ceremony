#!/usr/bin/env bash
# python-isolation-lint.sh — no shell script may run Python in a way that lets a file lying in the
# working directory, or a PYTHON* variable in the caller's environment, replace a module.
#
#   tools/python-isolation-lint.sh          # exit 1 and one line per finding
#
# WHY. `python3 -c …`, `python3 - …` (a program on standard input) and `python3 -m …` put the CURRENT
# DIRECTORY first on the module path. A secrets.py there is then the module the ceremony's generators
# import: measured on 2026-10-02, the recovery-key generator printed cccccccc-…-cccccccc with such a
# file beside it. PYTHONPATH does the same for every form. The rules, for every *.sh outside tests/:
#   python3 -c | - | -m      must carry -I (isolated: no working directory, no PYTHON* variables,
#                            no user site-packages)
#   python3 <a script>       must carry -E (the script's own directory stays first, so its sibling
#                            imports work; the caller's PYTHON* variables are ignored) or -I
# A comment line is not code. EXEMPT, each with its reason; an exemption is a debt, not a licence:
#   qubes/scripts/hsm-staging-ci.sh, hsm-host-role/files/commission-card.sh
#       their test harnesses supply a stand-in `cvc` module through PYTHONPATH
#       (test-hsm-staging-ci.sh, test-commission-card.sh). They are converted together with those
#       tests, where the emulator suite can show nothing else broke.
#   qubes/emulator/**
#       the emulator and its runner are test infrastructure: they run the suites, on purpose, from
#       the repository.
#   hardware/**   vendored firmware build material.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
# This linter is itself isolated.
python3 -I - <<'PY'
import re, subprocess, sys
EXEMPT = ("qubes/scripts/hsm-staging-ci.sh", "hsm-host-role/files/commission-card.sh")
files = subprocess.run(["git", "ls-files", "*.sh"], capture_output=True, text=True, check=True).stdout.split()
# An interpreter is `python3`, or, AT THE START OF A COMMAND, a quoted variable with one of the names
# these scripts use for one ("$py", "$PYBIN", "$PYTHON"...). A variable passed as an argument, or one
# that merely contains those letters ("$copyright"), is not an interpreter being run.
INTERP = (r'(?:(?<![\w./-])python3|(?:^|[;&|({!]|\$\(|\bthen\b|\bdo\b|\bif\b|\belse\b)\s*'
          r'"\$\{?(?:py|PY|_py|PYBIN|PYTHON|PYTHON3|python)\}?")')
cwd_first = re.compile(INTERP + r'\s+(?!(-[A-Za-z]*I[A-Za-z]*\s))((-[A-Za-z]+\s+)*)(-c\b|-\s|-$|-m\b)')
script = re.compile(INTERP + r'\s+(?!(-[A-Za-z]*[IE][A-Za-z]*\s))(?=(["\']?\$[\w{(]|["\']?[\w./-]*\.py\b))')
found = 0
for name in files:
    if name.startswith(("hardware/", "qubes/emulator/")) or "/tests/" in name or name in EXEMPT:
        continue
    for number, line in enumerate(open(name, encoding="utf-8", errors="replace"), 1):
        if line.lstrip().startswith("#"):
            continue
        if cwd_first.search(line):
            print("%s:%d: a program on the command line, on standard input or by module name, without -I: %s" % (name, number, line.strip()[:110])); found += 1
        elif script.search(line):
            print("%s:%d: a script by path without -E: %s" % (name, number, line.strip()[:110])); found += 1
if found:
    print("python-isolation-lint: %d finding(s). Add -I (or -E for a script by path); see this file's header." % found)
sys.exit(1 if found else 0)
PY
