#!/usr/bin/env bash
# python-isolation-lint.sh — no shell script may run Python in a way that lets a file lying in the
# working directory, a PYTHON* variable in the caller's environment, or the user's own site-packages
# replace a module.
#
#   tools/python-isolation-lint.sh          # exit 1 and one line per finding; exit 2 if it could not run
#
# WHY. `python3 -c …`, `python3 - …`, a program piped or redirected into `python3`, and `python3 -m …`
# put the CURRENT DIRECTORY first on the module path. A secrets.py there is then the module the
# ceremony's generators import: measured on 2026-10-02, the recovery-key generator printed
# cccccccc-…-cccccccc with such a file beside it. PYTHONPATH does the same for every form, and so does
# the user's site-packages (a .pth file there runs code at start-up, and PYTHONUSERBASE says where
# "there" is). What each flag stops, measured on Python 3.13:
#   -I   everything: no working directory, no script directory, no PYTHON* variables, no user site
#   -E   the PYTHON* variables only; user site and its .pth files still load, hence -s with it
#   -s   user site-packages
# THE RULES, for every tracked *.sh outside the test trees (a comment line is not code; a line
# continued with a backslash is one line):
#   a program on the command line, on standard input or by module name     must carry -I
#   a script run by path  (python3 x.py, python3 "$HERE/x.py")             must carry -E and -s, or -I
#   a Python program run through its "#!" line  ("$HERE/x.py" as a command)  is a finding: nothing on
#        its command line says how Python runs. Start it as  python3 -Es "$HERE/x.py".
# An interpreter is any word whose name is python, python3 or python3.N, with or without a directory,
# and a quoted variable at the start of a command with one of the names these scripts use.
#
# EXEMPTIONS are per LINE, never per file: the line carries the marker "isolation-exempt:" followed by
# its reason (on the line itself, or on the comment line directly above it). An exemption is a debt.
# NOT COVERED, and said so rather than implied: files that are not *.sh (the salt state, workflow YAML,
# commands quoted in documents), `eval "$CMD"`, and Python that starts Python (sys.executable).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
# This linter is itself isolated.
python3 -I - "$@" <<'PY'
import re, subprocess, sys
TEST_TREES = ("hardware/", "qubes/emulator/")     # vendored firmware material; the emulator and every test suite
try:
    listed = subprocess.run(["git", "ls-files", "-z", "*.sh"], capture_output=True, check=True).stdout
except (OSError, subprocess.CalledProcessError) as failure:
    print("python-isolation-lint: cannot list the tracked scripts (%s): nothing was checked" % failure)
    sys.exit(2)
files = [name.decode("utf-8", "surrogateescape") for name in listed.split(b"\0") if name]

# python3 or python3.N as a word; python, python3 or python3.N behind a directory
# (/usr/bin/python3, "$VENV/bin/python"); ${X:-python3}; or a quoted variable, at the start of a
# command, with one of the names these scripts give an interpreter.
INTERP = re.compile(
    r'(?:(?<![\w./$-])python3(?:\.\d+)?(?![\w.-])["\'}]?'
    r'|["\']?[\w$/{}.:-]*/python(?:3(?:\.\d+)?)?(?![\w.-])["\'}]?'
    r'|(?:^|[;&|({!]|\$\(|\bthen\b|\bdo\b|\bif\b|\belse\b|\btimeout\s+\S+|\bsudo\b|\bexec\b)\s*'
    r'"\$\{?(?:py|PY|_py|PYBIN|KEK_PY|PYTHON|PYTHON3|python|interp|HSM_PYSERIAL_PYTHON)\b[^"]*")')
# A Python program started through its "#!" line: a path (with a directory or a variable) ending in
# .py, as the FIRST word of a command.
DIRECT = re.compile(r'(?:^|[;&({!]|\|\||&&|\$\(|\bthen\b|\bdo\b|\bif\b|\belse\b)\s*(?:!\s*)?"?(?:\$[\w{(]|\.{0,2}/)[\w$/{}.-]*\.py"?(?=\s|$|\))')
TAKES_VALUE = ("-X", "-W")      # options whose value is the NEXT word


def judge(rest, piped):
    """What follows the interpreter on the (joined) line -> a finding, or None. `piped`: the interpreter
    is the right-hand side of a pipe."""
    words = rest.split()
    flags, i, inline = "", 0, False
    while i < len(words) and len(words[i]) > 1 and words[i].startswith("-") and not words[i].startswith("--"):
        word = words[i]
        if word in TAKES_VALUE:
            i += 2
            continue
        letters = word[1:]
        # -c and -m end the options, also when bundled (-uc, -mvenv, -Ic)
        cut = min([letters.index(ch) for ch in "cm" if ch in letters] or [len(letters)])
        flags += letters[:cut]
        if cut < len(letters):
            inline = True
            break
        i += 1
    word = words[i] if i < len(words) else ""
    if not inline:
        if word == "-" or word.startswith("<"):
            inline = True                               # python3 - …, python3 <<EOF, python3 < file
        elif piped and (not word or re.match(r"^[0-9]*[>|;&)]", word)):
            inline = True                               # … | python3   (the program arrives on the pipe)
    if inline:
        return None if "I" in flags else "a program on the command line, on standard input or by module name, without -I"
    if not word or re.match(r"^[0-9]*[<>|&;)]", word):  # no program on this line: `command -v python3 >/dev/null`
        return None
    bare = word.strip("\"'")
    # A script by path: something with a directory, a variable, or a .py name. A plain word after
    # "python3" in prose or in a package list ("python3 python3-pip", "python3 is required") is not one.
    if "/" in bare or bare.startswith("$") or bare.endswith(".py"):
        return None if ("I" in flags or ("E" in flags and "s" in flags)) else "a script by path without -E and -s"
    return None


SELF = "tools/python-isolation-lint.sh"
found, visited = 0, []
for name in files:
    if name.startswith(TEST_TREES) or name == SELF:
        continue
    try:
        text = open(name, encoding="utf-8", errors="replace").read()
    except OSError as failure:
        print("python-isolation-lint: cannot read %s (%s): nothing was checked" % (name, failure)); sys.exit(2)
    visited.append(name)
    lines = text.split("\n")
    number = 0
    while number < len(lines):
        start, line = number, lines[number]
        while line.rstrip().endswith("\\") and number + 1 < len(lines):   # a continued line is one line
            number += 1
            line = line.rstrip()[:-1] + " " + lines[number].lstrip()
        number += 1
        if line.lstrip().startswith("#"):
            continue
        above = lines[start - 1] if start else ""
        if "isolation-exempt:" in line or (above.lstrip().startswith("#") and "isolation-exempt:" in above):
            marker = (line if "isolation-exempt:" in line else above).split("isolation-exempt:", 1)[1].strip()
            if len(marker) < 12:
                print("%s:%d: an exemption without its reason" % (name, start + 1)); found += 1
            continue
        for match in INTERP.finditer(line):
            what = judge(line[match.end():], bool(re.search(r"(?<!\|)\|\s*$", line[:match.start()])))
            if what:
                print("%s:%d: %s: %s" % (name, start + 1, what, line.strip()[:110])); found += 1
        if DIRECT.search(line):
            print("%s:%d: a Python program run through its #! line (start it as python3 -Es <path>): %s" % (name, start + 1, line.strip()[:110])); found += 1
if "--list" in sys.argv[1:]:
    print("\n".join(visited))
print("python-isolation-lint: %d script(s) checked, %d finding(s)%s" % (
    len(visited), found, ". Add -I, or -Es for a script by path; see this file's header." if found else ""))
sys.exit(1 if found else 0)
PY
