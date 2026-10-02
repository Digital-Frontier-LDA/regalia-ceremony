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
# An interpreter is any word whose name is python, python3, python3.N or pypy3, with or without a
# directory, and a variable, quoted or not, whose name says it holds one (py, PYBIN, KEK_PY, PYTHON_BIN…).
#
# THIS IS A GUARD FOR THE FORMS THESE SCRIPTS USE, NOT A PROOF. A shell line can start Python in ways a
# line-by-line reading does not see: `eval "$CMD"`, a wrapper function, an interpreter in a variable
# with another name, a script with no .py in its name, `find -exec`. The tests beside it RUN the
# generators, the PIN checker and the chip-card tool next to planted modules; that is the proof for those.
#
# EXEMPTIONS are per CALL, never per file: one un-isolated call on a line, with the marker
# "isolation-exempt:" and its reason in a trailing # comment or in the comment line directly above.
# A marker inside a quoted string, or on a line with two un-isolated calls, exempts nothing.
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

# WHAT COUNTS AS AN INTERPRETER:
#   python3, python3.N, pypy3 or python as a word; any of them behind a directory (/usr/bin/python3,
#   "$VENV/bin/python"); ${X:-python3}; and a variable, quoted or not, WHEREVER it stands as a whole
#   word, whose name says it is one: py, PY, PYBIN, KEK_PY, PYTHON, PYTHON_BIN, python_bin, interp …
WORD = r'(?<![\w./$-])(?:python3(?:\.\d+)?|pypy3|python)(?![\w.-])["\'}]?'
PATHED = r'["\']?[\w$/{}.:-]*/(?:python(?:3(?:\.\d+)?)?|pypy3)(?![\w.-])["\'}]?'
VARIABLE = r'(?<![\w$])"?\$\{?(?:\w*_)?(?:py|PY|pybin|PYBIN|python3?|PYTHON3?|interp|INTERP)(?:_\w+)?(?::-[^}]*)?\}?"?(?![\w.])'
INTERP = re.compile("(?P<word>%s)|(?P<pathed>%s)|(?P<variable>%s)" % (WORD, PATHED, VARIABLE))
# A Python program started through its "#!" line: a path (with a directory or a variable) ending in
# .py, as the first word of a command, also behind VAR=value, timeout N, sudo, nohup or env.
START = r'(?:^|[;&({!]|\|\||&&|\$\(|\bthen\b|\bdo\b|\bif\b|\belse\b)\s*(?:!\s*)?'
ASSIGN = r'\w+=(?:[\w./:-]*|"[^"$]*")\s+'       # VAR=value before a command; not VAR="$(…)"
PREFIX = r'(?:' + ASSIGN + r'|timeout\s+\S+\s+|sudo\s+|nohup\s+|env\s+(?:-\S+\s+\S+\s+|' + ASSIGN + r')*)*'
COMMAND = re.compile(START + PREFIX + r'(?:exec\s+)?$')
DIRECT = re.compile(START + PREFIX + r'"?(?:\$[\w{(]|\.{0,2}/)[\w$/{}.-]*\.py"?(?=\s|$|\)|;)')


def judge(rest, piped, loose):
    """What follows the interpreter on the (joined) line -> a finding, or None. `piped`: it is the
    right-hand side of a pipe. `loose`: the interpreter is the bare word `python`, or a variable
    that is not the first word of a command; only an inline program or an evident script counts."""
    words = rest.split()
    flags, i, inline = "", 0, False
    while i < len(words) and len(words[i]) > 1 and words[i].startswith("-"):
        word = words[i]
        if word == "--":
            i += 1
            break
        if word.startswith("--"):
            break
        if word[:2] in ("-W", "-X"):                    # an option with a value, attached or the next word
            i += 2 if len(word) == 2 else 1
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
    bare = word.strip("\"');")
    if loose:
        script = bare.endswith(".py") or re.search(r"(?i)^\$\{?\w*py\}?$", bare)
    else:
        # A script by path: something with a directory, a variable, or a .py name. A plain word after
        # "python3" in prose or a package list ("python3 python3-pip", "python3 is required") is not one.
        script = "/" in bare or bare.startswith("$") or bare.endswith(".py")
    if script:
        return None if ("I" in flags or ("E" in flags and "s" in flags)) else "a script by path without -E and -s"
    return None


def marker(line, above):
    """The reason of an exemption that applies to this line, or None. It must be a COMMENT: after a #
    at the end of the line (not inside a quoted string), or the comment line directly above."""
    trailing = re.search(r'(?:^|\s)#(?P<comment>[^#]*isolation-exempt:(?P<reason>.*))$', line)
    if trailing:
        code = line[:trailing.start()]
        if code.count('"') % 2 == 0 and code.count("'") % 2 == 0:
            return trailing.group("reason").strip(), code
    if above.lstrip().startswith("#") and "isolation-exempt:" in above:
        return above.split("isolation-exempt:", 1)[1].strip(), line
    return None, line


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
        reason, code = marker(line, lines[start - 1] if start else "")
        problems = []
        for match in INTERP.finditer(code):
            # The bare word `python` also turns up in prose, and a variable also stands as an ARGUMENT
            # (`imports "$py" "$module"`): for those, only an inline program or an evident script
            # counts, unless the variable is the first word of a command.
            loose = match.group(0).strip("\"'}") == "python" or (
                match.group("variable") is not None and not COMMAND.search(code[:match.start()]))
            what = judge(code[match.end():], bool(re.search(r"(?<!\|)\|\s*$", code[:match.start()])), loose)
            if what:
                problems.append(what)
        if DIRECT.search(code):
            problems.append("a Python program run through its #! line (start it as python3 -Es <path>)")
        if reason is not None and problems:
            # ONE exemption covers ONE call. A marker on a line with two un-isolated calls, or without
            # its reason, exempts nothing.
            if len(problems) == 1 and len(reason) >= 12:
                continue
            problems.append("an exemption covers one call and states its reason; this one does not")
        for what in problems:
            print("%s:%d: %s: %s" % (name, start + 1, what, line.strip()[:110])); found += 1
if "--list" in sys.argv[1:]:
    print("\n".join(visited))
print("python-isolation-lint: %d script(s) checked, %d finding(s)%s" % (
    len(visited), found, ". Add -I, or -Es for a script by path; see this file's header." if found else ""))
sys.exit(1 if found else 0)
PY
