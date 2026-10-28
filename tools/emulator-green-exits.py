#!/usr/bin/env python3
"""emulator-green-exits.py — every way an emulator test can end green without running, found by construction.

    python3 -I tools/emulator-green-exits.py --allow ALLOWLIST FILE...

A test that exits 0 because a tool is missing is green in CI for a test that never ran (#166). Matching the spellings
of such a skip (`{ echo SKIP; exit 0; }`, `echo "(skipping: ...)"; exit 0`) misses the next one written another way:
>&2, printf, single quotes, `|| exit 0`, an if-block, a bare `exit`. So this does not look for skips at all. It reads
each file as bash does, with quoted strings, heredoc bodies and comments set aside (a stub's `printf 'exit 0'` is not
the test's exit), and reports EVERY `exit` whose status is not a non-zero literal: `exit 0`, a bare `exit`,
`exit $rc`, `exit $?`, `exit 256` (0 to the shell), and a trap or eval whose string takes one (`trap 'exit 0' EXIT`
turns every later `exit 1` green; `bash -c 'exit 0'` is not reported: it ends only the child shell). Three are not reported:
  - the file's last line of code: how a test ends, by definition not before it ran;
  - the body of skip_dep(), the one way to skip, which REQUIRE_EMULATOR_DEPS=1 turns into a failure;
  - a line the allowlist names, by file and exact text, with its reason.
Each entry excuses ONE line: a second line of the same text needs its own entry. An entry that matches no line is
reported too: a stale entry would excuse the next line written to match it.
A file that ends inside a string or a heredoc is refused (exit 2): a file read wrongly must not pass as one with no
exits. `return` is not reported: no emulator test is sourced, and at the top level of an executed script bash prints
an error for `return` and runs on (measured, #167). Not seen: a command NAME quoted (`"exit" 0`) or built from a
variable (`$cmd 0`), and a non-final `exec` (its status is the command's, so it is not green by itself).

A Python suite (FILE ending .py) is read by tokenize instead and reports a unittest skip outside emulator_deps.py
(skipTest, skipUnless, skipIf, skip, SkipTest) and sys.exit(0), sys.exit() or os._exit(0) (#173).

Exit 0: nothing reported. 1: findings (printed FILE:LINE: TEXT). 2: a file or the allowlist could not be read.

ALLOWLIST: one entry per line, `FILE<TAB>TEXT<TAB>REASON`, FILE the test's basename, TEXT the line exactly as it
stands with its indentation stripped; blank lines and lines starting with # are ignored. REASON must not be empty.
"""
import collections
import io
import os
import re
import sys
import tokenize

EXIT = re.compile(r"(?<![\w$.-])exit(?![\w-])[ \t]*([^\s;&|)}]*)")
# trap and eval run a string as code IN THIS SHELL, so an exit in it ends the test (bash -c or sh -c does not: its
# exit ends only the child, measured). The string is set aside with the other strings, so it is read from the source.
RUNS_STRING = re.compile(r"(?<![\w$.-])(?:trap|eval)(?![\w-])")
STRING_ARG = re.compile(r"(?<![\w$.-])(?:trap|eval)[ \t]+(?:--[ \t]+)?(?:'([^']*)'|\"((?:[^\"\\]|\\.)*)\"|(\S+))")


def failing(status):
    """A status that cannot be green: a literal 1..255 (exit 256 is 0 to the shell, 7e)."""
    return re.fullmatch(r"[1-9][0-9]{0,2}", status) is not None and int(status) <= 255


def green_in(code):
    """Does this code take an exit that can be green?"""
    return any(not failing(m.group(1)) for m in EXIT.finditer(code))
SKIP_DEP = re.compile(r"^[ \t]*skip_dep\(\)[ \t]*\{")


def code_lines(text):
    """(lineno, code) per line, with quoted strings, heredoc bodies and comments blanked out.

    Quoting nests as bash's does: "$( ... )" inside double quotes is code again, with quotes of its own. Raises
    ValueError for a file that ends inside a string or a heredoc."""
    out, heredocs = [], []
    stack = [["code", 0]]                   # each [kind, paren depth]; kind is code, dq, sq or ansi ($'...')
    for no, line in enumerate(text.split("\n"), 1):
        if heredocs:
            term, strip = heredocs[0]
            if (line.lstrip("\t") if strip else line) == term:
                heredocs.pop(0)
            out.append((no, ""))
            continue
        code, i = [], 0
        while i < len(line):
            c, top = line[i], stack[-1]
            if top[0] == "sq":
                if c == "'":
                    stack.pop()
                i += 1
                continue
            if top[0] == "ansi":
                if c == "\\":
                    i += 2
                    continue
                if c == "'":
                    stack.pop()
                i += 1
                continue
            if top[0] == "dq":
                if c == "\\":
                    i += 2
                    continue
                if line.startswith("$(", i) and not line.startswith("$((", i):
                    stack.append(["code", 1])
                    i += 2
                    continue
                if c == '"':
                    stack.pop()
                i += 1
                continue
            if c == "\\":
                nxt = line[i + 1:i + 2]
                code.append(" " + (nxt if (nxt.isalnum() or nxt == "_") else " "))   # \exit runs exit (7e)
                i += 2
                continue
            if line.startswith("$'", i):
                stack.append(["ansi", 0])
                code.append("  ")
                i += 2
                continue
            if c == "'":
                stack.append(["sq", 0])
            elif c == '"':
                stack.append(["dq", 0])
            elif c == "#" and (i == 0 or line[i - 1] in " \t;&|()"):     # a word start: never ${#x} (7e)
                break
            elif line.startswith("$(", i) and len(stack) > 1:
                stack.append(["code", 1])
                code.append("$(")
                i += 2
                continue
            elif c == "(" and len(stack) > 1:
                top[1] += 1
            elif c == ")" and len(stack) > 1:
                top[1] -= 1
                if top[1] == 0:
                    stack.pop()
            else:
                m = re.match(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2", line[i:])
                if m and not line.startswith("<<<", i) and not (i and line[i - 1] == "<"):
                    heredocs.append((m.group(3), m.group(1) == "-"))
                    code.append(" " * m.end())
                    i += m.end()
                    continue
            code.append(c)
            i += 1
        out.append((no, "".join(code)))
    if heredocs:
        raise ValueError("the file ends inside the heredoc %s" % heredocs[0][0])
    if len(stack) > 1:
        raise ValueError("the file ends inside a %s context" % stack[-1][0])
    return out


def green_exits(text):
    """(lineno, source line stripped) of every exit that can be green before the test ran."""
    source = text.split("\n")
    lines = code_lines(text)
    last = max((no for no, code in lines if code.strip()), default=0)
    found, in_skip_dep = [], False
    for no, code in lines:
        if not in_skip_dep and SKIP_DEP.match(code):
            in_skip_dep = True
        if in_skip_dep:
            if code.strip().endswith("}"):
                in_skip_dep = False
            continue
        if no == last:
            continue
        runs_green = False
        if RUNS_STRING.search(code):
            for m in STRING_ARG.finditer(source[no - 1]):
                runs_green = runs_green or green_in(next(g for g in m.groups() if g is not None))
        if green_in(code) or runs_green:            # trap 'exit 0' EXIT turns every later exit 1 green (7e)
            found.append((no, source[no - 1].strip()))
    return found


PY_SKIPS = {"skipTest", "skipUnless", "skipIf", "skip", "SkipTest"}
PY_HELPER = "emulator_deps.py"


def python_green_exits(text):
    """(lineno, source line stripped) of a Python suite's ways to end green without running: a unittest skip outside
    emulator_deps (whose needs/skip_dep fail under REQUIRE_EMULATOR_DEPS=1, #173), and sys.exit(0), sys.exit() or
    os._exit(0). Read by tokenize, so strings (a stub script written out) and comments are not code. A skip is ANY name
    token in PY_SKIPS, after a dot or not, so `from unittest import SkipTest` and a bare `@skip(...)` are reported too
    (7e on #175), the import line with them. Not seen: an early `return` in a test, which passes it without running
    the rest. Raises ValueError for a file that does not tokenize."""
    source = text.split("\n")
    try:
        tokens = [t for t in tokenize.generate_tokens(io.StringIO(text).readline)
                  if t.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT)]
    except (tokenize.TokenError, IndentationError, SyntaxError) as error:
        raise ValueError("it does not tokenize (%s)" % error) from None
    found = []
    for i, t in enumerate(tokens):
        after_dot = i > 0 and tokens[i - 1].string == "."
        hit = t.type == tokenize.NAME and t.string in PY_SKIPS
        if t.type == tokenize.NAME and after_dot and t.string in ("exit", "_exit") and i > 1 and tokens[i - 2].string in ("sys", "os"):
            args = [x.string for x in tokens[i + 1:i + 4]]
            hit = args[:2] == ["(", ")"] or args == ["(", "0", ")"]
        if hit and (t.start[0], source[t.start[0] - 1].strip()) not in found:
            found.append((t.start[0], source[t.start[0] - 1].strip()))
    return found


def read_allowlist(path):
    allowed = collections.Counter()
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not all(p.strip() for p in parts):
                raise ValueError("allowlist line %d is not FILE<TAB>TEXT<TAB>REASON" % no)
            allowed[(parts[0], parts[1])] += 1
    return allowed


def main(argv):
    args = argv[1:]
    allowed = collections.Counter()
    try:
        if len(args) >= 2 and args[0] == "--allow":
            allowed = read_allowlist(args[1])
            args = args[2:]
        if not args:
            raise ValueError("no files given")
        findings = []
        for path in args:
            with open(path, encoding="utf-8", errors="strict") as f:
                text = f.read()
            try:
                if path.endswith(".py"):
                    exits = [] if os.path.basename(path) == PY_HELPER else python_green_exits(text)
                else:
                    exits = green_exits(text)
            except ValueError as error:
                raise ValueError("%s: %s" % (path, error)) from None
            for no, line in exits:
                key = (os.path.basename(path), line)
                if allowed[key] > 0:
                    allowed[key] -= 1
                else:
                    findings.append("%s:%d: %s" % (path, no, line))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print("emulator-green-exits: cannot judge: %s" % error, file=sys.stderr)
        return 2
    scanned = {os.path.basename(p) for p in args}
    for key in sorted(k for k, left in allowed.items() if left > 0):
        if key[0] in scanned:
            findings.append("%s: allowlisted line not found (stale entry): %s" % key)
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
