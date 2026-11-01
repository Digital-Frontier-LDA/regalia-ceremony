#!/usr/bin/env python3
"""Refuse the real KMS site names in this public repository (regalia-fft).

Every tracked file is scanned (path and content, binary files byte for byte), in any case and inside
identifiers (`FOO_BAR`, `fooBar`, `foo2`, `foo.conf`). The one shape let through is a name glued to a
preceding lowercase letter, because English words contain one of them. The words are stored ROT13-encoded
so this file does not trip its own scan; neutral fixture names are alder, birch and cedar.

    python3 -I tools/no-site-names.py              # scan; exit 1 on any hit
    python3 -I tools/no-site-names.py --self-test  # the scan's own positive and negative controls
"""

import codecs
import os
import re
import subprocess
import sys

WORDS = [codecs.decode(w, "rot13") for w in ("yvfoba", "yvfobn", "cbegb", "pbvzoen")]
_ANY = "|".join(WORDS)
_CAPS = "|".join([w.capitalize() for w in WORDS] + [w.upper() for w in WORDS])
PATTERN = re.compile(r"(?<![a-zA-Z])(?i:%s)|(?<=[a-z])(?:%s)" % (_ANY, _CAPS))


def hits(text):
    return [m.group(0) for m in PATTERN.finditer(text)]


def self_test():
    a, _, b, c = WORDS
    bad = [p for p in (a, a.upper(), a.capitalize(), b + "2", b + ".boot.key", "%s_MAC" % c.upper(),
                       "from" + b.capitalize(), "x-%s-y" % c, 'station = "%s"' % c.capitalize()) if not hits(p)]
    good = [p for p in ("Trans" + b[:4] + "Opener", "trans" + b[:4] + "ation", "alder birch cedar") if hits(p)]
    scan_ok = scan_control()
    if bad or good or not scan_ok:
        print("self-test FAILED: missed %r, flagged %r, scan control %s" % (bad, good, "ok" if scan_ok else "FAILED"))
        return 1
    print("self-test OK")
    return 0


def scan_control():
    """A throwaway repository with a planted name in a path, a symlink target and a content line, and one
    clean file: the scan must find exactly the three."""
    import tempfile
    a, _, b, c = WORDS
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["git", "init", "-q", d], check=True)
        for rel, text in (("clean.txt", "nothing here\n"), ("content.txt", "x\n%s.boot.key\n" % b),
                          (os.path.join(a.capitalize(), "f"), "\n")):
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
            with open(os.path.join(d, rel), "w") as f:
                f.write(text)
        os.symlink("../%s/target" % c, os.path.join(d, "link"))
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        found = scan(d, minimum=0)
    got = sorted(x.split(":")[0].split(" (")[0] for x in found)
    return got == sorted(["%s/f" % a.capitalize(), "content.txt", "link"]) and any("(symlink target)" in x for x in found)


def scan(root, minimum=50):
    listed = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    paths = [p for p in listed.decode("utf-8").split("\0") if p]
    if len(paths) < minimum:
        print("git ls-files listed %d files: the scan would prove nothing" % len(paths))
        return 2
    found = ["%s (path): %s" % (rel, h) for rel in paths for h in hits(rel)]
    scanned = 0
    for rel in paths:
        path = os.path.join(root, rel)
        if os.path.islink(path):                   # a tracked symlink: its target is content too
            found.extend("%s (symlink target): %s" % (rel, h) for h in hits(os.readlink(path)))
            scanned += 1
            continue
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            found.extend("%s:%d: %s" % (rel, lineno, h) for h in hits(line))
    if minimum == 0:                               # the self-test's control: quiet, so no planted name reaches a log
        return found
    for line in found:
        print(line)
    print("%d files scanned, %d site-name hits" % (scanned, len(found)))
    return 1 if found else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(scan(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
