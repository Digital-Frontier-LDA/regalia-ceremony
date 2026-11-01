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

WORDS = [codecs.decode(w, "rot13") for w in ("yvfoba", "cbegb", "pbvzoen")]
_ANY = "|".join(WORDS)
_CAPS = "|".join([w.capitalize() for w in WORDS] + [w.upper() for w in WORDS])
PATTERN = re.compile(r"(?<![a-zA-Z])(?i:%s)|(?<=[a-z])(?:%s)" % (_ANY, _CAPS))


def hits(text):
    return [m.group(0) for m in PATTERN.finditer(text)]


def self_test():
    a, b, c = WORDS
    bad = [p for p in (a, a.upper(), a.capitalize(), b + "2", b + ".boot.key", "%s_MAC" % c.upper(),
                       "from" + b.capitalize(), "x-%s-y" % c, 'station = "%s"' % c.capitalize()) if not hits(p)]
    good = [p for p in ("Trans" + b[:4] + "Opener", "trans" + b[:4] + "ation", "alder birch cedar") if hits(p)]
    if bad or good:
        print("self-test FAILED: missed %r, flagged %r" % (bad, good))
        return 1
    print("self-test OK")
    return 0


def scan(root):
    listed = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    paths = [p for p in listed.decode("utf-8").split("\0") if p]
    if len(paths) < 50:
        print("git ls-files listed %d files: the scan would prove nothing" % len(paths))
        return 2
    found = ["%s (path): %s" % (rel, h) for rel in paths for h in hits(rel)]
    scanned = 0
    for rel in paths:
        path = os.path.join(root, rel)
        if not os.path.isfile(path) or os.path.islink(path):
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
    for line in found:
        print(line)
    print("%d files scanned, %d site-name hits" % (scanned, len(found)))
    return 1 if found else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(scan(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
