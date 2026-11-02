#!/usr/bin/env python3
"""Refuse the real KMS site names in this public repository (regalia-fft).

Every tracked file is scanned: its path, a symlink's target, and its contents, read as UTF-8 (or byte for
byte) and, where they hold NUL bytes, as UTF-16 in both byte orders (regalia-iy9). A name is caught in any
case and inside identifiers (`FOO_BAR`, `fooBar`, `foo2`, `foo.conf`). The one shape let through is a name
glued to a preceding lowercase letter, because English words contain one of them.

It never prints a name, not even when it fails (regalia-9lr): this repository's CI logs are public. A hit is
reported as `<site-N>`, N being the word's place in WORDS, and the self-test reports word and shape numbers.
The words are stored ROT13-encoded so this file does not trip its own scan; neutral fixture names are
alder, birch and cedar.

    python3 -I tools/no-site-names.py              # scan; exit 1 on any hit
    python3 -I tools/no-site-names.py --self-test  # the scan's own positive and negative controls
"""

import codecs
import os
import re
import subprocess
import sys
import tempfile

WORDS = [codecs.decode(w, "rot13") for w in ("yvfoba", "yvfobn", "cbegb", "pbvzoen")]
_ANY = "|".join(WORDS)
_CAPS = "|".join([w.capitalize() for w in WORDS] + [w.upper() for w in WORDS])
PATTERN = re.compile(r"(?<![a-zA-Z])(?i:%s)|(?<=[a-z])(?:%s)" % (_ANY, _CAPS))


def hits(text):
    return [m.group(0) for m in PATTERN.finditer(text)]


def redact(text):
    """text with every hit replaced by <site-N>: the only form a hit is ever printed in."""
    return PATTERN.sub(lambda m: "<site-%d>" % (WORDS.index(m.group(0).lower()) + 1), text)


def decodings(data):
    """(label, text) for every reading of a file's bytes the scan makes."""
    try:
        out = [("", data.decode("utf-8"))]
    except UnicodeDecodeError:
        out = [("", data.decode("latin-1"))]
    if b"\0" in data:                              # UTF-16 hides a name from a byte-wise reading
        for offset in (0, 1):
            for codec in ("utf-16-le", "utf-16-be"):
                out.append((" (%s+%d)" % (codec, offset), data[offset:].decode(codec, "ignore")))
    return out


def scan(root):
    """Every hit under root, redacted, or None if git listed too little to prove anything; and the counts."""
    listed = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    paths = [p for p in listed.decode("utf-8").split("\0") if p]
    found, scanned = [], 0
    for rel in paths:
        shown = redact(rel)
        found.extend("%s (path): %s" % (shown, redact(h)) for h in hits(rel))
        path = os.path.join(root, rel)
        if os.path.islink(path):                   # a tracked symlink: its target is content too
            found.extend("%s (symlink target): %s" % (shown, redact(h)) for h in hits(os.readlink(path)))
            scanned += 1
            continue
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        scanned += 1
        for label, text in decodings(data):
            for lineno, line in enumerate(text.splitlines(), 1):
                found.extend("%s:%d%s: %s" % (shown, lineno, label, redact(h)) for h in hits(line))
    return found, len(paths), scanned


def scan_control():
    """A throwaway repository with names planted in a path, a symlink target, a UTF-8 line, a UTF-16 file with
    a BOM and a UTF-16 one without, at an odd offset, plus two clean files: the scan must flag exactly the
    five, and its report must name nothing. Returns a list of failures, as numbers and labels only."""
    a, d_, b, c = WORDS
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["git", "init", "-q", d], check=True)
        files = {"clean.txt": b"nothing here\n", "content.txt": ("x\n%s.boot.key\n" % b).encode(),
                 os.path.join(a.capitalize(), "f"): b"\n",
                 "le.txt": ("x\n%s\n" % c).encode("utf-16"),
                 "be.bin": b"\x01" + ("%s\n" % d_.upper()).encode("utf-16-be"),
                 "clean16.txt": "nothing\n".encode("utf-16")}
        for rel, data in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
            with open(os.path.join(d, rel), "wb") as f:
                f.write(data)
        os.symlink("../%s/target" % c, os.path.join(d, "link"))
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        found, listed, scanned = scan(d)
    failures = []
    flagged = sorted(set(x.split(":")[0].split(" (")[0] for x in found))
    expected = ["<site-1>/f", "be.bin", "content.txt", "le.txt", "link"]
    if (listed, scanned) != (7, 7):
        failures.append("listed %d, scanned %d, not 7 and 7" % (listed, scanned))
    if flagged != expected:
        failures.append("flagged %d files, %d of them the expected ones; want exactly %d"
                        % (len(flagged), len(set(flagged) & set(expected)), len(expected)))
    if not any("(symlink target)" in x for x in found):
        failures.append("no symlink-target hit")
    if not any("(utf-16-be+1)" in x for x in found):
        failures.append("no UTF-16 hit at an odd offset")
    if hits("\n".join(found)):
        failures.append("the scan's own report names a site")
    return failures


def self_test():
    failures = []
    # An independent copy of the words (reversed, not ROT13), so a mutated WORDS cannot test itself.
    control = [w[::-1] for w in ("nobsil", "aobsil", "otrop", "arbmioc")]
    if sorted(control) != sorted(WORDS):
        failures.append("WORDS differs from the control list")
    for i, word in enumerate(control, 1):          # every listed word, so none of them can go untested
        shapes = (word, word.capitalize(), word.upper(), word.upper() + "_MAC", "from" + word.capitalize(),
                  word + "2", word + ".boot.key", "x-%s-y" % word, 'station = "%s"' % word.capitalize())
        for j, planted in enumerate(shapes, 1):
            found = hits(planted)
            if not (len(found) == 1 and found[0].lower() == word):
                failures.append("word %d, shape %d: not caught" % (i, j))
            elif redact(planted).count("<site-%d>" % i) != 1 or hits(redact(planted)):
                failures.append("word %d, shape %d: not redacted" % (i, j))
    b = control[2]
    for j, clean in enumerate(("Trans" + b[:4] + "Opener", "trans" + b[:4] + "ation", "alder birch cedar"), 1):
        if hits(clean):
            failures.append("clean text %d flagged" % j)
    failures += scan_control()
    if failures:
        print("self-test FAILED:\n  " + "\n  ".join(failures))
        return 1
    print("self-test OK")
    return 0


def main(root):
    found, listed, scanned = scan(root)
    if listed < 50:
        print("git ls-files listed %d files: the scan would prove nothing" % listed)
        return 2
    for line in found:
        print(line)
    print("%d files scanned, %d site-name hits (shown redacted)" % (scanned, len(found)))
    return 1 if found else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(main(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
