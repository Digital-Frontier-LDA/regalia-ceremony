#!/usr/bin/env python3
"""ccid-add-reader.py — add a USB smart-card reader to libccid's list of supported readers.

  ccid-add-reader.py --plist /etc/libccid_Info.plist --vid 0x2E8A --pid 0x10FD --name "Pol Henarejos Pico Key"
  ccid-add-reader.py --plist /etc/libccid_Info.plist --vid 0x2E8A --pid 0x10FD --check   # 0 = listed

WHY: libccid (the CCID driver pcscd uses) only opens readers its Info.plist lists by USB vendor and
product ID, and checks every device against that list itself. Debian 13's libccid 1.6.2 lists 607
readers, including the Nitrokey HSM (20a0:4230) but NOT the Pico HSM (2e8a:10fd), so pcscd ignores a
Pico attached to the vault (owner's disposable, 2026-09-29). Debian keeps the list in /etc as a
conffile precisely so an admin can add a reader; this is that edit, made idempotent for Salt.

HOW: the plist holds three parallel arrays, ifdVendorID / ifdProductID / ifdFriendlyName, where
entry i of each describes reader i. One <string> is appended to each, so they stay in lockstep;
if they are not the same length on input the file is not touched. The file is replaced atomically
with its mode kept.
"""
import argparse
import os
import re
import sys
import tempfile

KEYS = ("ifdVendorID", "ifdProductID", "ifdFriendlyName")


def arrays(text):
    """{key: (list of strings, index of that array's </array>)} for the three parallel arrays."""
    out = {}
    for k in KEYS:
        m = re.search(r"<key>%s</key>\s*<array>(.*?)</array>" % k, text, re.S)
        if not m:
            raise ValueError("no %s array" % k)
        out[k] = (re.findall(r"<string>(.*?)</string>", m.group(1)), m.end(1))
    return out


def listed(text, vid, pid):
    a = arrays(text)
    return any(v.lower() == vid.lower() and p.lower() == pid.lower()
               for v, p in zip(a["ifdVendorID"][0], a["ifdProductID"][0]))


def add(text, vid, pid, name):
    a = arrays(text)
    n = {len(a[k][0]) for k in KEYS}
    if len(n) != 1:
        raise ValueError("the three reader arrays differ in length (%s): not editing"
                         % ", ".join("%s=%d" % (k, len(a[k][0])) for k in KEYS))
    if listed(text, vid, pid):
        return text
    # Insert from the last array backwards so earlier offsets stay valid.
    vals = {"ifdVendorID": vid, "ifdProductID": pid, "ifdFriendlyName": name}
    for k in sorted(KEYS, key=lambda k: a[k][1], reverse=True):
        at = a[k][1]
        text = text[:at] + "\t\t<string>%s</string>\n\t" % vals[k] + text[at:]
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plist", required=True)
    ap.add_argument("--vid", required=True, help="e.g. 0x2E8A")
    ap.add_argument("--pid", required=True, help="e.g. 0x10FD")
    ap.add_argument("--name", help="friendly name (required unless --check)")
    ap.add_argument("--check", action="store_true", help="exit 0 if already listed, 1 if not")
    a = ap.parse_args()
    for v in (a.vid, a.pid):
        if not re.fullmatch(r"0x[0-9A-Fa-f]{4}", v):
            sys.exit("ccid-add-reader: vendor/product IDs look like 0x2E8A, got %r" % v)
    if a.name is not None and not re.fullmatch(r"[A-Za-z0-9 ._()-]{1,64}", a.name):
        sys.exit("ccid-add-reader: the name must be plain text (letters, digits, space . _ ( ) -)")
    with open(a.plist) as fh:
        text = fh.read()
    if a.check:
        sys.exit(0 if listed(text, a.vid, a.pid) else 1)
    if not a.name:
        sys.exit("ccid-add-reader: --name is required")
    try:
        new = add(text, a.vid, a.pid, a.name)
    except ValueError as exc:
        sys.exit("ccid-add-reader: %s" % exc)
    if new == text:
        print("ccid-add-reader: %s:%s already listed in %s" % (a.vid, a.pid, a.plist))
        return
    assert listed(new, a.vid, a.pid) and len({len(v[0]) for v in arrays(new).values()}) == 1
    d = os.path.dirname(os.path.abspath(a.plist))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ccid-add-reader.")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(new)
        os.chmod(tmp, os.stat(a.plist).st_mode & 0o7777)
        os.replace(tmp, a.plist)
    except BaseException:
        os.unlink(tmp)
        raise
    print("ccid-add-reader: added %s:%s (%s) to %s" % (a.vid, a.pid, a.name, a.plist))


if __name__ == "__main__":
    main()
