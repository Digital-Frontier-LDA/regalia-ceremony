#!/usr/bin/env python3
"""Authenticate PIN escrow files with the ceremony's escrow MAC key (escrow/README.md).

The breakglass recipient is public, so anyone who can write to this repository could encrypt a file
of wrong PINs to it; recovery would then spend device tries on them. Each escrow file therefore
carries an HMAC-SHA256 under a 128-bit key that the ceremony generated, put in the tier-0 payload
(recovery gets it from k shares) and wrote on the PIN card (the owner has it when escrowing). Repository
write access alone cannot produce a valid MAC. The key is read from STANDARD INPUT, never argv.

    pin_escrow_mac.py kcv                      < key   # print the key check value (catches typos)
    pin_escrow_mac.py mac escrow/pins-0003.age < key   # print the file's MAC (written to <file>.mac)
    pin_escrow_mac.py highest <checkout> [prefix]       # highest sequence ever used (history + tree)
    pin_escrow_mac.py select <checkout> /dev/shm/pins.age < key
        # copy the highest-numbered escrow/pins-NNNN.age whose MAC verifies to the given path (0600),
        # exactly the bytes that were verified, and print its name; report every candidate skipped.
        # Exit 1 if none.

Candidates come from the repository's HISTORY (every commit, every ref), not only the current tree:
a writer who deletes the newest escrow pair cannot roll recovery back to an older, stale one, because
the deleted pair is still in history and still verifies. A file found only in history is reported.

MAC = HMAC-SHA256(key, "regalia-pin-escrow/v1\n" + file name + "\n" + sha256 hex of the file), so a
valid MAC cannot be moved to another sequence number. KCV = the first 16 hex of
HMAC-SHA256(key, "regalia-pin-escrow/kcv").
"""
import hashlib
import hmac
import os
import re
import subprocess
import sys

NAME = re.compile(r"^pins-(\d{4})\.age$")


def read_key(stream):
    raw = re.sub(r"[\s:-]", "", stream.readline()).lower()
    if not re.fullmatch(r"[0-9a-f]{32}", raw):
        raise SystemExit("pin_escrow_mac: the escrow MAC key is 32 hex characters (from the PIN card)")
    return bytes.fromhex(raw)


def kcv(key):
    return hmac.new(key, b"regalia-pin-escrow/kcv", hashlib.sha256).hexdigest()[:16]


def mac(key, name, data):
    msg = b"regalia-pin-escrow/v1\n" + name.encode() + b"\n" + hashlib.sha256(data).hexdigest().encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True).stdout


def candidates(repo):
    """(sequence, name, data, tag-or-None, in_head) for every distinct pins-NNNN.age blob in any
    commit of any ref, newest commit first. in_head: these exact bytes are at that name in HEAD."""
    def tree_of(commit):
        tree = {}
        for line in git(repo, "ls-tree", commit, "escrow/").decode().splitlines():
            meta, path = line.split("\t", 1)
            kind, obj = meta.split()[1:3]
            if kind == "blob":          # a directory (or submodule) named like an escrow is never one
                tree[os.path.basename(path)] = obj
        return tree
    head = tree_of("HEAD")
    seen, out = set(), []
    for commit in git(repo, "rev-list", "--all", "--", "escrow").decode().split():
        tree = tree_of(commit)
        for name, blob in tree.items():
            m = NAME.match(name)
            tag_blob = tree.get(name + ".mac")
            # The identity is the ciphertext AND its tag: a later commit that replaces only the .mac
            # must not hide an earlier commit's valid pairing of the same ciphertext.
            if not m or (name, blob, tag_blob) in seen:
                continue
            seen.add((name, blob, tag_blob))
            try:
                tag = git(repo, "cat-file", "blob", tag_blob).decode("ascii").strip() if tag_blob else None
            except UnicodeDecodeError:
                tag = ""
            out.append((int(m[1]), name, git(repo, "cat-file", "blob", blob), tag, head.get(name) == blob))
    return out


def highest(repo, prefix="pins"):
    """The highest sequence ever used for <prefix>-NNNN.age, in any commit of any ref or in the working
    tree: the producer numbers from here, so deleting files cannot make it restart below a number
    recovery would still find in history."""
    pat = re.compile(r"^%s-(\d{4})\.age$" % re.escape(prefix))
    # -z: NUL-separated and never C-quoted, so no path can hide behind quoting or spaces.
    names = {n for n in git(repo, "log", "--all", "-z", "--format=", "--name-only", "--", "escrow").decode(
        "utf-8", "surrogateescape").replace("\n", "\0").split("\0") if n}
    tree = os.path.join(repo, "escrow")
    names |= {"escrow/" + n for n in (os.listdir(tree) if os.path.isdir(tree) else [])}
    return max([int(m[1]) for m in (pat.match(os.path.basename(n)) for n in names) if m] or [0])


def select(key, repo, out):
    found = candidates(repo)
    found.sort(key=lambda c: c[0], reverse=True)          # stable: newest commit first within a number
    for seq, name, data, tag, present in found:
        if tag is None:
            print("SKIPPED %s: no .mac file (not written by tools/pin-escrow.sh): record it as an incident" % name,
                  file=sys.stderr)
            continue
        if not hmac.compare_digest(tag, mac(key, name, data)):
            print("SKIPPED %s: its MAC does not verify (forged, altered or renamed): record it as an incident" % name,
                  file=sys.stderr)
            continue
        if not present:
            print("NOTE %s verifies but HEAD no longer holds it (deleted or replaced after being written): "
                  "using the verified copy from history; record it as an incident" % name, file=sys.stderr)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except OSError as error:
            # A partial copy is not the verified ciphertext: never leave one behind (a full tmpfs).
            os.unlink(out)
            print("could not write %s (%s); nothing kept" % (out, error), file=sys.stderr)
            return 1
        print(name)
        return 0
    print("no verified escrow file in %s: use the payload's PINs" % repo, file=sys.stderr)
    return 1


def main(argv):
    if len(argv) == 1 and argv[0] == "kcv":
        print(kcv(read_key(sys.stdin)))
        return 0
    if len(argv) == 2 and argv[0] == "mac":
        with open(argv[1], "rb") as f:
            data = f.read()
        print(mac(read_key(sys.stdin), os.path.basename(argv[1]), data))
        return 0
    if len(argv) in (2, 3) and argv[0] == "highest":
        print(highest(argv[1], *argv[2:]))
        return 0
    if len(argv) == 3 and argv[0] == "select":
        return select(read_key(sys.stdin), argv[1], argv[2])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
