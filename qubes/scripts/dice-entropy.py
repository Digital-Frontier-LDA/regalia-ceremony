#!/usr/bin/env python3
"""dice-entropy.py — collect physical dice rolls and turn them into 256 bits of entropy.

  dice-entropy.py --out dice.hex            # guided: roll, type, Enter … until 100 rolls
  dice-entropy.py --selftest

WHY DICE AT ALL: the ceremony never trusts one random source. The owner's rule (2026-09-25):
the wallet seed always has physical dice mixed in on top of the Nitrokey HSM's hardware RNG, so
a flawed or backdoored RNG alone cannot determine the seed. entropy-mix.py XORs this with the
HSM and /dev/urandom; the result is at least as unpredictable as the best of the three.

HOW MANY ROLLS: a fair six-sided die gives log2(6) = 2.585 bits per roll, so 100 rolls carry
258 bits, just over the 256 the seed needs. The rolls are hashed with SHA-256, as hardware
wallets do with dice (Coldcard): the exact digits, in order, become one 32-byte value. Typing
fewer rolls than asked, or the same digit over and over, is refused rather than accepted as
less entropy than it looks.

WHAT IS KEPT: only the 32-byte hash, written 0600 to --out. The rolls are read with echo off,
never printed, and never written anywhere. The hash's own SHA-256 prefix is printed as a
fingerprint, so the operator can confirm the same value reached the mixer without seeing it.
"""
import argparse
import getpass
import hashlib
import os
import sys

FACES = "123456"
MIN_ROLLS = 100          # 100 * log2(6) = 258.5 bits >= 256


def check_line(line):
    """The rolls on one typed line, or None if the line holds anything but 1-6 and spaces.
    A bad line is discarded WHOLE: keeping the good part of a mistyped line would silently
    drop or shift rolls the operator believes were entered."""
    digits = "".join(line.split())
    if not digits or any(c not in FACES for c in digits):
        return None
    return digits


def sanity(rolls):
    """Refuse input that cannot have come from fair dice read honestly: a face that never
    appears in 100+ rolls happens with fair dice about once in 10^7 runs; one face making up
    over half the rolls is far outside chance. Either means a stuck die, a mis-read, or a
    keyboard pattern — not entropy."""
    counts = {f: rolls.count(f) for f in FACES}
    missing = [f for f, n in counts.items() if n == 0]
    if missing:
        return "face(s) %s never appeared — that is not fair dice; roll again" % ",".join(missing)
    top = max(counts.values())
    if top * 2 > len(rolls):
        return "one face is more than half of all rolls — that is not fair dice; roll again"
    return None


def collect(read_line, say, min_rolls=MIN_ROLLS):
    rolls = ""
    say("Roll your dice (any number at a time) and type the results as digits 1-6, then Enter.")
    say("What you type is hidden. A line with anything else is discarded whole — retype it.")
    while len(rolls) < min_rolls:
        line = read_line("   rolls (%d of %d so far): " % (len(rolls), min_rolls))
        if line is None:
            sys.exit("dice-entropy: input ended before %d rolls — nothing was written" % min_rolls)
        got = check_line(line)
        if got is None:
            say("   that line had something other than 1-6 — it was DISCARDED, retype those rolls")
            continue
        rolls += got
    say("   %d rolls entered." % len(rolls))
    return rolls


def to_entropy(rolls):
    return hashlib.sha256(rolls.encode("ascii")).digest()


def write_out(path, entropy):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(entropy.hex() + "\n")


def selftest():
    # the hash is the SHA-256 of the exact digit string: the documented, reproducible rule
    rolls = "123456" * 17                                  # 102 rolls, every face
    assert to_entropy(rolls) == hashlib.sha256(rolls.encode()).digest()
    assert len(to_entropy(rolls)) == 32
    assert check_line("1 2 3 4 5 6") == "123456"
    assert check_line("12a4") is None and check_line("7") is None and check_line("   ") is None
    assert sanity("1" * 100) is not None                   # stuck die
    assert sanity("12345" * 20) is not None                # a face never seen
    assert sanity("1" * 60 + "23456" * 8) is not None      # one face > half
    assert sanity(rolls) is None
    lines = iter(["123456", "12x", "6543216543", "1" * 90, ""])
    out = []
    got = collect(lambda _p: next(lines, None), out.append, min_rolls=100)
    assert got == "123456" + "6543216543" + "1" * 90, "discarded line must not contribute"
    assert any("DISCARDED" in s for s in out)
    print("dice-entropy selftest: OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--out", metavar="DICE.hex")
    g.add_argument("--selftest", action="store_true")
    ap.add_argument("--min-rolls", type=int, default=MIN_ROLLS)
    ap.add_argument("--from-stdin", action="store_true",
                    help="read roll lines from stdin instead of the terminal (TESTS ONLY)")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if a.min_rolls < MIN_ROLLS:
        sys.exit("dice-entropy: fewer than %d rolls cannot carry 256 bits" % MIN_ROLLS)
    if a.from_stdin:
        read_line = lambda _p: (sys.stdin.readline() or None)
    else:
        def read_line(prompt):
            try:
                return getpass.getpass(prompt)
            except EOFError:
                return None
    say = lambda s: print(s, file=sys.stderr, flush=True)
    while True:
        rolls = collect(read_line, say, a.min_rolls)
        problem = sanity(rolls)
        if problem is None:
            break
        say("   REFUSED: " + problem + ". Nothing was kept; start again.")
        if a.from_stdin:
            sys.exit(1)
    entropy = to_entropy(rolls)
    rolls = None
    write_out(a.out, entropy)
    say("dice entropy written to %s (fingerprint %s)"
        % (a.out, hashlib.sha256(entropy).hexdigest()[:16]))


if __name__ == "__main__":
    main()
