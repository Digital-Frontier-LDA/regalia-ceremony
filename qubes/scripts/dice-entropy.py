#!/usr/bin/env python3
"""dice-entropy.py — collect physical dice rolls and turn them into 256 bits of entropy.

  dice-entropy.py --out dice.hex            # guided: roll, type, Enter … until 50 dice values
  dice-entropy.py --selftest

WHY DICE AT ALL: the ceremony never trusts one random source. The owner's rule (2026-09-25):
the wallet seed always has physical dice mixed in on top of the Nitrokey HSM's hardware RNG, so
a flawed or backdoored RNG alone cannot determine the seed. entropy-mix.py XORs this with the
HSM and /dev/urandom; the result is at least as unpredictable as the best of the three.

HOW MANY ROLLS: 50 dice values (owner, 2026-09-29; ADR-0002 D11). A fair six-sided die gives
log2(6) = 2.585 bits per value, so 50 values carry 129 bits. That is the right target because the
dice are never the only source: they are XORed with the HSM's RNG and /dev/urandom, and exist so
that the seed stays out of reach even if BOTH of those are flawed. 128 bits is the standard
security level for that. (Wallets that use dice ALONE ask for 99-100 rolls, to fill all 256 bits.)
Several dice may be thrown at once: 2 dice x 25 throws is 50 values (one Enter per throw). The values are hashed with
SHA-256, as hardware wallets do with dice (Coldcard): the exact digits, in order, become one
32-byte value. Fewer values than asked is refused rather than accepted as less entropy than it looks.

WHAT THE FAIRNESS CHECK CAN AND CANNOT DO (owner, 2026-09-29): no test on the digits can prove
they came from dice, since entropy is a property of how they were made, and a careful person can
always type digits that look fair. The check catches a stuck or badly biased die, a misread, and
NAIVE made-up typing. It refuses:
  - two or more faces never appearing;
  - counts too uneven for fair dice: a chi-square test (5 degrees of freedom) at p < 1e-4. At 50
    values that is roughly one face coming up 22 or more times;
  - NO value ever repeated back-to-back. Real dice repeat about 8 times in 50, and people typing
    "random" digits almost never do. Fair dice show no repeat about 1 in 7,600 runs;
  - a repeating pattern (the sequence equals itself shifted by 1-16 places).
Real dice are refused about once in 3,000 runs (measured: 317 of 10^6 simulated 50-roll runs),
and the fix is to roll again. A
deliberate cheater is out of scope: the dice are XORed with the HSM and OS randomness, so fake dice
cannot weaken the seed (they only fail to add to it), and the operator is covered by the ceremony
record (ADR-0002 D8).

WHAT IS KEPT: only the 32-byte hash, written 0600 to --out. The rolls are read with echo off,
never printed, and never written anywhere. The hash's own SHA-256 prefix is printed as a
fingerprint, so the operator can confirm the same value reached the mixer without seeing it.
"""
import argparse
import getpass
import hashlib
import math
import os
import sys

FACES = "123456"
MIN_ROLLS = 50           # 50 * log2(6) = 129 bits >= 128: the security level the dice back up


def check_line(line):
    """The rolls on one typed line, or None if the line holds anything but 1-6 and spaces.
    A bad line is discarded WHOLE: keeping the good part of a mistyped line would silently
    drop or shift rolls the operator believes were entered."""
    digits = "".join(line.split())
    if not digits or any(c not in FACES for c in digits):
        return None
    return digits


CHI2_REFUSE_P = 1e-4     # refuse counts this unlikely for fair dice
MAX_PERIOD = 16


def chi2_sf_5df(x):
    """P(X >= x) for chi-square with 5 degrees of freedom (six faces): closed form, no scipy."""
    if x <= 0:
        return 1.0
    return math.erfc(math.sqrt(x / 2)) + math.sqrt(2 * x / math.pi) * math.exp(-x / 2) * (1 + x / 3)


def sanity(rolls):
    """Why the rolls cannot be fair dice read honestly, or None. See WHAT THE FAIRNESS CHECK CAN
    AND CANNOT DO above. In 50 fair rolls ONE face never appearing happens about once in 1,500
    runs, so that alone is allowed; TWO is about once in 10^8."""
    n = len(rolls)
    counts = {f: rolls.count(f) for f in FACES}
    missing = [f for f, c in counts.items() if c == 0]
    if len(missing) >= 2:
        return "face(s) %s never appeared — that is not fair dice; roll again" % ",".join(missing)
    expected = n / 6
    chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
    if chi2_sf_5df(chi2) < CHI2_REFUSE_P:
        top = max(FACES, key=lambda f: counts[f])
        return ("the counts are too uneven for fair dice (%s came up %d of %d times) — a biased or "
                "stuck die, or misread values; roll again" % (top, counts[top], n))
    if not any(a == b for a, b in zip(rolls, rolls[1:])):
        return ("no value ever came up twice in a row. Real dice do that about %d times in %d; "
                "this looks typed, not rolled. Roll the dice again" % (round((n - 1) / 6), n))
    for p in range(1, min(MAX_PERIOD, n // 3) + 1):
        if rolls[p:] == rolls[:-p]:
            return "the values repeat a %d-long pattern — that is not dice; roll again" % p
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


# A fixed 50-value sequence shaped like fair dice: every face 7-9 times, 11 back-to-back repeats.
FAIR50 = "35116424236655142311453662245135524611326443155226"


def selftest():
    # the hash is the SHA-256 of the exact digit string: the documented, reproducible rule
    rolls = FAIR50                                         # 50 real-looking rolls
    assert to_entropy(rolls) == hashlib.sha256(rolls.encode()).digest()
    assert len(to_entropy(rolls)) == 32
    assert check_line("1 2 3 4 5 6") == "123456"
    assert check_line("12a4") is None and check_line("7") is None and check_line("   ") is None
    assert sanity("1" * 100) is not None                   # stuck die
    assert sanity("1234" * 25) is not None                 # two faces never seen
    assert "too uneven" in sanity("1" * 60 + "23456" * 8)  # one face > half
    assert "too uneven" in sanity("6" * 22 + FAIR50[22:])  # 22+ of one face in 50
    assert "twice in a row" in sanity("123456" * 8 + "12")  # typed: never a repeat
    assert "twice in a row" in sanity("12345" * 10)
    assert "pattern" in sanity("1122334455661234" * 3 + "11")   # a 16-long loop, repeats inside
    assert sanity(FAIR50.replace("6", "5")) is None        # one face missing in 50: chance, allowed
    assert sanity(rolls) is None
    assert abs(chi2_sf_5df(11.0705) - 0.05) < 1e-4         # the textbook 5% point, 5 df
    assert abs(chi2_sf_5df(25.7448) - 1e-4) < 1e-6
    lines = iter(["123456", "12x", "6543216543", "1" * 90, ""])
    out = []
    got = collect(lambda _p: next(lines, None), out.append, min_rolls=100)   # a larger minimum still works
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
        sys.exit("dice-entropy: fewer than %d dice values cannot carry 128 bits" % MIN_ROLLS)
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
