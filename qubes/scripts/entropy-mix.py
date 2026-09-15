#!/usr/bin/env python3
"""entropy-mix.py — XOR-combine independent entropy sources into the master secret.

  entropy-mix.py --out mixed.hex dice.hex hsm.bin urandom.bin
  entropy-mix.py --selftest

WHY XOR AND NOT "PICK THE BEST SOURCE": the XOR of independent sources is at least as
unpredictable as the strongest one. If the HSM's hardware RNG is backdoored, the dice still
save you; if the dice are biased or miscounted, the HSM still saves you. Replacing dice WITH
the HSM would reintroduce exactly the hardware trust the ceremony exists to remove, and
trusting dice alone assumes a human rolled and transcribed 256 bits without error.

THE FAILURE THIS GUARDS AGAINST MOST: x XOR x == 0. Feed the same file twice — a copy-paste
slip, a source that silently failed and left a stale file, `head -c 32 /dev/urandom` written to
the same path twice — and those two sources contribute NOTHING. With exactly two identical
sources the master secret is all zeros. The result still looks like plausible hex, mints valid
SLIP-39 shares, and reconstruct-verifies perfectly, so no downstream check catches it. Only
comparing the inputs does. That is why identical and all-zero sources are refused here, hard.

The mixed value is written to --out and NEVER printed. Its SHA-256 is printed so the operator
can confirm the same value reached the minting step without ever displaying it.
"""
import argparse
import hashlib
import os
import sys

HEX_CHARS = set("0123456789abcdefABCDEF")


def read_source(path, assume_raw=False):
    """Return (bytes, how) for one entropy file. Accepts hex text (dice rolls transcribed by
    hand) or raw bytes (pkcs11-tool --generate-random, /dev/urandom), and reports which
    interpretation it used so a misread is visible rather than silent."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if not blob:
        sys.exit("entropy-mix: '%s' is EMPTY — a source that produced nothing must not be "
                 "silently treated as zeros." % path)
    if not assume_raw:
        # STRICT decode. With errors="ignore" a raw-binary source whose non-ASCII bytes happen
        # to sit between hex-looking ones would have those bytes DROPPED, and the remainder could
        # then pass the all-hex test — silently reinterpreting binary entropy as hex text and
        # changing the mixed secret. A source that is not strictly ASCII is raw bytes, full stop.
        try:
            text = blob.decode("ascii")
        except UnicodeDecodeError:
            return blob, "raw bytes"
        stripped = "".join(text.split())
        if stripped and len(stripped) % 2 == 0 and all(c in HEX_CHARS for c in stripped) \
                and len(stripped) == len(text.replace("\n", "").replace("\r", "").replace(" ", "").replace("\t", "")):
            return bytes.fromhex(stripped), "hex text"
    return blob, "raw bytes"


def mix(paths, nbytes, assume_raw=False, quiet=False):
    if len(paths) < 2:
        sys.exit("entropy-mix: need at least TWO independent sources — mixing one source with "
                 "nothing is not mixing, it is just that source.")

    sources = []
    for p in paths:
        data, how = read_source(p, assume_raw)
        if len(data) != nbytes:
            sys.exit("entropy-mix: '%s' is %d bytes (%s), expected %d. Every source must be "
                     "exactly the master-secret length — truncating or zero-padding one would "
                     "quietly reduce the entropy it contributes."
                     % (p, len(data), how, nbytes))
        if not any(data):
            sys.exit("entropy-mix: '%s' is ALL ZEROS — that is a failed read, not entropy. "
                     "XORing it in contributes nothing and hides the failure." % p)
        sources.append((p, data, how))

    # x XOR x == 0. Two identical sources cancel completely; with exactly two, the result is
    # all zeros and every downstream check still passes. Compare by digest so the values
    # themselves are never held for comparison or printed.
    seen = {}
    for p, data, _ in sources:
        d = hashlib.sha256(data).hexdigest()
        if d in seen:
            sys.exit("entropy-mix: '%s' and '%s' are IDENTICAL — XOR would cancel them to zero. "
                     "Two sources must never be the same file, the same command run twice into "
                     "the same path, or a stale file from an earlier attempt." % (seen[d], p))
        seen[d] = p

    out = bytearray(nbytes)
    for _, data, _ in sources:
        for i in range(nbytes):
            out[i] ^= data[i]
    out = bytes(out)

    # A zero result from non-identical sources is astronomically unlikely (2^-256) but would be
    # catastrophic and silent, so check rather than assume. It also catches an even number of
    # sources that pairwise cancel in a way the pairwise digest check above cannot see.
    if not any(out):
        sys.exit("entropy-mix: the mixed result is ALL ZEROS — the sources cancelled. Re-gather "
                 "entropy; do NOT proceed.")

    if not quiet:
        for p, data, how in sources:
            print("  source: %-28s %d bytes (%s)  sha256=%s" % (
                os.path.basename(p), len(data), how, hashlib.sha256(data).hexdigest()[:16]))
        print("  mixed %d sources -> %d bytes  sha256=%s" % (
            len(sources), nbytes, hashlib.sha256(out).hexdigest()[:16]))
        print("  (the mixed value itself is never printed — only its digest)")
    return out


def selftest():
    import tempfile
    tmp = tempfile.mkdtemp()
    ok = 0

    def src(name, data):
        p = os.path.join(tmp, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    a = src("a.bin", bytes(range(32)))
    b = src("b.bin", bytes((i * 7 + 3) & 0xFF for i in range(32)))
    got = mix([a, b], 32, quiet=True)
    expect = bytes(x ^ y for x, y in zip(bytes(range(32)), bytes((i * 7 + 3) & 0xFF for i in range(32))))
    assert got == expect, "XOR result wrong"
    ok += 1

    # hex text and raw bytes of the SAME value must be read identically
    h = src("c.hex", b"".join(b"%02x" % i for i in range(32)) + b"\n")
    data, how = read_source(h)
    assert data == bytes(range(32)) and how == "hex text", (data[:4], how)
    ok += 1

    # order must not matter
    assert mix([b, a], 32, quiet=True) == got, "XOR is not order-independent"
    ok += 1

    def must_fail(paths, needle, label):
        try:
            mix(paths, 32, quiet=True)
        except SystemExit as e:
            assert needle in str(e), "%s: wrong error %r" % (label, e)
            return 1
        raise AssertionError("%s: should have failed" % label)

    dup = src("dup.bin", bytes(range(32)))
    ok += must_fail([a, dup], "IDENTICAL", "duplicate source")
    ok += must_fail([a], "at least TWO", "single source")
    ok += must_fail([a, src("z.bin", bytes(32))], "ALL ZEROS", "zero source")
    ok += must_fail([a, src("short.bin", bytes(16))], "expected 32", "wrong length")
    ok += must_fail([a, src("empty.bin", b"")], "EMPTY", "empty source")

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print("entropy-mix selftest: OK (%d checks)" % ok)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*", help="two or more entropy files (hex text or raw bytes)")
    ap.add_argument("--out", help="write the mixed entropy here as hex (never printed)")
    ap.add_argument("--bytes", type=int, default=32, choices=(16, 32),
                    help="master-secret length: 32 = 256-bit (default), 16 = 128-bit")
    ap.add_argument("--assume-raw", action="store_true",
                    help="treat every source as raw bytes, never as hex text")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    os.umask(0o077)
    if a.selftest:
        selftest()
        return
    if not a.sources or not a.out:
        sys.exit("entropy-mix: need --out and two or more source files (see --help)")
    out = mix(a.sources, a.bytes, assume_raw=a.assume_raw)
    with open(a.out, "w") as fh:
        fh.write(out.hex() + "\n")
    os.chmod(a.out, 0o600)
    print("  wrote %d-byte mixed entropy (hex) -> %s" % (len(out), a.out))


if __name__ == "__main__":
    main()
