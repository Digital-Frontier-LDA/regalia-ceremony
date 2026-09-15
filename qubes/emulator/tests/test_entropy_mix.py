#!/usr/bin/env python3
"""Adversarial tests for entropy-mix.py — the XOR combiner that builds the master secret from
independent entropy sources.

THE PROPERTY THAT MATTERS MOST: x XOR x == 0. Two identical sources cancel completely, and with
exactly two the master secret becomes all zeros. That value still looks like plausible hex,
still mints valid SLIP-39 shares, and still reconstruct-verifies perfectly — every downstream
check in the ceremony passes. Nothing but comparing the inputs can catch it, so these tests
pin that comparison down hard, along with the other silent-weakening cases (a zeroed source
from a failed read, a short source, an empty file, a single source dressed up as "mixing").

Also asserts the mixed value is NEVER printed: it is the master secret, and this tool runs on
a terminal that may be photographed or recorded during the ceremony.
"""
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
SCRIPT = os.path.join(_SCRIPTS, "entropy-mix.py")


def run(*args):
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)


class EntropyMixTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.a = self.src("a.bin", bytes(range(32)))
        self.b = self.src("b.bin", bytes((i * 7 + 3) & 0xFF for i in range(32)))
        self.out = os.path.join(self.tmp, "mixed.hex")

    def src(self, name, data):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def mixed(self):
        with open(self.out) as fh:
            return bytes.fromhex(fh.read().strip())

    # ------------------------------------------------------------------ correctness
    def test_xor_is_exact(self):
        r = run("--out", self.out, self.a, self.b)
        self.assertEqual(r.returncode, 0, r.stderr)
        expect = bytes(x ^ y for x, y in zip(bytes(range(32)),
                                             bytes((i * 7 + 3) & 0xFF for i in range(32))))
        self.assertEqual(self.mixed(), expect)

    def test_order_does_not_matter(self):
        run("--out", self.out, self.a, self.b)
        first = self.mixed()
        run("--out", self.out, self.b, self.a)
        self.assertEqual(self.mixed(), first)

    def test_hex_text_and_raw_bytes_are_read_identically(self):
        """Dice are transcribed by hand as hex; the HSM and kernel emit raw bytes. The same
        value in either form must contribute the same thing, or the mix silently differs."""
        raw = self.src("v.bin", bytes(range(32)))
        hexed = self.src("v.hex", (bytes(range(32)).hex() + "\n").encode())
        run("--out", self.out, raw, self.b)
        via_raw = self.mixed()
        run("--out", self.out, hexed, self.b)
        self.assertEqual(self.mixed(), via_raw)

    def test_three_sources_mix(self):
        c = self.src("c.bin", bytes((i * 13 + 5) & 0xFF for i in range(32)))
        r = run("--out", self.out, self.a, self.b, c)
        self.assertEqual(r.returncode, 0, r.stderr)
        expect = bytearray(32)
        for blob in (bytes(range(32)),
                     bytes((i * 7 + 3) & 0xFF for i in range(32)),
                     bytes((i * 13 + 5) & 0xFF for i in range(32))):
            for i in range(32):
                expect[i] ^= blob[i]
        self.assertEqual(self.mixed(), bytes(expect))

    # --------------------------------------------------------- the cancellation traps
    def test_identical_sources_are_refused(self):
        """THE trap: the same file twice, or a command run twice into the same path, XORs to
        zero. Nothing downstream can detect it."""
        dup = self.src("dup.bin", bytes(range(32)))
        r = run("--out", self.out, self.a, dup)
        self.assertNotEqual(r.returncode, 0, "identical sources must never be mixed")
        self.assertIn("IDENTICAL", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(self.out), "no output may be written on refusal")

    def test_identical_pair_among_three_is_refused(self):
        """Two of three cancelling leaves only one real source while the operator believes
        there are three — a silent downgrade, not a hard failure, so it must be refused."""
        dup = self.src("dup.bin", bytes(range(32)))
        c = self.src("c.bin", bytes((i * 13 + 5) & 0xFF for i in range(32)))
        r = run("--out", self.out, self.a, c, dup)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("IDENTICAL", r.stdout + r.stderr)

    def test_all_zero_source_is_refused(self):
        z = self.src("z.bin", bytes(32))
        r = run("--out", self.out, self.a, z)
        self.assertNotEqual(r.returncode, 0, "a zeroed source is a failed read, not entropy")
        self.assertIn("ALL ZEROS", r.stdout + r.stderr)

    def test_single_source_is_refused(self):
        r = run("--out", self.out, self.a)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("at least TWO", r.stdout + r.stderr)

    def test_wrong_length_source_is_refused(self):
        short = self.src("short.bin", bytes(16))
        r = run("--out", self.out, self.a, short)
        self.assertNotEqual(r.returncode, 0, "padding or truncating would weaken the mix silently")
        self.assertIn("expected 32", r.stdout + r.stderr)

    def test_empty_source_is_refused(self):
        empty = self.src("empty.bin", b"")
        r = run("--out", self.out, self.a, empty)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("EMPTY", r.stdout + r.stderr)

    # ------------------------------------------------------------------- hygiene
    def test_mixed_value_is_never_printed(self):
        r = run("--out", self.out, self.a, self.b)
        combined = r.stdout + r.stderr
        self.assertNotIn(self.mixed().hex(), combined, "the master secret must never be printed")
        # ...but its digest is, so the operator can confirm continuity without seeing the value
        self.assertIn(hashlib.sha256(self.mixed()).hexdigest()[:16], combined)

    def test_output_is_owner_only(self):
        run("--out", self.out, self.a, self.b)
        mode = stat.S_IMODE(os.stat(self.out).st_mode)
        self.assertEqual(mode & 0o077, 0, "mixed entropy file must not be group/world readable")

    def test_source_values_are_never_printed(self):
        r = run("--out", self.out, self.a, self.b)
        combined = r.stdout + r.stderr
        self.assertNotIn(bytes(range(32)).hex(), combined)

    def test_selftest_subcommand_passes(self):
        r = run("--selftest")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK", r.stdout)

    # --------------------------------------------------------------- integration
    def test_mixed_entropy_reconstructs_through_slip39(self):
        """The whole point: the mixed value must survive minting and 4-of-6 reconstruction
        unchanged, or the entropy never actually became the master secret."""
        try:
            from shamir_mnemonic import combine_mnemonics
        except ImportError:
            self.skipTest("shamir_mnemonic not installed")
        mint = os.path.join(_SCRIPTS, "slip39-mint.py")
        if not os.path.exists(mint):
            self.skipTest("slip39-mint.py not present")
        self.assertEqual(run("--out", self.out, self.a, self.b).returncode, 0)
        shares = os.path.join(self.tmp, "shares.txt")
        r = subprocess.run([sys.executable, mint, "--threshold", "4", "--shares", "6",
                            "--from-entropy", "--entropy-file", self.out, "--out", shares],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(shares) as fh:
            words = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        self.assertEqual(combine_mnemonics(words[:4]), self.mixed(),
                         "4-of-6 must reconstruct exactly the mixed entropy")


if __name__ == "__main__":
    unittest.main(verbosity=2)
