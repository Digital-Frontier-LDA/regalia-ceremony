#!/usr/bin/env python3
"""Adversarial tests for metal-stamp-worksheet.py --verify.

The metal plate is the LAST-resort, fire/water/decay-proof backup. `--verify` exists to
catch a mis-stamp BEFORE you rely on the plate. The dangerous case: a mis-stamp that lands
on a DIFFERENT but still-valid SLIP-39 word (e.g. ACADEMIC->ACID) — prefix-validity alone
cannot catch that, but the SLIP-39 RS1024 share checksum can. These tests require verify to
reject a checksum-invalid reconstruction, not just confirm the prefixes are real words.
"""
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
SCRIPT = os.path.join(_SCRIPTS, "metal-stamp-worksheet.py")


def have_lib():
    try:
        import shamir_mnemonic  # noqa: F401
        return True
    except Exception:
        return False


def a_real_share():
    import shamir_mnemonic as sm
    return sm.generate_mnemonics(1, [(2, 3)], b"0123456789abcdef", b"")[0][0]


@unittest.skipUnless(have_lib(), "shamir-mnemonic not installed")
class TestMetalStampVerify(unittest.TestCase):
    def _verify(self, prefixes_text):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write(prefixes_text)
            path = tf.name
        try:
            return subprocess.run([sys.executable, SCRIPT, "--verify", "--in", path],
                                  capture_output=True, text=True)
        finally:
            os.unlink(path)

    def _prefixes(self, share):
        return " ".join(w[:4].upper() for w in share.split())

    def test_correct_stamping_verifies(self):
        r = self._verify(self._prefixes(a_real_share()))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VERIFY OK", r.stdout)

    def test_misstamp_to_a_different_valid_word_is_caught(self):
        # the dangerous mis-stamp: a valid prefix, but the WRONG word -> checksum must fail
        from shamir_mnemonic import wordlist
        WL = list(wordlist.WORDLIST)
        share = a_real_share().split()
        orig = share[7]
        share[7] = next(w for w in WL if w != orig)   # a different, still-valid word
        r = self._verify(" ".join(w[:4].upper() for w in share))
        self.assertNotEqual(r.returncode, 0,
                            "verify reported OK on a share that fails its SLIP-39 checksum (mis-stamp not caught)")
        self.assertIn("FAIL", (r.stdout + r.stderr).upper())

    def test_nonexistent_prefix_is_caught(self):
        r = self._verify("ZZZZ ACAD ACID")
        self.assertNotEqual(r.returncode, 0)

    def test_verify_does_not_print_secret_on_a_bad_share(self):
        # on failure it must not dump a reconstructed (wrong) share to stdout as if valid
        from shamir_mnemonic import wordlist
        WL = list(wordlist.WORDLIST)
        share = a_real_share().split()
        share[3] = next(w for w in WL if w != share[3])
        r = self._verify(" ".join(w[:4].upper() for w in share))
        self.assertNotIn("Reconstructed share", r.stdout,
                         "verify printed a 'reconstructed share' for a checksum-invalid plate")


if __name__ == "__main__":
    unittest.main(verbosity=2)
