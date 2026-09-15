#!/usr/bin/env python3
"""Adversarial tests for seed-to-pkcs12.py — the tool that turns the 4-of-6-backed seed into
the PKCS#12 container the SmartCard-HSM import path consumes.

WHAT MAKES THIS TOOL DANGEROUS: everything it emits looks correct. A container built from the
wrong derivation path, or carrying a key that is not the seed's, imports cleanly and produces a
valid Akash address that signs perfectly — and the funds land under a key nobody can rebuild
from the shares. There is no error message in that failure, only a wrong address, so the tests
that matter are the ones pinning the derivation to a known vector and proving the container
carries exactly the derived key.

Second class of failure: the tool handles the funding seed in plaintext. It must never let the
mnemonic or the container password reach argv (visible in ps / /proc/<pid>/cmdline / history),
never print them, and never leave the raw key behind in a temp file after a crash.
"""
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
SCRIPT = os.path.join(_SCRIPTS, "seed-to-pkcs12.py")
DERIVER = os.path.join(_SCRIPTS, "derive-akash-address.py")

# BIP39 test vector. m/44'/118'/0'/0/0 on this mnemonic is a fixed, independently checkable
# value — pinning it means a change to the derivation path or curve math fails here loudly
# rather than silently producing a different (unrecoverable) funding address.
TEST_MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon about")
EXPECTED_ADDR = "akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0"
OTHER_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"


def have_openssl():
    return subprocess.run(["which", "openssl"], capture_output=True).returncode == 0


def run(*args):
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)


@unittest.skipUnless(have_openssl(), "openssl not installed")
class SeedToPkcs12Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mfile = self.w("m.txt", TEST_MNEMONIC)
        self.pwfile = self.w("pw.txt", "container-password-not-a-real-secret")
        self.out = os.path.join(self.tmp, "funding.p12")

    def w(self, name, content):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as fh:
            fh.write(content)
        return p

    def build(self, mfile=None, pwfile=None, extra=()):
        return run("--mnemonic-file", mfile or self.mfile,
                   "--password-file", pwfile or self.pwfile,
                   "--out", self.out, *extra)

    def p12_pubkey_address(self):
        """Read the key back OUT of the container and derive its address with the audited
        deriver — the same check the ceremony step makes against the card."""
        r = subprocess.run(["openssl", "pkcs12", "-in", self.out, "-nocerts", "-nodes",
                            "-passin", "file:" + self.pwfile], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode()[:300])
        r2 = subprocess.run(["openssl", "ec", "-pubout", "-outform", "DER"],
                            input=r.stdout, capture_output=True)
        self.assertEqual(r2.returncode, 0, r2.stderr.decode()[:300])
        der = os.path.join(self.tmp, "pub.der")
        with open(der, "wb") as fh:
            fh.write(r2.stdout)
        r3 = subprocess.run([sys.executable, DERIVER, "--der", der], capture_output=True, text=True)
        self.assertEqual(r3.returncode, 0, r3.stderr)
        return r3.stdout.strip()

    # ------------------------------------------------------------------ derivation
    def test_derivation_matches_the_pinned_vector(self):
        """If this fails, the HD path or curve math changed and every future ceremony would
        fund a different address than the recovery docs describe."""
        r = self.build()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(EXPECTED_ADDR, r.stdout)

    def test_agrees_with_the_audited_deriver(self):
        """Two implementations of key derivation is two chances to derive the wrong key. This
        tool reuses derive-akash-address.py's math; prove the reuse actually holds."""
        self.build()
        r = subprocess.run([sys.executable, DERIVER, "--mnemonic-file", self.mfile],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), EXPECTED_ADDR)

    def test_container_carries_the_derived_key(self):
        """The address printed is only a claim until the container is opened and checked."""
        self.build()
        self.assertEqual(self.p12_pubkey_address(), EXPECTED_ADDR)

    def test_a_different_seed_yields_a_different_container(self):
        other = self.w("other.txt", OTHER_MNEMONIC)
        self.build()
        first = self.p12_pubkey_address()
        os.remove(self.out)
        self.build(mfile=other)
        self.assertNotEqual(self.p12_pubkey_address(), first)

    def test_custom_hd_path_changes_the_key(self):
        self.build()
        default = self.p12_pubkey_address()
        os.remove(self.out)
        r = self.build(extra=("--hd-path", "m/44'/118'/0'/0/1"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(self.p12_pubkey_address(), default)

    def test_container_is_a_real_pkcs12_openssl_accepts(self):
        self.build()
        r = subprocess.run(["openssl", "pkcs12", "-in", self.out, "-info", "-nokeys",
                            "-passin", "file:" + self.pwfile], capture_output=True)
        self.assertEqual(r.returncode, 0, "openssl could not parse the container")

    def test_container_password_is_actually_required(self):
        """A container that opens with the wrong password would be an unprotected copy of the
        funding key sitting in the workdir."""
        self.build()
        wrong = self.w("wrong.txt", "definitely-not-the-password")
        r = subprocess.run(["openssl", "pkcs12", "-in", self.out, "-nocerts", "-nodes",
                            "-passin", "file:" + wrong], capture_output=True)
        self.assertNotEqual(r.returncode, 0, "container opened with the WRONG password")

    # ------------------------------------------------------------------ secret hygiene
    def test_mnemonic_is_never_printed(self):
        r = self.build()
        self.assertNotIn("abandon", r.stdout + r.stderr)

    def test_password_is_never_printed(self):
        r = self.build()
        with open(self.pwfile) as fh:
            pw = fh.read()
        self.assertNotIn(pw, r.stdout + r.stderr)

    def test_refuses_a_mnemonic_on_argv(self):
        """argv is visible in ps, /proc/<pid>/cmdline and shell history. The tool must have no
        way to accept the seed there, not merely discourage it."""
        r = run("--mnemonic-file", TEST_MNEMONIC, "--password-file", self.pwfile, "--out", self.out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must exist", r.stdout + r.stderr)

    def test_container_is_owner_only(self):
        self.build()
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode) & 0o077, 0,
                         "PKCS#12 container must not be group/world readable")

    def test_no_raw_key_material_left_behind(self):
        """The builder writes the private key in three encodings to a temp tree. If that tree
        survives, the funding key is sitting in plaintext on whatever filesystem it used."""
        before = set(os.listdir(tempfile.gettempdir()))
        self.build()
        after = set(os.listdir(tempfile.gettempdir()))
        leaked = []
        for name in after - before:
            path = os.path.join(tempfile.gettempdir(), name)
            if not os.path.isdir(path):
                continue
            try:
                if {"k.der", "k.pem", "pw"} & set(os.listdir(path)):
                    leaked.append(path)
            except OSError:
                pass
        self.assertEqual(leaked, [], "raw key material left in %s" % leaked)

    # ------------------------------------------------------------------ fail-closed
    def test_refuses_a_missing_mnemonic_file(self):
        r = self.build(mfile=os.path.join(self.tmp, "nope.txt"))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.out))

    def test_refuses_an_empty_mnemonic_file(self):
        r = self.build(mfile=self.w("empty.txt", "  \n"))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.out))

    def test_refuses_an_invalid_mnemonic(self):
        """A mistyped or truncated mnemonic must fail the BIP39 checksum here, not silently
        derive a valid-looking key for a seed nobody holds shares for."""
        r = self.build(mfile=self.w("bad.txt", "abandon abandon abandon"))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.out))

    def test_refuses_an_empty_password_file(self):
        r = self.build(pwfile=self.w("nopw.txt", ""))
        self.assertNotEqual(r.returncode, 0)

    def test_selftest_subcommand_passes(self):
        r = run("--selftest")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK", r.stdout)

    def test_prints_the_post_import_warning(self):
        """The operator must be told the card has to report this same address, or the whole
        address-match proof is something they might skip."""
        r = self.build()
        self.assertRegex(r.stdout, re.compile("AFTER IMPORT.*MUST report", re.S))


if __name__ == "__main__":
    unittest.main(verbosity=2)
