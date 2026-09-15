#!/usr/bin/env python3
"""Adversarial tests for verify-hsm-control.py — the ROOT OF TRUST for every sign proof in the
ceremony.

WHY THIS FILE MATTERS MORE THAN IT LOOKS: four separate suites call this script to decide
whether a signature is genuine — the born-in-HSM keypair-control proof, the seed-derived import
proof, the two-device clone check, and the hardware drill. None of them tested the verifier
ITSELF. If it ever returned success unconditionally, or accepted a signature from the wrong key,
every one of those proofs would pass against a hostile or faulty card and the ceremony would
happily record a funding address whose private key nobody holds.

So this pins the property that matters in both directions: it must ACCEPT a genuine signature
(or the ceremony blocks on working hardware) and REJECT everything else — wrong key, tampered
r or s, malformed lengths, out-of-range scalars, and the classic identity/zero edge cases that
naive ECDSA implementations wave through.
"""
import importlib.machinery
import importlib.util
import os
import secrets
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
SCRIPT = os.path.join(_SCRIPTS, "verify-hsm-control.py")


def load():
    ldr = importlib.machinery.SourceFileLoader("vhc", SCRIPT)
    spec = importlib.util.spec_from_loader("vhc", ldr)
    mod = importlib.util.module_from_spec(spec)
    ldr.exec_module(mod)
    return mod


V = load()


def sign(priv, digest):
    """Textbook ECDSA over secp256k1 — an independent signer, so a bug shared with the verifier
    cannot make a test pass by symmetry."""
    z = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(V.N - 1) + 1
        R = V.scalar_mul(k, V.G)
        r = R[0] % V.N
        if r == 0:
            continue
        s = (V.inv_mod(k, V.N) * (z + r * priv)) % V.N
        if s == 0:
            continue
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def spki(pub_point):
    pt = b"\x04" + pub_point[0].to_bytes(32, "big") + pub_point[1].to_bytes(32, "big")
    bitstr = b"\x03" + bytes([len(pt) + 1]) + b"\x00" + pt
    algid = b"\x30\x10" + bytes.fromhex("06072a8648ce3d0201") + bytes.fromhex("06052b8104000a")
    body = algid + bitstr
    return b"\x30" + bytes([len(body)]) + body


class VerifyHsmControlTest(unittest.TestCase):
    def setUp(self):
        self.priv = secrets.randbelow(V.N - 1) + 1
        self.pub = V.scalar_mul(self.priv, V.G)
        self.digest = secrets.token_bytes(32)
        self.sig = sign(self.priv, self.digest)

    # ------------------------------------------------------------------ must accept
    def test_accepts_a_genuine_signature(self):
        """If this fails the ceremony blocks on working hardware — the opposite failure, but
        still a failure."""
        self.assertTrue(V.verify(self.pub, self.digest, self.sig))

    def test_accepts_many_independent_signatures(self):
        """ECDSA uses a random k; a verifier that happens to work for one nonce and not others
        would be intermittently wrong, which is worse than consistently wrong."""
        for _ in range(25):
            d = secrets.token_bytes(32)
            self.assertTrue(V.verify(self.pub, d, sign(self.priv, d)))

    # ------------------------------------------------------------------ must reject
    def test_rejects_a_signature_from_a_DIFFERENT_key(self):
        """THE case that loses money: a card that hands back a pubkey it cannot sign for, or
        signs with a key other than the one it exported."""
        other = secrets.randbelow(V.N - 1) + 1
        self.assertFalse(V.verify(self.pub, self.digest, sign(other, self.digest)))

    def test_rejects_a_signature_over_a_DIFFERENT_digest(self):
        self.assertFalse(V.verify(self.pub, secrets.token_bytes(32), self.sig))

    def test_rejects_a_tampered_r(self):
        bad = bytearray(self.sig)
        bad[0] ^= 0x01
        self.assertFalse(V.verify(self.pub, self.digest, bytes(bad)))

    def test_rejects_a_tampered_s(self):
        bad = bytearray(self.sig)
        bad[63] ^= 0x01
        self.assertFalse(V.verify(self.pub, self.digest, bytes(bad)))

    def test_rejects_zero_r_and_zero_s(self):
        """r=0 or s=0 are the classic accept-anything bugs in naive implementations."""
        r = self.sig[:32]
        s = self.sig[32:]
        self.assertFalse(V.verify(self.pub, self.digest, bytes(32) + s))
        self.assertFalse(V.verify(self.pub, self.digest, r + bytes(32)))
        self.assertFalse(V.verify(self.pub, self.digest, bytes(64)))

    def test_rejects_r_or_s_at_the_group_order(self):
        """r or s >= N must be rejected; accepting them admits malleable/forged pairs."""
        n = V.N.to_bytes(32, "big")
        self.assertFalse(V.verify(self.pub, self.digest, n + self.sig[32:]))
        self.assertFalse(V.verify(self.pub, self.digest, self.sig[:32] + n))

    def test_rejects_a_wrong_length_signature(self):
        for bad in (b"", self.sig[:63], self.sig + b"\x00", b"\x00" * 32):
            self.assertFalse(V.verify(self.pub, self.digest, bad),
                             "accepted a %d-byte signature" % len(bad))

    def test_rejects_an_all_zero_signature_against_any_key(self):
        self.assertFalse(V.verify(self.pub, self.digest, bytes(64)))

    # ------------------------------------------------------------------ pubkey parsing
    def test_parses_the_spki_der_the_card_exports(self):
        pt = V.point_from_der(spki(self.pub))
        self.assertEqual(pt, self.pub)

    def test_rejects_a_point_not_on_the_curve(self):
        """A pubkey off the curve is a corrupt or hostile export; deriving an address from it
        would produce an unspendable account."""
        with self.assertRaises(Exception):
            V.point_from_bytes(b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big"))

    def test_on_curve_check_is_real(self):
        self.assertTrue(V.is_on_curve(self.pub))
        self.assertFalse(V.is_on_curve((self.pub[0], (self.pub[1] + 1) % V.P)))

    # ------------------------------------------------------------------ CLI contract
    def test_cli_exits_zero_only_for_a_valid_signature(self):
        """The ceremony branches on the EXIT CODE, not on stdout — so the exit code is the
        contract, and both directions of it are load-bearing."""
        tmp = tempfile.mkdtemp()
        der = os.path.join(tmp, "pub.der")
        dig = os.path.join(tmp, "d.bin")
        sig = os.path.join(tmp, "s.bin")
        with open(der, "wb") as fh:
            fh.write(spki(self.pub))
        with open(dig, "wb") as fh:
            fh.write(self.digest)
        with open(sig, "wb") as fh:
            fh.write(self.sig)
        good = subprocess.run([sys.executable, SCRIPT, "--der", der, "--digest", dig, "--sig", sig],
                              capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr.decode()[:300])

        other = secrets.randbelow(V.N - 1) + 1
        with open(sig, "wb") as fh:
            fh.write(sign(other, self.digest))
        bad = subprocess.run([sys.executable, SCRIPT, "--der", der, "--digest", dig, "--sig", sig],
                             capture_output=True)
        self.assertNotEqual(bad.returncode, 0, "exited 0 for a signature from the WRONG key")

    def test_cli_fails_on_a_missing_file(self):
        r = subprocess.run([sys.executable, SCRIPT, "--der", "/nonexistent",
                            "--digest", "/nonexistent", "--sig", "/nonexistent"],
                           capture_output=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
