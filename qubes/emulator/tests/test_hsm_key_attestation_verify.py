#!/usr/bin/env python3
"""Tests for hsm-key-attestation-verify.py against REAL Nitrokey HSM 2 artifacts.

The blobs are EF 2F02 and EF CE01 read from DENK0404144 (fw 4.1) on 2026-09-17, immediately after
`pkcs11-tool --keypairgen --key-type EC:secp256k1 --id 01`. They are public data: a device
certificate chain and a public key. Every accept has a matching reject, because a verifier that
only ever goes green proves nothing (TESTING.md §18).
"""
import os
import subprocess
import sys
import tempfile
import shutil
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts",
                      "hsm-key-attestation-verify.py")

EF2F02 = (
    "7F2181E47F4E819D5F290100420D444544494E4B303430303030317F494F060A04007F00070202020203864104854A60"
    "8E6F7B27D4B990C0EEA68F6C1D738E0E38CC9C6D1CEEDE55C0583F0B7B37363551A876B8EC2B0DB88545ADFE418ABECD"
    "555C128BE81A5C6A0361FCA1DF5F201044454E4B3034303431343430303030307F4C10060B2B0601040181C31F030101"
    "5301005F25060206000502085F24060301000502075F3740A4D5D47D41451FCFAC7C8766EEBA2871CAA8086C6E789AF7"
    "52A7968CF3310852962F428EEE0F209FBB6EB928E6DEFF8AA3CC97F4B8EDC000131683AAF291968F7F2181E47F4E819D"
    "5F290100420E44455352434143433130303030317F494F060A04007F0007020202020386410441BEF11216285DE54D35"
    "BAE22FC4953E99EDD7D0294B45CF578AA8545E5F5BBB8F8AF9150E936F7F77777B1EECC58F2D823FE520EBC430964889"
    "A4463A7EB2425F200D444544494E4B303430303030317F4C10060B2B0601040181C31F0301015301805F250602040100"
    "03005F240603020100020965005F3740039567AA4930C8327D651E45B133B71E90F2C134EB385162B96913C0AB3AC265"
    "110860CDAD312F970C2A652DA8B31BE8A8FAEA5B87CD146D517937D8B8771122"
)
CE01 = (
    "678201E67F2182018C7F4E8201445F29010042095554434130303030317F4982011D060A04007F000702020202038120"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F82200000000000000000000000000000"
    "000000000000000000000000000000000000832000000000000000000000000000000000000000000000000000000000"
    "0000000784410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655D"
    "A4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B88520FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A0"
    "3BBFD25E8CD0364141864104C5007688149BB767A91E1716B3EFC4E80B4408B1BA8A3B83712BBBF963E150BDD7E039AF"
    "0165E4229CAD670398161AE8456FF6B78C2F770A6DC0CF8F6723D34F8701015F201044454E4B30343034313434303030"
    "30315F3740FDC6DEC3D283E27EF40A9BDD1141A3B86E5E7DD57CFD93F08E8EE93937AA83F1D65078067FD049A0CAD2F6"
    "7A62D25B5663BB23E0030977BFAFA790C17796A2F9421044454E4B3034303431343430303030305F3740236FD005C7C1"
    "E36142BE72B2CB753B3250A338C3E7081251531F6C120114837B3A641C03B01A9BAA58766216EE399613006AC1B33A51"
    "891FFC38FF12BB830811"
)
TOKEN_POINT = ("04c5007688149bb767a91e1716b3efc4e80b4408b1ba8a3b83712bbbf963e150bd"
               "d7e039af0165e4229cad670398161ae8456ff6b78c2f770a6dc0cf8f6723d34f")


class KeyAttestationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.ef = bytes.fromhex(EF2F02)
        cls.ce = bytes.fromhex(CE01)
        cls.ef_path = cls.put("ef2f02.bin", cls.ef)
        cls.ce_path = cls.put("ce01.bin", cls.ce)

    @classmethod
    def put(cls, name, data):
        p = os.path.join(cls.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)

    def test_the_real_attestation_verifies_and_names_the_token_key(self):
        r = self.run_cli("--devaut", self.ef_path, "--attestation", self.ce_path,
                         "--expect-point", TOKEN_POINT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ATTEST_CAR=DENK040414400000", r.stdout)
        self.assertIn("ATTEST_SIGNATURE=verified", r.stdout)
        self.assertIn("ATTESTED_POINT_MATCHES=yes", r.stdout)

    def test_a_flipped_signature_byte_is_refused(self):
        bad = bytearray(self.ce)
        bad[-2] ^= 0x01
        r = self.run_cli("--devaut", self.ef_path, "--attestation", self.put("bad-sig.bin", bytes(bad)))
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATTEST_SIGNATURE=failed", r.stdout)

    def test_a_different_key_point_is_refused(self):
        r = self.run_cli("--devaut", self.ef_path, "--attestation", self.ce_path,
                         "--expect-point", TOKEN_POINT[:-1] + "0")
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATTESTED_POINT_MATCHES=no", r.stdout)

    def test_the_issuer_ca_key_is_not_accepted_in_place_of_the_device_key(self):
        """EF 2F02 minus its first element starts with the issuer CA certificate. Signed by the
        device, not the CA: the CAR check and the signature must both refuse."""
        n = self.ef[3] + 4
        r = self.run_cli("--devaut", self.put("dica-first.bin", self.ef[n:]), "--attestation", self.ce_path)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATTEST_SIGNATURE=failed", r.stdout)

    def test_a_tampered_attested_point_is_refused(self):
        """Swapping the key inside the request (the substitution attack this exists to catch)
        breaks the device signature even when --expect-point is not given."""
        i = self.ce.find(bytes.fromhex(TOKEN_POINT[:20]))
        self.assertGreater(i, 0)
        bad = bytearray(self.ce)
        bad[i + 12] ^= 0x01
        r = self.run_cli("--devaut", self.ef_path, "--attestation", self.put("bad-point.bin", bytes(bad)))
        self.assertEqual(r.returncode, 1)

    def test_garbage_is_a_failure_not_a_crash(self):
        r = self.run_cli("--devaut", self.ef_path, "--attestation", self.put("junk.bin", os.urandom(64)))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_a_missing_file_is_an_operator_error(self):
        r = self.run_cli("--devaut", self.ef_path, "--attestation", os.path.join(self.tmp, "nope.bin"))
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
