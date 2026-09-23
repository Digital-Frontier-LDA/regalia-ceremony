#!/usr/bin/env python3
"""Tests for hsm-key-attestation-verify.py against REAL Nitrokey HSM 2 artifacts.

The blobs are EF 2F02 and EF CE01 read from DENK0404144 (fw 4.1) on 2026-09-17, immediately after
`pkcs11-tool --keypairgen --key-type EC:secp256k1 --id 01`. They are public data: a device
certificate chain and a public key. Every accept has a matching reject, because a verifier that
only ever goes green proves nothing (TESTING.md §18).
"""
import hashlib
import importlib.util
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
ANCHORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "trust-anchors",
                       "smartcard-hsm")


class KeyAttestationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.ef = bytes.fromhex(EF2F02)
        cls.ce = bytes.fromhex(CE01)
        cls.ef_path = cls.put("ef2f02.bin", cls.ef)
        cls.ce_path = cls.put("ce01.bin", cls.ce)
        # A trust directory holding the pinned root and the card's own issuer certificate (the
        # second element of EF 2F02), named by CHR as the verifier expects.
        cls.trust = os.path.join(cls.tmp, "trust")
        os.mkdir(cls.trust)
        n = cls.ef[3] + 4
        with open(os.path.join(cls.trust, "DEDINK0400001"), "wb") as f:
            f.write(cls.ef[n:])
        with open(os.path.join(ANCHORS, "DESRCACC100001"), "rb") as src, \
                open(os.path.join(cls.trust, "DESRCACC100001"), "wb") as dst:
            dst.write(src.read())

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
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.ef_path, "--attestation", self.ce_path,
                         "--expect-point", TOKEN_POINT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ATTEST_CAR=DENK040414400000", r.stdout)
        self.assertIn("ATTEST_SIGNATURE=verified", r.stdout)
        self.assertIn("ATTESTED_POINT_MATCHES=yes", r.stdout)

    def test_a_flipped_signature_byte_is_refused(self):
        bad = bytearray(self.ce)
        bad[-2] ^= 0x01
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.ef_path, "--attestation", self.put("bad-sig.bin", bytes(bad)))
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATTEST_SIGNATURE=failed", r.stdout)

    def test_a_different_key_point_is_refused(self):
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.ef_path, "--attestation", self.ce_path,
                         "--expect-point", TOKEN_POINT[:-1] + "0")
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATTESTED_POINT_MATCHES=no", r.stdout)

    def test_the_issuer_ca_key_is_not_accepted_in_place_of_the_device_key(self):
        """EF 2F02 minus its first element starts with the issuer CA certificate. Signed by the
        device, not the CA: the CAR check and the signature must both refuse."""
        n = self.ef[3] + 4
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.put("dica-first.bin", self.ef[n:]), "--attestation", self.ce_path)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATTEST_SIGNATURE=failed", r.stdout)

    def test_a_tampered_attested_point_is_refused(self):
        """Swapping the key inside the request (the substitution attack this exists to catch)
        breaks the device signature even when --expect-point is not given."""
        i = self.ce.find(bytes.fromhex(TOKEN_POINT[:20]))
        self.assertGreater(i, 0)
        bad = bytearray(self.ce)
        bad[i + 12] ^= 0x01
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.ef_path, "--attestation", self.put("bad-point.bin", bytes(bad)))
        self.assertEqual(r.returncode, 1)

    def test_garbage_is_a_failure_not_a_crash(self):
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.ef_path, "--attestation", self.put("junk.bin", os.urandom(64)))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_without_assurance_about_the_device_certificate_it_refuses_to_report(self):
        """THE finding this contract exists for. Verifying the attestation under whatever key the
        caller hands in proves nothing: an attacker's certificate plus an attestation forged under
        its own private key passes every signature check. Neither arm given is an operator error,
        not a verification."""
        r = self.run_cli("--devaut", self.ef_path, "--attestation", self.ce_path)
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("refusing to report an attestation", r.stderr)
        self.assertNotIn("ATTEST_SIGNATURE=verified", r.stdout)

    def test_a_device_certificate_that_does_not_chain_is_refused_before_the_attestation(self):
        """The attacker's arm, end to end: a certificate that does not validate to the anchor is
        refused even though the attestation would verify under the key it carries."""
        bad = bytearray(self.ef)
        i = bad.index(b"\x5f\x37")           # the device certificate's signature
        bad[i + 8] ^= 0x01
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.put("bad-chain.bin", bytes(bad)),
                         "--attestation", self.ce_path)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("DEVAUT_CHAIN=failed", r.stdout)
        self.assertNotIn("ATTEST_SIGNATURE=verified", r.stdout)

    def test_the_explicit_opt_out_is_recorded_in_the_output(self):
        """A pipeline that validated the same bytes earlier may say so — and a reader of the
        transcript can see that it did, rather than assuming a chain check happened."""
        r = self.run_cli("--devaut-already-verified", "--devaut", self.ef_path,
                         "--attestation", self.ce_path, "--expect-point", TOKEN_POINT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DEVAUT_CHAIN=asserted-by-caller", r.stdout)

    def test_the_verified_chain_is_reported(self):
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.ef_path,
                         "--attestation", self.ce_path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DEVAUT_CHAIN=verified", r.stdout)

    def test_the_chain_is_validated_against_the_bytes_this_process_read(self):
        """TOCTOU: the child must not re-open the caller's path (CWE-367).

        Two reads of one path can see two different files — a local process that swaps the path
        between them gets a trusted certificate validated while the attestation is checked against
        the bytes the parent already cached.

        A pipe makes that testable without a race: it can be read exactly once. If the chain check
        re-opened the path it would find an empty stream and fail; reading once and handing the
        child those bytes is what makes this pass. Deleting a symlink mid-run was tried first and
        was itself racy — it failed whether or not the defect was present, which proves nothing.
        """
        proc = subprocess.run(
            [sys.executable, SCRIPT, "--trust-dir", self.trust, "--devaut", "/dev/stdin",
             "--attestation", self.ce_path],
            input=self.ef, capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertIn(b"DEVAUT_CHAIN=verified", proc.stdout)

    def test_a_missing_file_is_an_operator_error(self):
        r = self.run_cli("--trust-dir", self.trust, "--devaut", self.ef_path, "--attestation", os.path.join(self.tmp, "nope.bin"))
        self.assertEqual(r.returncode, 2)


# ---------------------------------------------------------------------------------------------------
# RSA AND EC, SIDE BY SIDE, FROM ONE CARD (regalia#28 criterion 4 rehearsal, ADR-0002 D1).
#
# Read from DENK0404144 (fw 4.1) on 2026-09-23, read-only, right after two keys were GENERATED on the
# card: a P-256 key at PKCS#11 id 20 (key ref 3, EF CE03) and an RSA-2048 key at id 21 (key ref 4,
# EF CE04). The SPKIs are what `pkcs11-tool --read-object --type pubkey --id …` wrote for them. Public
# data only: a device-signed request carrying a public key, and the public key.
#
# The RSA pair is the one that could not be commissioned before this change: the verifier read only
# the EC point tag (0x86), found none in an RSA key (0x81 modulus, 0x82 exponent) and refused the
# attestation as unparseable. The digests are hard-coded, not derived from the bytes below, so a
# wrong fixture cannot agree with itself.
CE03_EC_ID20 = (
    "678201E67F2182018C7F4E8201445F29010042095554434130303030317F4982011D060A04007F000702020202038120"
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF8220FFFFFFFF00000001000000000000"
    "000000000000FFFFFFFFFFFFFFFFFFFFFFFC83205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E"
    "27D2604B8441046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8E"
    "E7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F58520FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E"
    "84F3B9CAC2FC632551864104CFEAE11953BEFEBC2489796F251E0762804BC7D843019853584C276B88002C09C931A6AC"
    "4703D1F769BBDB7C1EFA469EECBF276868B223D000FD211E5590262B8701015F201044454E4B30343034313434303030"
    "30315F3740E605C41659E8C01421565D65BC3CF4A494169BF284D4E159E3B8BBCEE3ADA4D0EBA65AB9827CD185C32619"
    "FA0A5080563EB08CE2A2DC2075914FBD06938106EF421044454E4B3034303431343430303030305F3740042EE12ACF33"
    "9326252DE0FB0BC070C1275902A54187765B648D370C0CBA10C01A286CD58E07D6DC229373A054F59FA5DC664185049E"
    "196706CF47D5E3C70FE5"
)
SPKI_EC_ID20 = (
    "3059301306072A8648CE3D020106082A8648CE3D03010703420004CFEAE11953BEFEBC2489796F251E0762804BC7D843"
    "019853584C276B88002C09C931A6AC4703D1F769BBDB7C1EFA469EECBF276868B223D000FD211E5590262B"
)
PIN_EC_ID20 = "sha256:91493c73de01b630faa8122b131fa09d5241d2c41968213db8cfa4481a331f2a"
CE04_RSA_ID21 = (
    "678202A07F218202467F4E82013C5F29010042095554434130303030317F49820115060A04007F000702020201028182"
    "01009987064B1EF5D88C447704BB3E5D19751D96E72EA3A4DCF9D638C9D84534FF84B3A3F4C3D39F7F854DCB56F6D79F"
    "EC3FE027C8329855475143A1EE6A6474353D55E9282D930C27C281120C1876B79B625C7BFCC34404721EE144514EBB55"
    "0146E400D5D7300B274CA2696DF60DDA9AB87409FD530BF3B4E8C068D509B0EFBD79A50C11D12DA77D98BAA3A1A4EE06"
    "B42A2594CFEEA31CE8190670492C26FB08870263BF68B06D84DC20A89AE14CD95659DE77BD27EA1AA091E8265C8CE1C0"
    "0F6D182BC71E48BA7AF90AD389D24CFA601896C038FFE01806E6FD44455B45252F8E371A407AC18F468586EB877E1AE8"
    "3601B8459029615EE47BC5D6A227CB1CE9E582030100015F201044454E4B3034303431343430303030315F378201007D"
    "AA99DF9938249F7C6130CB92B8B65479959B7D87C3712BC608BECF314BF13821F2FB2C140B38C0959768A31878F8C36E"
    "EA82611A6E44C74DB623FE4148E16E2174185A398D8B78C986EDE09C227873985249E102D14A7AB03630656A8FE5128D"
    "FFA6911BBD83ECE024893FB42F6721CEDBD7030DE7CFCEF3E8BC5E6866F09E2732EEF2F683C8F661AD76CDE0DFB998E1"
    "15335B6856C39366D8D3FB676FD8E345A4F24C4B4EF48D35CE1D72B32453A309AD61DEF10F806988A801F9278AABB167"
    "78F04BAED5771A47C9617AB438D8860330FCC98CB8A99AB3E56020D9DD1E7787051AB593106D1A2AB53B270BFB4148FD"
    "4006331FB850B25C97F1FD8552627C421044454E4B3034303431343430303030305F374034822F4FBCA8AEDF1B0E57AD"
    "D28917523F0820B7816319BD9355A3C2FC79A2B1251E344E96E3E8FFC19C33FE0BEFE4384B48958C2113760DF37B0C2A"
    "935958CE"
)
SPKI_RSA_ID21 = (
    "30820122300D06092A864886F70D01010105000382010F003082010A02820101009987064B1EF5D88C447704BB3E5D19"
    "751D96E72EA3A4DCF9D638C9D84534FF84B3A3F4C3D39F7F854DCB56F6D79FEC3FE027C8329855475143A1EE6A647435"
    "3D55E9282D930C27C281120C1876B79B625C7BFCC34404721EE144514EBB550146E400D5D7300B274CA2696DF60DDA9A"
    "B87409FD530BF3B4E8C068D509B0EFBD79A50C11D12DA77D98BAA3A1A4EE06B42A2594CFEEA31CE8190670492C26FB08"
    "870263BF68B06D84DC20A89AE14CD95659DE77BD27EA1AA091E8265C8CE1C00F6D182BC71E48BA7AF90AD389D24CFA60"
    "1896C038FFE01806E6FD44455B45252F8E371A407AC18F468586EB877E1AE83601B8459029615EE47BC5D6A227CB1CE9"
    "E50203010001"
)
PIN_RSA_ID21 = "sha256:dfa76329fe003cf6bc93c33a1b4041683bb3d91cd573cfefb09720df5bed263f"


def load_verifier():
    spec = importlib.util.spec_from_file_location("hsm_key_attestation_verify", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BothKeyTypesTest(unittest.TestCase):
    """--expect-spki: the attested key IS the token's key, for RSA and EC alike. Each refusal asserted
    by its message, so a refusal for the wrong reason does not count as the guard working."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.ef = bytes.fromhex(EF2F02)
        cls.paths = {}
        for name, hexs in (("ef2f02", EF2F02), ("ce03", CE03_EC_ID20), ("ec.der", SPKI_EC_ID20),
                           ("ce04", CE04_RSA_ID21), ("rsa.der", SPKI_RSA_ID21)):
            cls.paths[name] = cls.put(name, bytes.fromhex(hexs))
        # A DIFFERENT RSA-2048 key, fresh from openssl: same type and size, other modulus.
        cls.paths["other-rsa.der"] = cls.fresh_public_key("other-rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
        cls.paths["ed25519.der"] = cls.fresh_public_key("ed25519", ["-algorithm", "ED25519"])

    @classmethod
    def fresh_public_key(cls, name, genpkey_args):
        """A fresh key's SubjectPublicKeyInfo, via two argv-only openssl calls (no shell)."""
        key = os.path.join(cls.tmp, name + ".key.pem")
        der = os.path.join(cls.tmp, name + ".der")
        subprocess.run(["openssl", "genpkey", *genpkey_args, "-out", key], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER", "-out", der],
                       check=True, capture_output=True)
        return der

    @classmethod
    def put(cls, name, data):
        p = os.path.join(cls.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def verify(self, attestation, *extra, env=None):
        # The anchor directory itself, not a copy: the device certificate must chain to what the
        # repo pins, exactly as commission-card.sh runs it.
        return subprocess.run([sys.executable, SCRIPT, "--trust-dir", ANCHORS, "--devaut", self.paths["ef2f02"],
                               "--attestation", attestation, *extra], capture_output=True, text=True, env=env)

    def assert_verified(self, r):
        self.assertEqual(r.returncode, 0, r.stderr)
        for line in ("DEVAUT_CHAIN=verified", "ATTEST_SIGNATURE=verified", "ATTESTED_KEY_MATCHES=yes"):
            self.assertIn(line, r.stdout.splitlines())

    def assert_mismatch(self, r, why):
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("ATTESTED_KEY_MATCHES=no", r.stdout.splitlines())
        self.assertNotIn("ATTESTED_KEY_MATCHES=yes", r.stdout)
        self.assertIn(why, r.stderr)

    def test_the_fixtures_are_the_measured_keys(self):
        self.assertEqual("sha256:" + hashlib.sha256(bytes.fromhex(SPKI_EC_ID20)).hexdigest(), PIN_EC_ID20)
        self.assertEqual("sha256:" + hashlib.sha256(bytes.fromhex(SPKI_RSA_ID21)).hexdigest(), PIN_RSA_ID21)

    def test_the_real_ec_attestation_matches_its_spki(self):
        r = self.verify(self.paths["ce03"], "--expect-spki", self.paths["ec.der"])
        self.assert_verified(r)
        self.assertIn("ATTESTED_KEY_TYPE=ec", r.stdout)
        self.assertIn(f"EXPECTED_SPKI_SHA256={PIN_EC_ID20}", r.stdout)

    def test_the_real_rsa_attestation_matches_its_spki(self):
        """THE defect: an RSA KEK could not be commissioned at all."""
        r = self.verify(self.paths["ce04"], "--expect-spki", self.paths["rsa.der"])
        self.assert_verified(r)
        self.assertIn("ATTESTED_KEY_TYPE=rsa", r.stdout)
        self.assertIn("ATTESTED_RSA_BITS=2048", r.stdout)
        self.assertIn(f"EXPECTED_SPKI_SHA256={PIN_RSA_ID21}", r.stdout)

    def test_an_rsa_attestation_against_an_ec_spki_is_no(self):
        self.assert_mismatch(self.verify(self.paths["ce04"], "--expect-spki", self.paths["ec.der"]),
                             "the attestation is of an RSA key but the token's key is EC")

    def test_an_ec_attestation_against_an_rsa_spki_is_no(self):
        self.assert_mismatch(self.verify(self.paths["ce03"], "--expect-spki", self.paths["rsa.der"]),
                             "the attestation is of an EC key but the token's key is RSA")

    def test_an_rsa_attestation_against_another_rsa_key_is_no(self):
        """A genuine attestation of a DIFFERENT key — the wrong --kek-ref for --kek-id."""
        self.assert_mismatch(self.verify(self.paths["ce04"], "--expect-spki", self.paths["other-rsa.der"]),
                             "the attested RSA modulus is not the token key's modulus")

    def test_the_same_modulus_with_another_exponent_is_no(self):
        """Modulus AND exponent: a key is both. Built with the attested modulus and e=3, so only the
        exponent comparison can refuse it."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
        n = load_der_public_key(bytes.fromhex(SPKI_RSA_ID21)).public_numbers().n
        der = rsa.RSAPublicNumbers(3, n).public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assert_mismatch(self.verify(self.paths["ce04"], "--expect-spki", self.put("e3.der", der)),
                             "the attested RSA public exponent is not the token key's exponent")

    def test_an_spki_naming_an_unknown_algorithm_is_a_named_no_not_a_traceback(self):
        """A well-formed SPKI whose algorithm OID (1.2.3.4) cryptography does not know raises
        UnsupportedAlgorithm — not ValueError. It must still print the verdict line (review of #40)."""
        unknown = bytes.fromhex("302a300506032a0304032100" + "11" * 32)
        r = self.verify(self.paths["ce04"], "--expect-spki", self.put("unknown-alg.der", unknown))
        self.assertNotIn("Traceback", r.stderr)
        self.assert_mismatch(r, "names a key algorithm this cannot compare")

    def test_an_ec_attestation_against_another_ec_key_is_no(self):
        other = self.fresh_public_key("other-ec", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
        self.assert_mismatch(self.verify(self.paths["ce03"], "--expect-spki", other),
                             "the attested EC point is not the token key's point")

    def test_an_attested_generator_that_is_not_the_spki_curves_is_no(self):
        """The point alone names no curve. One byte of the attested generator (0x84) changed: the
        device signature breaks too, but the key comparison must refuse on its own account."""
        ce = bytearray(bytes.fromhex(CE03_EC_ID20))
        i = ce.index(bytes.fromhex("844104")) + 3
        ce[i + 5] ^= 0x01
        r = self.verify(self.put("bad-g.bin", bytes(ce)), "--expect-spki", self.paths["ec.der"])
        self.assert_mismatch(r, "the attested key is on a different curve than the token key")

    def test_an_attestation_without_domain_parameters_confirms_no_curve(self):
        m = load_verifier()
        der = bytes.fromhex(SPKI_EC_ID20)
        key = {"type": "ec", "point": der[-65:], "generator": None}
        self.assertEqual(m.compare_to_spki(key, der),
                         (False, "the attestation carries no domain parameters, so its curve cannot be confirmed"))

    def test_an_spki_the_card_cannot_attest_is_no(self):
        self.assert_mismatch(self.verify(self.paths["ce04"], "--expect-spki", self.paths["ed25519.der"]),
                             "a SmartCard-HSM attests only RSA and EC keys")

    def test_an_spki_that_does_not_parse_is_no(self):
        self.assert_mismatch(self.verify(self.paths["ce04"], "--expect-spki", self.put("junk.der", b"\x30\x03junk")),
                             "the expected SubjectPublicKeyInfo does not parse")

    def test_a_tampered_rsa_attestation_signature_fails(self):
        ce = bytearray(bytes.fromhex(CE04_RSA_ID21))
        ce[-2] ^= 0x01
        r = self.verify(self.put("bad-rsa-sig.bin", bytes(ce)), "--expect-spki", self.paths["rsa.der"])
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("ATTEST_SIGNATURE=failed", r.stdout.splitlines())
        self.assertIn("the outer signature does not verify under the device key", r.stderr)

    def test_a_substituted_rsa_modulus_fails_the_device_signature(self):
        """The substitution attack: the attacker's modulus in the request AND in the SPKI. The keys
        then 'match' — only the device signature over the request can refuse it."""
        ce = bytearray(bytes.fromhex(CE04_RSA_ID21))
        spki = bytearray(bytes.fromhex(SPKI_RSA_ID21))
        i, j = ce.index(bytes.fromhex("81820100")) + 4, spki.index(bytes.fromhex("0282010100")) + 5
        ce[i + 40] ^= 0x01
        spki[j + 40] ^= 0x01
        r = self.verify(self.put("sub-rsa.bin", bytes(ce)), "--expect-spki", self.put("sub-rsa.der", bytes(spki)))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("ATTESTED_KEY_MATCHES=yes", r.stdout)
        self.assertIn("ATTEST_SIGNATURE=failed", r.stdout)

    def test_an_rsa_attestation_never_matches_a_point(self):
        r = self.verify(self.paths["ce04"], "--expect-point", "04" + "00" * 64)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATTESTED_POINT_MATCHES=no", r.stdout.splitlines())

    def test_a_missing_pycvc_is_its_own_named_failure_first(self):
        """The bench, 2026-09-23: run under the system python3 (no pycvc) this printed "C.DevAut does
        not validate to an anchor" first — a verdict about the card for a problem with the
        interpreter. A package named `cvc` that refuses to import stands in for the missing one, for
        this process AND the chain walker it starts."""
        shadow = os.path.join(self.tmp, "no-pycvc", "cvc")
        os.makedirs(shadow, exist_ok=True)
        with open(os.path.join(shadow, "__init__.py"), "w") as f:
            f.write("raise ImportError('simulated: pycvc is not installed')\n")
        env = dict(os.environ, PYTHONPATH=os.path.dirname(shadow))
        r = self.verify(self.paths["ce04"], "--expect-spki", self.paths["rsa.der"], env=env)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertTrue(r.stderr.startswith("hsm-key-attestation-verify ERROR: MISSING DEPENDENCY — pycvc"), r.stderr)
        self.assertIn("DEPENDENCY_MISSING=pycvc", r.stdout.splitlines())
        self.assertNotIn("does not validate to an anchor", r.stderr)
        self.assertNotIn("DEVAUT_CHAIN=", r.stdout)
        self.assertNotIn("=verified", r.stdout)

    def test_a_chain_the_walker_could_not_evaluate_is_not_reported_as_failed(self):
        """The walker's exit 2 (input or environment) is not a verdict on the card either."""
        r = subprocess.run([sys.executable, SCRIPT, "--trust-dir", ANCHORS, "--devaut", self.put("empty", b""),
                            "--attestation", self.paths["ce04"]], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("DEVAUT_CHAIN=not-evaluated", r.stdout.splitlines())
        self.assertIn("the C.DevAut chain could NOT BE EVALUATED", r.stderr)
        self.assertNotIn("DEVAUT_CHAIN=failed", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=1)
