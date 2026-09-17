#!/usr/bin/env python3
"""Adversarial tests for cvc-devaut-verify.py — the offline CVC check behind device identity.

WHY THIS FILE MATTERS: the Nitrokey gate (RUNBOOK-NITROKEY-GATE.md §2.3) and rack
commissioning (B7) both rest on the C.DevAut certificate. Until now the genuineness arm was a
STRING check ("CAR names a CardContact Device Issuer CA") and the parse was a tag-substring
search in hsm-devaut-id.js — two places where a check can LOOK green while proving nothing.
cvc-devaut-verify.py replaces both with a real TR-03110 parse and a cryptographic chain
verification. If the verifier ever went green unconditionally — accepted a tampered
certificate, treated a missing trust anchor as a skip, or passed a self-signed cert as
CA-issued — the gate would certify a device nothing vouches for, which is exactly the
substitution attack commissioning exists to catch.

So this pins both directions on fixtures generated IN-TEST with pycvc's own create API (a
CVCA -> Device Issuer CA -> device chain, no hardware needed): it must ACCEPT a genuine
chain, and REJECT a tampered blob, a self-signed cert under --require-external-car, a wrong
--expect-* pin, a missing trust anchor, and unparsable input — with the house exit-code
contract (0 verified / 1 failed / 2 operator error).
"""
import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cvc.certificates import CVC
from cvc import oid
from cvc.terminal import TypeAT

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
SCRIPT = os.path.join(_SCRIPTS, "cvc-devaut-verify.py")

CVCA_CHR = b"ZETCVCA00001"
DICA_CHR = b"ZETDICA00001"
DEV_CHR = b"ZETDEVAUT0001"


def load():
    ldr = importlib.machinery.SourceFileLoader("cdv", SCRIPT)
    spec = importlib.util.spec_from_loader("cdv", ldr)
    mod = importlib.util.module_from_spec(spec)
    ldr.exec_module(mod)
    return mod


V = load()


def make_cert(pubkey, signkey, car, chr_, role=None, days=90):
    scheme = oid.ID_TA_ECDSA_SHA_256
    return CVC().cert(pubkey=pubkey, scheme=scheme, signkey=signkey, signscheme=scheme,
                      car=car, chr=chr_, role=role, days=days).encode()


class CvcDevautVerifyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.trust = os.path.join(cls.tmp, "trust")
        os.mkdir(cls.trust)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = make_cert(ca_key.public_key(), ca_key, CVCA_CHR, CVCA_CHR, TypeAT(TypeAT.CVCA), 365)
        dica_key = ec.generate_private_key(ec.SECP256R1())
        dica = make_cert(dica_key.public_key(), ca_key, CVCA_CHR, DICA_CHR,
                         TypeAT(TypeAT.DV_domestic), 180)
        dev_key = ec.generate_private_key(ec.SECP256R1())
        cls.dev = make_cert(dev_key.public_key(), dica_key, DICA_CHR, DEV_CHR)
        # trust dir, certs named by CHR — the cvc-print convention the verifier follows
        with open(os.path.join(cls.trust, CVCA_CHR.decode()), "wb") as f:
            f.write(ca)
        with open(os.path.join(cls.trust, DICA_CHR.decode()), "wb") as f:
            f.write(dica)
        cls.ca = ca
        cls.certfile = os.path.join(cls.tmp, "devaut.bin")
        with open(cls.certfile, "wb") as f:
            f.write(cls.dev)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)

    def write_tmp(self, name, data, mode="wb"):
        p = os.path.join(self.tmp, name)
        with open(p, mode) as f:
            f.write(data)
        return p

    # ------------------------------------------------------------------ must accept
    def test_accepts_a_genuine_chain(self):
        """If this fails the gate blocks on a genuine device — the opposite failure, but
        still a failure."""
        r = self.run_cli("--cert", self.certfile, "--trust-dir", self.trust)
        self.assertEqual(r.returncode, 0, r.stderr[:400])
        self.assertIn("CVC_CHAIN=verified", r.stdout)
        self.assertIn(f"CVC_CHR={DEV_CHR.decode()}", r.stdout)
        self.assertIn(f"CVC_CAR={DICA_CHR.decode()}", r.stdout)
        self.assertIn("CVC_SCHEME=ECDSA_SHA_256", r.stdout)

    def test_accepts_hex_input_and_matching_pins(self):
        hexfile = self.write_tmp("devaut.hex", self.dev.hex() + "\n", "w")
        r = self.run_cli("--hex", hexfile, "--require-external-car",
                         "--expect-chr", DEV_CHR.decode(),
                         "--expect-car", DICA_CHR.decode(),
                         "--expect-sha256", hashlib.sha256(self.dev).hexdigest())
        self.assertEqual(r.returncode, 0, r.stderr[:400])

    def test_self_signed_root_still_verifies_as_a_root(self):
        """A self-signed cert is not automatically garbage — the trust anchor IS one. It must
        pass chain verification and fail only the --require-external-car check."""
        cafile = self.write_tmp("cvca.bin", self.ca)
        r = self.run_cli("--cert", cafile, "--trust-dir", self.trust)
        self.assertEqual(r.returncode, 0, r.stderr[:400])

    # ------------------------------------------------------------------ must reject
    def test_rejects_a_tampered_certificate(self):
        """THE negative control: flip one byte INSIDE the signature (ASN.1 stays intact, so
        this exercises the cryptographic check, not the parser). A verifier that never goes
        red here is worthless no matter how green it goes above."""
        i = self.dev.index(b"\x5f\x37")  # signature tag
        bad = bytearray(self.dev)
        bad[i + 5] ^= 0x01
        badfile = self.write_tmp("tampered.bin", bytes(bad))
        r = self.run_cli("--cert", badfile, "--trust-dir", self.trust)
        self.assertEqual(r.returncode, 1, "accepted a tampered certificate")
        self.assertIn("CVC_CHAIN=failed", r.stdout)

    def test_rejects_self_signed_when_external_car_required(self):
        """The measured Pico posture (CHR == CAR) must fail the Nitrokey genuineness check."""
        cafile = self.write_tmp("cvca2.bin", self.ca)
        r = self.run_cli("--cert", cafile, "--require-external-car")
        self.assertEqual(r.returncode, 1)
        self.assertIn("SELF-SIGNED", r.stderr)

    def test_rejects_a_wrong_expect_chr(self):
        r = self.run_cli("--cert", self.certfile, "--expect-chr", "NOTTHEDEVICE1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("CHR MISMATCH", r.stderr)

    def test_rejects_a_wrong_expect_car(self):
        r = self.run_cli("--cert", self.certfile, "--expect-car", "NOTTHECA00001")
        self.assertEqual(r.returncode, 1)
        self.assertIn("CAR MISMATCH", r.stderr)

    def test_rejects_a_wrong_expect_sha256(self):
        r = self.run_cli("--cert", self.certfile, "--expect-sha256", "00" * 32)
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIGEST MISMATCH", r.stderr)

    def test_missing_trust_anchor_is_a_failure_not_a_skip(self):
        """The classic way a chain check goes soft: treat 'issuer cert not found' as N/A.
        Here it must go red."""
        empty = os.path.join(self.tmp, "empty-trust")
        os.mkdir(empty)
        r = self.run_cli("--cert", self.certfile, "--trust-dir", empty)
        self.assertEqual(r.returncode, 1, "missing trust anchor was not a failure")

    def test_rejects_garbage_input(self):
        g = self.write_tmp("garbage.bin", os.urandom(200))
        r = self.run_cli("--cert", g)
        self.assertEqual(r.returncode, 1, "unparsable input must fail closed, not error or pass")

    # ------------------------------------------------------------------ operator errors (rc=2)
    def test_missing_input_file_is_an_operator_error(self):
        r = self.run_cli("--cert", os.path.join(self.tmp, "nonexistent.bin"))
        self.assertEqual(r.returncode, 2)

    def test_empty_input_file_is_an_operator_error(self):
        e = self.write_tmp("empty.bin", b"")
        r = self.run_cli("--cert", e)
        self.assertEqual(r.returncode, 2)

    def test_bad_hex_is_an_operator_error(self):
        h = self.write_tmp("bad.hex", "zzzz not hex\n", "w")
        r = self.run_cli("--hex", h)
        self.assertEqual(r.returncode, 2)

    def test_nonexistent_trust_dir_is_an_operator_error(self):
        r = self.run_cli("--cert", self.certfile,
                         "--trust-dir", os.path.join(self.tmp, "no-such-dir"))
        self.assertEqual(r.returncode, 2)

    # ------------------------------------------------------------------ readout contract
    def test_digest_in_output_matches_the_input_file(self):
        """commission-card.sh pins DEVAUT_SHA256 from the card side; this value must be
        reproducible offline from the same bytes."""
        r = self.run_cli("--cert", self.certfile)
        self.assertEqual(r.returncode, 0, r.stderr[:400])
        self.assertIn(f"CVC_SHA256={hashlib.sha256(self.dev).hexdigest()}", r.stdout)
        self.assertIn("CVC_CHAIN=unverified", r.stdout)
        self.assertIn("CHAIN UNVERIFIED", r.stderr)

    def test_bcd_date_handles_both_encodings(self):
        """pycvc emits one byte per digit; a packed on-card encoding is two nibbles per byte.
        Refuse anything else rather than printing a plausible wrong date."""
        self.assertEqual(V.fmt_bcd_date(bytes([2, 6, 0, 8, 0, 5])), "2026-08-05")
        self.assertEqual(V.fmt_bcd_date(bytes([0x26, 0x08, 0x05])), "2026-08-05")
        with self.assertRaises(ValueError):
            V.fmt_bcd_date(bytes([0x26, 0x08]))
        with self.assertRaises(ValueError):
            V.fmt_bcd_date(bytes([0x2A, 0x08, 0x05]))



# TWO REAL EF 2F02 blobs, read off the same staging Pico (serial ESP2202E14A) ninety minutes
# apart on 2026-08-06 while its firmware was being iterated. Public data by construction — a
# device certificate is what the card hands out to prove itself — and the keys are throwaway.
#
# Keeping BOTH is the point. The board emitted two different structures in one morning:
#
#   07:41  940 B   0x67 authenticated request (undated) ++ 0x7F21 certificate   sha 567f0b…
#   09:31  443 B   0x7F21 certificate only, dated 2023-03-21 -> 2070-12-31      sha 475ae1…
#
# CHR stayed ESP2202E14A00001 through both — it is derived from the board id — while the digest
# and the element count did not. So the parser has to handle both shapes, and anything that pins
# the DIGEST is pinning something that moves whenever the firmware is rebuilt. The 07:41 capture
# stays even though the card no longer produces it: the undated-request form is what broke the
# verifier, and a regression fixture is worth more than a current one.
#
# It is here because the in-test fixtures above are all built with CVC().cert(..., days=90), so
# every one of them is a well-formed, dated, single certificate — and the verifier passed all 16
# of them while being unable to read the actual artifact it exists to read. A generated fixture
# only ever tests the shapes you thought of. This is the shape the hardware really produces:
#   * TWO concatenated top-level elements, not one (497B + 443B = 940B)
#   * the first is a 0x67 authenticated REQUEST, which carries NO validity dates
#   * both are self-signed: CHR == CAR == ESP2202E14A00001
#   * the device key is on secp256k1
GOLDEN_PICO_DEVAUT = (
    "678201ED7F218201937F4E82014B5F2901004210455350323230324531344130303030317F4982011D060A04007F0007"
    "02020202038120FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F822000000000000000"
    "000000000000000000000000000000000000000000000000008320000000000000000000000000000000000000000000"
    "000000000000000000000784410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483A"
    "DA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B88520FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "BAAEDCE6AF48A03BBFD25E8CD036414186410466D5C0119B82CDA689B5F7DF10AC369A595C848456C138B40994B8D5D3"
    "0612D3FE7993CB3DBDD2B06D39E7BE6E4C469D8C04DEF09BA76BC6C87835FACDCCBB5C8701015F201045535032323032"
    "4531344130303030315F3740510F9EDE6592FE89534DE359E04391D8266D4C64558FBE9347B48B84FCD64741EF9F53A0"
    "8207420F00D0464F921CB31A661FEDE4FAF728B4302AD922F00DA3BF4210455350323230324531344130303030315F37"
    "407A4446352E69B9ACCFCCE39A4243D4F4369DDF4F219B9B51058422667FC1035303DFCE6782DB75113B99245BE1C5D2"
    "F16A18FE5EDE327CE504CC7D8E336BA7E77F218201B67F4E82016E5F2901004210455350323230324531344130303030"
    "317F4982011D060A04007F000702020202038120FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "FFFFFC2F8220000000000000000000000000000000000000000000000000000000000000000083200000000000000000"
    "00000000000000000000000000000000000000000000000784410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2D"
    "CE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B88520FFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036414186410466D5C0119B82CDA689B5F7DF10AC369A"
    "595C848456C138B40994B8D5D30612D3FE7993CB3DBDD2B06D39E7BE6E4C469D8C04DEF09BA76BC6C87835FACDCCBB5C"
    "8701015F2010455350323230324531344130303030315F4C0E060904007F0007030102025301005F2506020300030201"
    "5F24060700010203015F37404D82885DED9C4D67D9E04E1FF221B0D84D8EC30CDCA70E904E0D23CE0B5A1EE4924F0A69"
    "71F608038FC3F61457D0BC12494F985099D4C7F7CF8F2398CA0EBAB3"
)
GOLDEN_CHR = "ESP2202E14A00001"

# The 09:31 capture: the same board after a firmware iteration — one bare 0x7F21 certificate,
# dated, still self-signed. Same CHR, different digest, different element count.
GOLDEN_PICO_DEVAUT_V2 = (
    "7F218201B67F4E82016E5F2901004210455350323230324531344130303030317F4982011D060A04007F000702020202"
    "038120FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F82200000000000000000000000"
    "000000000000000000000000000000000000000000832000000000000000000000000000000000000000000000000000"
    "0000000000000784410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3"
    "C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B88520FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6"
    "AF48A03BBFD25E8CD036414186410466D5C0119B82CDA689B5F7DF10AC369A595C848456C138B40994B8D5D30612D3FE"
    "7993CB3DBDD2B06D39E7BE6E4C469D8C04DEF09BA76BC6C87835FACDCCBB5C8701015F20104553503232303245313441"
    "30303030317F4C0E060904007F0007030102025301005F25060203000302015F24060700010203015F3740A6280F3743"
    "AD0049337BA029DE224A76C50D032FA508D94DA2B03E7F192CED150FB882FE52C08AF8FB2A060509296CB7EE1E601397"
    "D2B14DE3AFA398EBECD34D"
)


class GoldenPicoDevautTest(unittest.TestCase):
    """Regression cover for the real hardware artifact. Every assertion here failed before
    2026-08-06: the verifier called c.valid() unconditionally, an authenticated request has no
    validity period, and the resulting AttributeError was caught by a blanket `except` that
    reported a perfectly readable certificate as 'not a parseable CVC certificate'."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.blob = bytes.fromhex(GOLDEN_PICO_DEVAUT)
        cls.hexfile = os.path.join(cls.tmp, "golden.hex")
        with open(cls.hexfile, "w") as f:
            f.write(GOLDEN_PICO_DEVAUT)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)

    def test_the_real_card_certificate_parses(self):
        """THE regression. If this goes red the gate cannot read the device it is gating."""
        self.assertEqual(len(self.blob), 940)
        r = self.run_cli("--hex", self.hexfile)
        self.assertEqual(r.returncode, 0, r.stderr[:500])
        self.assertIn(f"CVC_CHR={GOLDEN_CHR}", r.stdout)
        self.assertIn(f"CVC_CAR={GOLDEN_CHR}", r.stdout)
        self.assertIn("CVC_SCHEME=ECDSA_SHA_256", r.stdout)

    def test_an_undated_request_is_reported_as_undated_not_as_unparseable(self):
        r = self.run_cli("--hex", self.hexfile)
        self.assertIn("CVC_DATED=no", r.stdout)
        self.assertIn("CVC_SINCE=n/a", r.stdout)
        self.assertNotIn("not a parseable CVC", r.stderr)
        self.assertIn("NO VALIDITY PERIOD", r.stderr, "the operator is not told why there are no dates")

    def test_the_concatenated_structure_is_reported(self):
        """EF 2F02 is not one certificate, and a reader who assumes it is will pin the wrong
        bytes. The element walk must say so out loud."""
        r = self.run_cli("--hex", self.hexfile)
        self.assertIn("CVC_ELEMENTS=2", r.stdout)
        self.assertIn("CVC_ELEMENT_1=0x67", r.stdout)
        self.assertIn("CVC_ELEMENT_2=0x7F21", r.stdout)
        self.assertEqual([(0x67, 493), (0x7F21, 438)], V.top_level_elements(self.blob))

    def test_the_real_card_is_refused_under_the_nitrokey_gate_posture(self):
        """CHR == CAR: nothing above this device vouches for it. Expected on a Pico, and a hard
        stop for anything claiming to be a Nitrokey."""
        r = self.run_cli("--hex", self.hexfile, "--require-external-car")
        self.assertEqual(r.returncode, 1)
        self.assertIn("SELF-SIGNED", r.stderr)

    def test_the_digest_is_the_one_commissioning_would_pin(self):
        want = hashlib.sha256(self.blob).hexdigest()
        r = self.run_cli("--hex", self.hexfile, "--expect-sha256", want)
        self.assertEqual(r.returncode, 0, r.stderr[:400])
        self.assertIn(f"CVC_SHA256={want}", r.stdout)

    def test_a_normal_dated_certificate_still_reports_its_dates(self):
        """The other side of the contract: making dates optional must not make them invisible."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = make_cert(key.public_key(), key, b"ZETSOLO00001", b"ZETSOLO00001",
                         TypeAT(TypeAT.CVCA), 365)
        p = os.path.join(self.tmp, "dated.bin")
        with open(p, "wb") as f:
            f.write(cert)
        r = self.run_cli("--cert", p)
        self.assertEqual(r.returncode, 0, r.stderr[:400])
        self.assertIn("CVC_DATED=yes", r.stdout)
        self.assertIn("CVC_ELEMENTS=1", r.stdout)
        self.assertNotIn("CVC_SINCE=n/a", r.stdout)

    def test_the_second_real_shape_from_the_same_board_also_parses(self):
        """Same card, ninety minutes later, after a firmware iteration: one bare dated 0x7F21.
        Both shapes must read, or the gate goes red every time the firmware is rebuilt."""
        blob = bytes.fromhex(GOLDEN_PICO_DEVAUT_V2)
        self.assertEqual(len(blob), 443)
        p = os.path.join(self.tmp, "golden-v2.hex")
        with open(p, "w") as f:
            f.write(GOLDEN_PICO_DEVAUT_V2)
        r = self.run_cli("--hex", p)
        self.assertEqual(r.returncode, 0, r.stderr[:500])
        self.assertIn(f"CVC_CHR={GOLDEN_CHR}", r.stdout)
        self.assertIn("CVC_ELEMENTS=1", r.stdout)
        self.assertIn("CVC_ELEMENT_1=0x7F21", r.stdout)
        self.assertIn("CVC_DATED=yes", r.stdout)
        self.assertIn("CVC_EXPIRES=2070-12-31", r.stdout)

    def test_the_board_identity_held_while_the_digest_did_not(self):
        """The finding that decides what commissioning may pin: across a firmware rebuild the
        CHR is stable (it is derived from the board id) and the digest is not. Pinning the digest
        detects a rebuild as loudly as a substitution — correct, but only if you expect it."""
        v1, v2 = bytes.fromhex(GOLDEN_PICO_DEVAUT), bytes.fromhex(GOLDEN_PICO_DEVAUT_V2)
        self.assertNotEqual(hashlib.sha256(v1).hexdigest(), hashlib.sha256(v2).hexdigest())
        for blob in (v1, v2):
            c = CVC().decode(blob)
            self.assertEqual(bytes(c.chr()).decode(), GOLDEN_CHR)
            self.assertEqual(bytes(c.car()).decode(), GOLDEN_CHR, "both captures are self-signed")

    def test_garbage_still_names_the_tags_it_found(self):
        """A parse failure must be diagnosable. 'not parseable' with no detail is what sent the
        first investigation of this bug looking at the firmware instead of at this script."""
        p = os.path.join(self.tmp, "garbage.bin")
        with open(p, "wb") as f:
            f.write(bytes.fromhex("7F2103AABBCC"))
        r = self.run_cli("--cert", p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("top-level tags present", r.stderr)


GOLDEN_NITROKEY_EF2F02 = (
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
TRUST_ANCHORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "trust-anchors", "smartcard-hsm")


class GoldenNitrokeyDevautTest(unittest.TestCase):
    """The real EF 2F02 of Nitrokey HSM 2 DENK0404144 (fw 4.1), read 2026-09-17, against the pinned
    CardContact root. The Pico golden above is the self-signed shape; this is the genuine one,
    and it is the only fixture that proves the gate's genuineness check accepts real hardware."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.blob = bytes.fromhex(GOLDEN_NITROKEY_EF2F02)
        cls.hexfile = os.path.join(cls.tmp, "nitrokey.hex")
        with open(cls.hexfile, "w") as f:
            f.write(GOLDEN_NITROKEY_EF2F02)
        # The issuer CA certificate is the second element of EF 2F02 (it travels on the card).
        n = cls.blob[3] + 3 + 1
        cls.dica = cls.blob[n:]
        cls.trust = os.path.join(cls.tmp, "trust")
        os.mkdir(cls.trust)
        with open(os.path.join(TRUST_ANCHORS, "DESRCACC100001"), "rb") as f:
            cls.root = f.read()
        cls._write_trust(cls.trust, cls.root)

    @classmethod
    def _write_trust(cls, d, root):
        with open(os.path.join(d, "DESRCACC100001"), "wb") as f:
            f.write(root)
        with open(os.path.join(d, "DEDINK0400001"), "wb") as f:
            f.write(cls.dica)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)

    def test_the_genuine_chain_verifies_to_the_cardcontact_root(self):
        self.assertEqual(hashlib.sha256(self.blob).hexdigest(),
                         "1b7763b72b871f37a4cc43808b72d65a915a488420fa18c0137f8389260d9aa4")
        r = self.run_cli("--hex", self.hexfile, "--trust-dir", self.trust,
                         "--require-external-car", "--expect-chr", "DENK040414400000",
                         "--expect-car", "DEDINK0400001")
        self.assertEqual(r.returncode, 0, r.stderr[:500])
        self.assertIn("CVC_CHAIN=verified", r.stdout)
        self.assertIn("CVC_ELEMENTS=2", r.stdout)

    def test_a_different_root_key_is_refused(self):
        """THE control for the test above: the same root certificate with a different, VALID
        public point (the curve generator). If this passes, the root file is not being used."""
        root = bytearray(self.root)
        g = root.find(bytes.fromhex("8441048BD2"))
        p = root.find(bytes.fromhex("8641046D025A"))
        self.assertTrue(g > 0 and p > 0, "root layout changed under this test")
        root[p + 2:p + 67] = root[g + 2:g + 67]
        d = os.path.join(self.tmp, "otherkey")
        os.mkdir(d)
        self._write_trust(d, bytes(root))
        r = self.run_cli("--hex", self.hexfile, "--trust-dir", d)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("CVC_CHAIN=failed", r.stdout)

    def test_an_anchor_whose_point_is_not_on_the_curve_fails_closed_without_a_traceback(self):
        root = bytearray(self.root)
        p = root.find(bytes.fromhex("8641046D025A"))
        root[p + 12] ^= 0x01
        d = os.path.join(self.tmp, "badpoint")
        os.mkdir(d)
        self._write_trust(d, bytes(root))
        r = self.run_cli("--hex", self.hexfile, "--trust-dir", d)
        self.assertEqual(r.returncode, 1, r.stderr[:500])
        self.assertIn("CVC_CHAIN=failed", r.stdout)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
