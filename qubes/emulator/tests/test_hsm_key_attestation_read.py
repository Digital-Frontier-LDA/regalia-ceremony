#!/usr/bin/env python3
"""Tests for hsm-key-attestation-read.sh — the OpenSC-only reader for EF CE<keyref>.

The blob is EF CE01 read from a Nitrokey HSM 2 (DENK0404144, fw 4.1) on 2026-09-23 with
`opensc-tool -s`, read-only: SELECT and READ BINARY, no PIN. Key reference 1 on that card holds the
private key whose PKCS#11 id is 0a, and the SubjectPublicKeyInfo pkcs11-tool writes for id 0a hashes
to sha256:ca2d0456…1b59 — the value regalia-kms measured from the daemon on the same card
(regalia-kms#26). So this suite pins the whole commissioning chain on real bytes: the reader returns
the attestation, the attestation verifies under the card's C.DevAut (itself pinned by
test_hsm_devaut_read.py), the attested point is the point inside that SPKI, and the SPKI hashes to
the pin the daemon will compare against.

Every accept has a matching reject (TESTING.md §18): a missing EF, a failed read part-way, an empty
file, the wrong card, a malformed key reference, and an APDU that is neither SELECT nor READ BINARY.
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import shutil
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from test_hsm_devaut_read import EF2F02  # noqa: E402  the same card's C.DevAut, one pin not two

SCRIPT = os.path.join(HERE, "..", "..", "scripts", "hsm-key-attestation-read.sh")
VERIFY = os.path.join(HERE, "..", "..", "scripts", "hsm-key-attestation-verify.py")
ANCHORS = os.path.join(HERE, "..", "..", "trust-anchors", "smartcard-hsm")

# EF CE01 of DENK0404144 — the authenticated request GENERATE ASYMMETRIC KEY PAIR left for key ref 1.
CE01_KEY_0A = (
    "678201E67F2182018C7F4E8201445F29010042095554434130303030317F4982011D060A04007F000702020202038120"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F82200000000000000000000000000000"
    "000000000000000000000000000000000000832000000000000000000000000000000000000000000000000000000000"
    "0000000784410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655D"
    "A4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B88520FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A0"
    "3BBFD25E8CD0364141864104580EFACEB9499D697805867170852FBAD787A2492D7E07FF2161058AD9B1AF02CAED30C5"
    "55B22BBC51320EBF7C4E7D2405E432F9F9012578DA6B9E910C29B2448701015F201044454E4B30343034313434303030"
    "30315F37405FDBD1390AAFD04C8D5420C3BAA823E0E06E79BAD1A0DE041F8DEC547D684950597B51CF55DEB7B7EDAAF2"
    "E2D63984DDA64F2C1F327A75842BE49D8001020131421044454E4B3034303431343430303030305F37400174CB14E103"
    "5FBCAAA0991980B54E8C04D894C9CC310E03646117C47875330F9DD824461236B36411F246E89AD44AA531598A3AF4E9"
    "FA89DB021B1EE366A903"
)
# `pkcs11-tool --read-object --type pubkey --id 0a` on the same card, same day: a secp256k1 SPKI.
KEK_DER_0A = (
    "3056301006072a8648ce3d020106052b8104000a03420004580efaceb9499d697805867170852fbad787a2492d7e07ff"
    "2161058ad9b1af02caed30c555b22bbc51320ebf7c4e7d2405e432f9f9012578da6b9e910c29b244"
)
KEK_POINT_0A = KEK_DER_0A[-130:]
# The pin regalia-kms computed from the daemon on DENK0404144 (regalia-kms#26). Hard-coded, not
# derived from KEK_DER_0A above, so a wrong fixture cannot agree with itself.
KEK_PIN_0A = "sha256:ca2d0456823208d49b11e88064cb7aa45f2eb34c85f29b453445cb2274621b59"

BLOB = bytes.fromhex(CE01_KEY_0A)


class KeyAttestationReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.bin = os.path.join(cls.tmp, "bin")
        os.makedirs(cls.bin)
        for name, body in (("opensc-tool", STUB_OPENSC), ("pkcs15-tool", STUB_PKCS15)):
            p = os.path.join(cls.bin, name)
            with open(p, "w") as fh:
                fh.write(body)
            os.chmod(p, 0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_reader(self, *args, **env):
        e = dict(os.environ)
        e["PATH"] = self.bin + os.pathsep + e["PATH"]
        e["FIXTURE_FID"] = "CE01"
        e["FIXTURE_HEX"] = CE01_KEY_0A
        e["STUB_SERIAL"] = "DENK0404144"
        e["STUB_APDU_LOG"] = os.path.join(self.tmp, "apdus.log")
        e.update({k: str(v) for k, v in env.items()})
        open(e["STUB_APDU_LOG"], "w").close()
        return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, env=e,
                              timeout=120)

    def fields(self, r):
        return dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)

    def apdus(self):
        with open(os.path.join(self.tmp, "apdus.log")) as fh:
            return [l.strip() for l in fh if l.strip()]

    # ---- the real blob ---------------------------------------------------------------------
    def test_reads_the_whole_attestation_across_chunks(self):
        r = self.run_reader("--key-ref", "1")
        self.assertEqual(r.returncode, 0, r.stderr)
        f = self.fields(r)
        self.assertEqual(f["ATTEST_FID"], "CE01")
        self.assertEqual(f["ATTEST_KEY_REF"], "1")
        self.assertEqual(int(f["ATTEST_BYTES"]), len(BLOB))
        self.assertGreater(len(BLOB), 255)            # the fixture really does span two reads
        self.assertEqual(f["ATTEST_HEX"].upper(), CE01_KEY_0A.upper())
        self.assertEqual(f["ATTEST_SHA256"], hashlib.sha256(BLOB).hexdigest())

    def test_the_key_reference_names_the_file(self):
        # Ref 10 is EF CE0A — not CE10, and not the CKA_ID 0a's file (that is CE01 on this card).
        r = self.run_reader("--key-ref", "10", FIXTURE_FID="CE0A")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.fields(r)["ATTEST_FID"], "CE0A")

    def test_the_real_blob_verifies_and_hashes_to_the_daemons_pin(self):
        """The whole D1 chain on real bytes: reader -> verifier -> point -> SPKI -> pin."""
        try:
            import cryptography  # noqa: F401
            import cvc  # noqa: F401
        except ImportError:
            self.fail("cryptography and pycvc are required to evaluate this (qubes/requirements.txt)")
        f = self.fields(self.run_reader("--key-ref", "1"))
        att = os.path.join(self.tmp, "ce01.bin")
        dev = os.path.join(self.tmp, "ef2f02.bin")
        with open(att, "wb") as fh:
            fh.write(bytes.fromhex(f["ATTEST_HEX"]))
        with open(dev, "wb") as fh:
            fh.write(bytes.fromhex(EF2F02))
        r = subprocess.run([sys.executable, VERIFY, "--devaut", dev, "--attestation", att,
                            "--trust-dir", ANCHORS, "--expect-point", KEK_POINT_0A],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DEVAUT_CHAIN=verified", r.stdout)
        self.assertIn("ATTEST_SIGNATURE=verified", r.stdout)
        self.assertIn("ATTESTED_POINT_MATCHES=yes", r.stdout)
        self.assertEqual("sha256:" + hashlib.sha256(bytes.fromhex(KEK_DER_0A)).hexdigest(), KEK_PIN_0A)

    # ---- it only reads ---------------------------------------------------------------------
    def test_only_select_and_read_binary_reach_the_card(self):
        r = self.run_reader("--key-ref", "1")
        self.assertEqual(r.returncode, 0, r.stderr)
        sent = self.apdus()
        self.assertTrue(sent)
        for a in sent:
            self.assertTrue(a.startswith("00A40400") or a.startswith("00B1CE01"), a)
        # SELECT with P2=00 + Le, the encoding both a Nitrokey and a Pico accept.
        self.assertEqual(sent[0], "00A404000BE82B0601040181C31F020100")

    def test_the_apdu_allow_list_refuses_a_pin_or_a_write(self):
        """No input to the script can make it build a VERIFY or an UPDATE BINARY, so the allow-list
        is exercised by lifting apdu_data() out of the script and handing it one. Without this the
        guard could be deleted and every other test here would still pass."""
        func = subprocess.run(["sed", "-n", "/^apdu_data() {/,/^}/p", SCRIPT],
                              capture_output=True, text=True, check=True).stdout
        self.assertIn("apdu_data()", func)
        for apdu in ("0020008106313233343536",    # VERIFY with a PIN
                     "00D6CE0100",                # UPDATE BINARY
                     "00D7CE010401FF",            # UPDATE BINARY, odd INS
                     "00A4000C022F02",            # SELECT by FID, not the application
                     "8046000000"):               # GENERATE ASYMMETRIC KEY PAIR
            with self.subTest(apdu=apdu):
                e = dict(os.environ)
                e["PATH"] = self.bin + os.pathsep + e["PATH"]
                e["STUB_APDU_LOG"] = os.path.join(self.tmp, "apdus.log")
                open(e["STUB_APDU_LOG"], "w").close()
                r = subprocess.run(["bash", "-c", func + '\nRARGS=()\napdu_data "$1"', "x", apdu],
                                   capture_output=True, text=True, env=e, timeout=30)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("REFUSING to send APDU", r.stderr)
                self.assertEqual(self.apdus(), [])

    # ---- refusals ---------------------------------------------------------------------------
    def test_a_missing_ef_is_named_as_no_attestation(self):
        # SW 6A82: no key at that reference, or an IMPORTED key — which leaves no attestation and is
        # the case commissioning exists to refuse.
        r = self.run_reader("--key-ref", "2")
        self.assertEqual(r.returncode, 2)
        self.assertIn("EF CE02 does not exist", r.stderr)
        self.assertIn("IMPORTED", r.stderr)
        self.assertNotIn("ATTEST_HEX", r.stdout)

    def test_a_failed_read_midway_is_a_refusal_not_a_short_attestation(self):
        r = self.run_reader("--key-ref", "1", STUB_FAIL_READ_AT=255)
        self.assertEqual(r.returncode, 2)
        self.assertIn("partial attestation", r.stderr)
        self.assertIn("6F00", r.stderr)
        self.assertNotIn("ATTEST_HEX", r.stdout)

    def test_an_empty_ef_is_a_refusal(self):
        r = self.run_reader("--key-ref", "1", FIXTURE_HEX="")
        self.assertEqual(r.returncode, 2)
        self.assertIn("read back empty", r.stderr)
        self.assertNotIn("ATTEST_HEX", r.stdout)

    def test_a_card_that_is_not_a_smartcard_hsm_is_a_refusal(self):
        r = self.run_reader("--key-ref", "1", STUB_SELECT="none")
        self.assertEqual(r.returncode, 2)
        self.assertIn("could not select", r.stderr)

    def test_it_refuses_to_read_another_cards_attestation(self):
        r = self.run_reader("--key-ref", "1", "--expect-serial", "DENK0404144",
                            STUB_SERIAL="DENK0400664")
        self.assertEqual(r.returncode, 2)
        self.assertIn("DENK0400664", r.stderr)
        self.assertNotIn("ATTEST_HEX", r.stdout)
        self.assertEqual(self.apdus(), [])       # refused before a single APDU was sent

    def test_the_named_card_is_read(self):
        r = self.run_reader("--key-ref", "1", "--expect-serial", "DENK0404144")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_key_reference_is_required(self):
        r = self.run_reader()
        self.assertEqual(r.returncode, 2)
        self.assertIn("--key-ref is required", r.stderr)

    def test_malformed_key_references_are_refused_not_guessed(self):
        for bad in ("0", "256", "0a", "01", "0x01", "-1", ""):
            with self.subTest(ref=bad):
                r = self.run_reader("--key-ref", bad)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertNotIn("ATTEST_HEX", r.stdout)
                self.assertEqual(self.apdus(), [])


STUB_OPENSC = r'''#!/usr/bin/env python3
"""opensc-tool stub: answers SELECT and READ BINARY of FIXTURE_FID from FIXTURE_HEX."""
import os, sys

blob = bytes.fromhex(os.environ.get("FIXTURE_HEX", ""))
fid = os.environ.get("FIXTURE_FID", "CE01").upper()
mode = os.environ.get("STUB_SELECT", "ok")

def dump(data):
    out = []
    for i in range(0, len(data), 16):
        row = data[i:i+16]
        h = " ".join("%02X" % b for b in row)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append("%-47s %s" % (h, a))
    return "\n".join(out)

args = sys.argv[1:]
apdus = [args[i+1] for i, a in enumerate(args) if a == "-s"]
with open(os.environ["STUB_APDU_LOG"], "a") as log:
    for a in apdus:
        log.write(a.upper() + "\n")
for apdu in apdus:
    a = apdu.upper()
    print("Sending: " + " ".join(a[i:i+2] for i in range(0, len(a), 2)))
    if a.startswith("00A404"):
        # P2=00 with Le works on both vendors; anything else is refused the way a Pico refuses it.
        ok = mode == "ok" and a[6:8] == "00"
        print("Received (SW1=0x90, SW2=0x00)" if ok else "Received (SW1=0x6A, SW2=0x86)")
        if not ok:
            sys.exit(0)
    elif a.startswith("00B1"):
        if a[4:8] != fid:
            print("Received (SW1=0x6A, SW2=0x82)")
            sys.exit(0)
        off = int(a[14:18], 16)
        fail_at = os.environ.get("STUB_FAIL_READ_AT")
        if fail_at is not None and off == int(fail_at):
            print("Received (SW1=0x6F, SW2=0x00)")
            sys.exit(0)
        le = int(a[18:20], 16) or 256
        chunk = blob[off:off+le]
        if not blob:                     # an EF that exists and holds nothing
            print("Received (SW1=0x90, SW2=0x00)")
            continue
        if not chunk:
            print("Received (SW1=0x6B, SW2=0x00)")
            sys.exit(0)
        eof = off + len(chunk) >= len(blob)
        print("Received (%s):" % ("SW1=0x62, SW2=0x82" if eof else "SW1=0x90, SW2=0x00"))
        print(dump(chunk))
    else:
        print("Received (SW1=0x6D, SW2=0x00)")
        sys.exit(0)
print("Success!")
'''

STUB_PKCS15 = r'''#!/usr/bin/env bash
printf 'PKCS#15 Card [attest]:\n\tSerial number  : %s\n' "${STUB_SERIAL:-DENK0404144}"
'''

if __name__ == "__main__":
    unittest.main(verbosity=2)
