#!/usr/bin/env python3
"""Tests for hsm-devaut-read.sh — the OpenSC-only C.DevAut reader.

The blob is EF 2F02 read from a Nitrokey HSM 2 (DENK0404144, fw 4.1) on 2026-09-18 with
`opensc-tool -s`. The SAME bytes come back from the Smart Card Shell reader (hsm-devaut-id.js) and
are already pinned by test_hsm_key_attestation_verify.py, so this suite is a cross-check of two
independent readers against one device, not a round-trip of one implementation against itself.

WHAT MUST NOT REGRESS. A SmartCard-HSM answers a read that runs past the end of EF 2F02 with
SW 6282 ("end of file reached") *and* the bytes it did have. The first cut of this reader treated
anything but 9000 as an error, kept the first 255 bytes, and printed a confident DEVAUT_SHA256 of a
PREFIX of the certificate. Commissioning pins that digest, so the failure mode was a card that
could never be commissioned — with no hint that the reader, not the card, was wrong.
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import shutil
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "scripts", "hsm-devaut-read.sh")

# EF 2F02 of DENK0404144 — device certificate followed by its issuer's.
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
BLOB = bytes.fromhex(EF2F02)
SHA = hashlib.sha256(BLOB).hexdigest()
CHR_ = "DENK040414400000"
CAR = "DEDINK0400001"


def dump(data: bytes) -> str:
    """opensc-tool's hex dump: 16 bytes per line in the first 48 columns, ASCII after."""
    out = []
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        hexpart = " ".join(f"{b:02X}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"{hexpart:<47} {asc}")
    return "\n".join(out)


class DevAutReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.bin = os.path.join(cls.tmp, "bin")
        os.makedirs(cls.bin)
        cls.write_stub("opensc-tool", STUB_OPENSC)
        cls.write_stub("pkcs15-tool", STUB_PKCS15)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def write_stub(cls, name, body):
        p = os.path.join(cls.bin, name)
        with open(p, "w") as fh:
            fh.write(body)
        os.chmod(p, 0o755)

    def run_reader(self, *args, **env):
        e = dict(os.environ)
        e["PATH"] = self.bin + os.pathsep + e["PATH"]
        e["FIXTURE_HEX"] = EF2F02
        e.setdefault("STUB_SELECT", "nitrokey")
        e.setdefault("STUB_SERIAL", "DENK0404144")
        e.update({k: str(v) for k, v in env.items()})
        return subprocess.run([SCRIPT, *args], capture_output=True, text=True, env=e, timeout=120)

    def fields(self, r):
        return dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)

    # ---- the cross-check -------------------------------------------------------------------
    def test_reads_the_whole_certificate_file_across_the_end_of_file_warning(self):
        r = self.run_reader()
        self.assertEqual(r.returncode, 0, r.stderr)
        f = self.fields(r)
        self.assertEqual(int(f["DEVAUT_BYTES"]), len(BLOB))
        self.assertEqual(f["DEVAUT_HEX"].upper(), EF2F02.upper())
        self.assertEqual(f["DEVAUT_SHA256"], SHA)

    def test_a_final_chunk_that_is_one_short_row_of_hex_looking_ascii_is_read_exactly(self):
        """opensc-tool does not pad a one-row response, so a fixed 48-column slice read its ASCII
        ('AB12') as hex. Found in review of regalia-ceremony#35; this reader had the same parser."""
        blob = bytes(range(256)) + b"AB12 C"
        r = self.run_reader(FIXTURE_HEX=blob.hex())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.fields(r)["DEVAUT_HEX"].upper(), blob.hex().upper(),
                         "the reader returned bytes the card did not send")

    def test_a_flag_with_no_value_is_refused_not_an_infinite_loop(self):
        """`VAR="${2:-}"; shift 2` on a trailing flag never shifted and looped forever (review of
        regalia-ceremony#35). A flag followed by another flag must not swallow it either."""
        for args in (["--reader"], ["--reader", "--expect-serial", "X"]):
            r = self.run_reader(*args)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("--reader needs a value", r.stderr)

    def test_the_digest_is_not_a_digest_of_the_first_chunk(self):
        # The exact defect: 255 bytes hashed and reported as the card's identity.
        prefix = hashlib.sha256(BLOB[:255]).hexdigest()
        self.assertNotEqual(prefix, SHA)
        self.assertEqual(self.fields(self.run_reader())["DEVAUT_SHA256"], SHA)

    def test_identity_fields_match_the_scsh_reader(self):
        f = self.fields(self.run_reader())
        self.assertEqual(f["DEVAUT_CHR"], CHR_)
        self.assertEqual(f["DEVAUT_CAR"], CAR)
        self.assertNotEqual(f["DEVAUT_CHR"], f["DEVAUT_CAR"])  # not self-signed: a real issuer

    # ---- selection ------------------------------------------------------------------------
    def test_a_card_that_rejects_the_p2_0c_select_is_still_read(self):
        # A Pico HSM answers 6A86 to the encoding a Nitrokey accepts. Measured 2026-09-18.
        r = self.run_reader(STUB_SELECT="pico")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.fields(r)["DEVAUT_SHA256"], SHA)

    def test_a_card_that_is_not_a_smartcard_hsm_is_a_refusal(self):
        r = self.run_reader(STUB_SELECT="none")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not select", r.stderr)

    def test_an_empty_certificate_file_is_a_refusal_not_an_empty_digest(self):
        r = self.run_reader(FIXTURE_HEX="")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("DEVAUT_SHA256", r.stdout)

    # ---- naming the card ------------------------------------------------------------------
    def test_it_refuses_to_report_another_cards_identity(self):
        # Two SmartCard-HSMs attached: a certificate from the wrong device parses perfectly and
        # every downstream check passes on it. Measured 2026-09-03.
        r = self.run_reader("--expect-serial", "DENK0404144", STUB_SERIAL="DENK0400664")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("DENK0400664", r.stderr)
        self.assertNotIn("DEVAUT_SHA256", r.stdout)

    def test_a_failed_read_midway_is_a_refusal_not_a_short_certificate(self):
        # The status word used to be assigned to a global INSIDE a command substitution, so the
        # parent never saw it and any non-9000 answer merely ended the loop. The reader then hashed
        # the 255 bytes it happened to hold and printed them as the device's identity, which
        # commissioning compares against the pinned digest: DEVAUT DIGEST MISMATCH on a genuine
        # card, with nothing pointing at the reader.
        r = self.run_reader(STUB_FAIL_READ_AT=255)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("DEVAUT_SHA256", r.stdout)
        self.assertIn("6F00", r.stderr)
        self.assertIn("partial", r.stderr)

    def test_the_named_card_is_read(self):
        r = self.run_reader("--expect-serial", "DENK0404144")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.fields(r)["DEVAUT_SHA256"], SHA)


STUB_OPENSC = r'''#!/usr/bin/env python3
"""opensc-tool stub: answers SELECT and READ BINARY from FIXTURE_HEX, in opensc-tool's format."""
import os, sys

blob = bytes.fromhex(os.environ.get("FIXTURE_HEX", ""))
mode = os.environ.get("STUB_SELECT", "nitrokey")

def dump(data):
    out = []
    for i in range(0, len(data), 16):
        row = data[i:i+16]
        h = " ".join("%02X" % b for b in row)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        # One short row is NOT padded by opensc-tool; a short last row of a longer dump is.
        out.append(("%s %s" % (h, a)) if len(data) <= 16 else ("%-47s %s" % (h, a)))
    return "\n".join(out)

args = sys.argv[1:]
apdus = [args[i+1] for i, a in enumerate(args) if a == "-s"]
for apdu in apdus:
    a = apdu.upper()
    print("Sending: " + " ".join(a[i:i+2] for i in range(0, len(a), 2)))
    if a.startswith("00A404"):
        p2 = a[6:8]
        ok = (mode == "nitrokey" and p2 == "0C") or (mode == "pico" and p2 == "00")
        print("Received (SW1=0x90, SW2=0x00)" if ok else "Received (SW1=0x6A, SW2=0x86)")
        if not ok:
            sys.exit(0)
    elif a.startswith("00B12F02"):
        off = int(a[14:18], 16)
        fail_at = os.environ.get("STUB_FAIL_READ_AT")
        if fail_at is not None and off == int(fail_at):
            print("Received (SW1=0x6F, SW2=0x00)")
            sys.exit(0)
        le = int(a[18:20], 16) or 256
        chunk = blob[off:off+le]
        eof = off + len(chunk) >= len(blob)
        sw = "SW1=0x62, SW2=0x82" if eof else "SW1=0x90, SW2=0x00"
        if not chunk:
            print("Received (SW1=0x6B, SW2=0x00)")
            sys.exit(0)
        print("Received (%s):" % sw)
        print(dump(chunk))
    else:
        print("Received (SW1=0x6D, SW2=0x00)")
        sys.exit(0)
print("Success!")
'''

STUB_PKCS15 = r'''#!/usr/bin/env bash
printf 'PKCS#15 Card [regalia-staging]:\n\tSerial number  : %s\n' "${STUB_SERIAL:-DENK0404144}"
'''

if __name__ == "__main__":
    unittest.main(verbosity=2)
