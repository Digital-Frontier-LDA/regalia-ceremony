#!/usr/bin/env python3
"""yubikey-attestation-verify.py against REAL attestations from a staging YubiKey (36345471, fw 5.7.4,
captured 2026-09-24), and against forgeries built here: a chain under an attacker's root that carries
Yubico's extensions, a tampered signature, a vendored root that no longer matches its pin, and
expectations (serial, policy, key) that the attestation does not support."""
import contextlib
import datetime
import importlib.util
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "scripts", "yubikey-attestation-verify.py")
FIX = os.path.join(HERE, "fixtures", "yubikey-attestation")
SERIAL = 36345471

spec = importlib.util.spec_from_file_location("ykatt", SCRIPT)
ykatt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ykatt)


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = ykatt.main(list(argv))
    return rc, dict(line.split("=", 1) for line in out.getvalue().splitlines() if "=" in line)


def fixture(name):
    return os.path.join(FIX, name)


class RealAttestation(unittest.TestCase):
    def test_the_genuine_card_verifies_with_every_expectation(self):
        rc, v = run("--attestation", fixture("att-36345471.pem"), "--f9", fixture("f9-36345471.pem"),
                    "--serial", str(SERIAL), "--pin-policy", "once", "--touch-policy", "never",
                    "--expect-spki", fixture("spki-36345471.der"))
        self.assertEqual(rc, 0, v)
        self.assertTrue(v["YUBICO_CHAIN"].startswith("verified"))
        self.assertIn("Yubico Attestation Root 1", v["YUBICO_CHAIN"])
        self.assertEqual((v["SERIAL_MATCHES"], v["POLICY_MATCHES"], v["ATTESTED_KEY_MATCHES"]), ("yes", "yes", "yes"))
        self.assertEqual(v["ATTESTED_FIRMWARE"], "5.7.4")
        self.assertEqual(v["ATTESTED_KEY_SHA256"],
                         "sha256:35bba72093e4183f38fb7b9c76ab031dc886beb665c5a58b5c51ce74ba4d48a7")

    def test_each_expectation_the_attestation_does_not_support_fails(self):
        base = ["--attestation", fixture("att-36345471.pem"), "--f9", fixture("f9-36345471.pem")]
        for extra, key in ((["--serial", "36344616"], "SERIAL_MATCHES"),
                           (["--serial", str(SERIAL), "--pin-policy", "always"], "POLICY_MATCHES"),
                           (["--serial", str(SERIAL), "--touch-policy", "cached"], "POLICY_MATCHES"),
                           (["--serial", str(SERIAL), "--expect-sha256", "sha256:" + "00" * 32], "ATTESTED_KEY_MATCHES")):
            with self.subTest(extra=extra):
                rc, v = run(*base, *extra)
                self.assertEqual(rc, 1)
                self.assertEqual(v[key], "no")

    def test_the_serial_is_mandatory(self):
        # The f9 key is shared across a batch: without a serial, any genuine card's key would pass.
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            run("--attestation", fixture("att-36345471.pem"), "--f9", fixture("f9-36345471.pem"))

    def test_a_tampered_signature_breaks_the_chain(self):
        pem = Path(fixture("att-36345471.pem")).read_bytes()
        der = bytearray(x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER))
        der[-5] ^= 0x01  # inside the signature
        with tempfile.NamedTemporaryFile(suffix=".pem") as f:
            f.write(b"-----BEGIN CERTIFICATE-----\n" + __import__("base64").encodebytes(bytes(der)) + b"-----END CERTIFICATE-----\n")
            f.flush()
            rc, v = run("--attestation", f.name, "--f9", fixture("f9-36345471.pem"), "--serial", str(SERIAL))
        self.assertEqual(rc, 1)
        self.assertTrue(v["YUBICO_CHAIN"].startswith("failed"), v)


def cert(subject, issuer, key, signer, ca, extensions=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    for oid, value in extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False)
    return builder.sign(signer, hashes.SHA256())


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class Forgeries(unittest.TestCase):
    def write(self, *certs):
        f = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        for c in certs:
            f.write(c.public_bytes(serialization.Encoding.PEM))
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_a_chain_under_an_attackers_root_is_refused_even_with_yubico_names_and_extensions(self):
        root_key, inter_key, f9_key, slot_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
        root = cert(name("Yubico Attestation Root 1"), name("Yubico Attestation Root 1"), root_key, root_key, True)
        inter = cert(name("Yubico PIV Attestation B 1"), root.subject, inter_key, root_key, True)
        f9 = cert(name("YubiKey PIV Attestation"), inter.subject, f9_key, inter_key, True)
        serial_ext = b"\x02\x04" + SERIAL.to_bytes(4, "big")
        att = cert(name("YubiKey PIV Attestation 9a"), f9.subject, slot_key, f9_key, False,
                   ((ykatt.OID_SERIAL, serial_ext), (ykatt.OID_POLICY, b"\x02\x01"), (ykatt.OID_FIRMWARE, b"\x05\x07\x04")))
        rc, v = run("--attestation", self.write(att), "--f9", self.write(f9), "--serial", str(SERIAL),
                    "--pin-policy", "once", "--touch-policy", "never")
        self.assertEqual(rc, 1)
        self.assertTrue(v["YUBICO_CHAIN"].startswith("failed"), v)
        # The forged extensions parse and "match" — which is exactly why the chain must decide.
        self.assertEqual((v["SERIAL_MATCHES"], v["POLICY_MATCHES"]), ("yes", "yes"))

    def test_a_key_signed_by_the_wrong_f9_is_refused(self):
        other_key, slot_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        real_f9 = x509.load_pem_x509_certificate(Path(fixture("f9-36345471.pem")).read_bytes())
        att = cert(name("YubiKey PIV Attestation 9a"), real_f9.subject, slot_key, other_key, False,
                   ((ykatt.OID_SERIAL, b"\x02\x04" + SERIAL.to_bytes(4, "big")),))
        rc, v = run("--attestation", self.write(att), "--f9", fixture("f9-36345471.pem"), "--serial", str(SERIAL))
        self.assertEqual(rc, 1)
        self.assertIn("not signed by the f9", v["YUBICO_CHAIN"])

    def test_a_vendored_root_that_no_longer_matches_its_pin_stops_the_check(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(ykatt.VENDOR, os.path.join(tmp, "v"))
        key = ec.generate_private_key(ec.SECP256R1())
        with open(os.path.join(tmp, "v", "yubico-attestation-root-1.pem"), "wb") as f:
            f.write(cert(name("Yubico Attestation Root 1"), name("Yubico Attestation Root 1"), key, key, True)
                    .public_bytes(serialization.Encoding.PEM))
        saved, ykatt.VENDOR = ykatt.VENDOR, os.path.join(tmp, "v")
        try:
            rc, v = run("--attestation", fixture("att-36345471.pem"), "--f9", fixture("f9-36345471.pem"), "--serial", str(SERIAL))
        finally:
            ykatt.VENDOR = saved
        self.assertEqual(rc, 2)
        self.assertIn("does not match its pinned SHA-256", v["YUBICO_CHAIN"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
