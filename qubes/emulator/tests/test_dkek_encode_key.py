#!/usr/bin/env python3
"""The DKEK key blob, decoded back field by field. NO CARD.

WHY IT IS CHECKED THIS WAY. The blob is the only thing standing between "the ceremony imported the
funding key" and "the card holds a key nobody has". A card that receives a malformed blob answers
SW=6400 and nothing is lost; a card that receives a WELL-FORMED blob built from the wrong domain
parameters, or the wrong private scalar, accepts it — and the failure surfaces later as a signature
that does not verify, or not at all. So this decodes what the encoder produced, with the same
derivation the card uses, and checks every field against the key that went in.

The one number this cannot self-check is the KCV, because self-consistency proves nothing about
agreement with scsh. That one was measured: for the staging share the encoder printed
`bc3174fa8a01d070`, byte for byte what the Smart Card Shell reported for the same file
(`STEP wrap: keyblob=363 bytes under kcv=BC3174FA8A01D070`, 2026-09-21), and the card accepted the
resulting blob with SW=9000.
"""
import hashlib
import importlib.util
import os
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

ENCODER = Path(__file__).resolve().parents[3] / "qubes" / "scripts" / "hsm-dkek-encode-key.py"


def load():
    spec = importlib.util.spec_from_file_location("hsm_dkek_encode_key", ENCODER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


enc = load()
DKEK = bytes(range(32))


def decode(blob, dkek):
    """Undo encode_ec_key: verify the MAC, decrypt, and split the body into its fields."""
    kcv, kenc, kmac = enc.dkek_keys(dkek)
    mac = cmac.CMAC(algorithms.AES(kmac))
    mac.update(blob[:-16])
    mac.verify(blob[-16:])                       # raises InvalidSignature if the MAC is wrong
    assert blob[:8] == kcv, "KCV prefix does not match the DKEK"
    assert blob[8] == 0x0C, "key type is not ECC"
    oid_len = int.from_bytes(blob[9:11], "big")
    offset = 11 + oid_len + 6                    # three empty u16 fields follow the OID
    dec = Cipher(algorithms.AES(kenc), modes.CBC(b"\x00" * 16)).decryptor()
    body = dec.update(blob[offset:-16]) + dec.finalize()   # the last 16 bytes are the CMAC
    body = body[8:]                              # drop the 8 random bytes
    bits = int.from_bytes(body[:2], "big")
    rest, fields = body[2:], []
    for _ in range(7):
        n = int.from_bytes(rest[:2], "big")
        fields.append(rest[2:2 + n])
        rest = rest[2 + n:]
    return dict(oid=blob[11:11 + oid_len], bits=bits, a=fields[0], b=fields[1], p=fields[2],
                n=fields[3], g=fields[4], d=fields[5], q=fields[6], tail=rest)


class DkekBlobTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.derive_private_key(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678,
                                         ec.SECP256K1())

    def test_the_blob_is_the_size_the_card_and_scsh_agree_on(self):
        blob = enc.encode_ec_key(self.key, DKEK)
        self.assertEqual(363, len(blob),
                         "a 256-bit EC blob is 363 bytes; scsh produced exactly that for the same "
                         "kind of key, and the card accepted it")

    def test_every_field_survives_the_round_trip(self):
        blob = enc.encode_ec_key(self.key, DKEK)
        got = decode(blob, DKEK)
        numbers = self.key.private_numbers()
        curve = enc.CURVES["secp256k1"]
        self.assertEqual(256, got["bits"])
        self.assertEqual(enc.EC_ALGO_OID, got["oid"], "the TR-03110 algorithm OID must be exact")
        self.assertEqual(curve["p"], int.from_bytes(got["p"], "big"))
        self.assertEqual(curve["n"], int.from_bytes(got["n"], "big"))
        self.assertEqual(curve["a"], int.from_bytes(got["a"], "big"))
        self.assertEqual(curve["b"], int.from_bytes(got["b"], "big"))
        self.assertEqual(b"\x04" + curve["gx"].to_bytes(32, "big") + curve["gy"].to_bytes(32, "big"),
                         got["g"])
        self.assertEqual(numbers.private_value, int.from_bytes(got["d"], "big"),
                         "the private scalar the card receives must be the key's own")
        pub = numbers.public_numbers
        self.assertEqual(b"\x04" + pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big"), got["q"])

    def test_the_padding_leaves_a_whole_number_of_aes_blocks(self):
        # scsh's own comment: "pad() pads to 8 byte blocks, but we 16 byte blocks". Get this wrong
        # and the AES-CBC encrypt throws — or, worse, a different implementation silently truncates.
        blob = enc.encode_ec_key(self.key, DKEK)
        kcv, _, _ = enc.dkek_keys(DKEK)
        head = 8 + 1 + 2 + len(enc.EC_ALGO_OID) + 6
        self.assertEqual(0, (len(blob) - head - 16) % 16, "the ciphertext is not a whole number of blocks")
        got = decode(blob, DKEK)
        self.assertEqual(b"\x80", got["tail"][:1], "the ISO 9797-1 method 2 pad byte is missing")
        self.assertEqual(b"\x00" * (len(got["tail"]) - 1), got["tail"][1:], "the padding is not zeros")

    def test_a_different_dkek_produces_a_blob_this_card_would_reject(self):
        # The KCV is the card's own check: it refuses a blob whose first 8 bytes name another DKEK.
        mine = enc.encode_ec_key(self.key, DKEK)
        other = enc.encode_ec_key(self.key, bytes(32))
        self.assertNotEqual(mine[:8], other[:8])
        self.assertEqual(hashlib.sha256(bytes(32)).digest()[:8], other[:8])

    def test_a_curve_whose_generator_is_wrong_is_refused(self):
        # THE TABLE IS DATA, and data can be wrong. A bad constant here would hand the card a
        # domain that is not the key's, and the card cannot tell.
        saved = enc.CURVES["secp256k1"]["gy"]
        try:
            enc.CURVES["secp256k1"]["gy"] = saved ^ 1
            with self.assertRaises(ValueError) as cm:
                enc.encode_ec_key(self.key, DKEK)
            self.assertIn("not on the curve", str(cm.exception))
        finally:
            enc.CURVES["secp256k1"]["gy"] = saved

    def test_an_unsupported_curve_is_named_rather_than_guessed(self):
        key = ec.generate_private_key(ec.SECP384R1())
        with self.assertRaises(ValueError) as cm:
            enc.encode_ec_key(key, DKEK)
        self.assertIn("secp384r1", str(cm.exception))

    def test_a_share_that_does_not_decrypt_is_refused(self):
        # The share carries its own check — a trailing block of 0x10 bytes. Without it a wrong
        # password yields noise that would be wrapped into a blob the card silently rejects, with
        # nothing to say which of the two inputs was wrong. The KDF is 30 million MD5 rounds, so
        # this drives decrypt_share with the derivation stubbed; the derivation itself is measured
        # against scsh's KCV, which no stub can fake.
        original = enc.derive_share_key
        try:
            enc.derive_share_key = lambda salt, password: hashlib.sha512(salt + password).digest()[:48]
            keyiv = enc.derive_share_key(b"12345678", b"pw")
            plain = os.urandom(32) + bytes([0x10]) * 16
            e = Cipher(algorithms.AES(keyiv[:32]), modes.CBC(keyiv[32:48])).encryptor()
            good = b"Salted__" + b"12345678" + (e.update(plain) + e.finalize())
            self.assertEqual(plain[:32], enc.decrypt_share(good, b"pw"))
            with self.assertRaises(ValueError) as cm:
                enc.decrypt_share(good, b"wrong")
            self.assertIn("wrong password", str(cm.exception))
        finally:
            enc.derive_share_key = original

    def test_a_file_that_is_not_a_share_is_refused(self):
        with self.assertRaises(ValueError):
            enc.decrypt_share(b"not a share at all", b"pw")


if __name__ == "__main__":
    unittest.main(verbosity=2)
