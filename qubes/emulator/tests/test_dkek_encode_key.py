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




class OpenScPasswordShares(unittest.TestCase):
    """Reconstructing the DKEK-share password from OpenSC's 4-of-6 shares (regalia#486).

    WHY THIS MATTERS. `sc-hsm-tool --create-dkek-share --pwd-shares-threshold t --pwd-shares-total
    n` does not take a password: it generates 8 random bytes, splits them with Shamir over a 64-bit
    prime, prints only the shares, and never writes the password anywhere. Every real ceremony uses
    that path. Without reconstruction the JVM-free import could serve only the drill's
    single-password shortcut — which is to say, not a ceremony.

    THE FIXTURE IS REAL. Prime and shares below came from `sc-hsm-tool --create-dkek-share
    --pwd-shares-threshold 4 --pwd-shares-total 6` on 2026-09-21, and the expected password is the
    one the card confirmed: fed shares 1-4, the Nitrokey reported DKEK KCV EDE4B653C8280D28, and
    the key check value derived from THIS reconstructed password is the same value.
    """

    PRIME = 0xE28C4E2A93CCA877
    SHARES = {
        1: 0xBED92AF69643C441,
        2: 0x8DD49D6982048A5B,
        3: 0x083ECBCE3E4AD6B6,
        4: 0x845D7A40863E4C32,
        5: 0xB0D1825C59A0944A,
        6: 0x1EC80BE84C0000F0,
    }
    PASSWORD = bytes.fromhex("2792fe8453ad89ff")

    def _file(self, ids):
        out = []
        for i in ids:
            out.append("Prime       : " + ":".join("%02x" % b for b in self.PRIME.to_bytes(8, "big")))
            out.append("Share ID    : %d" % i)
            value = self.SHARES[i]
            out.append("Share value : " + ":".join("%02x" % b for b in
                                                   value.to_bytes((value.bit_length() + 7) // 8, "big")))
            out.append("")
        return "\n".join(out)

    def test_any_quorum_of_four_recovers_the_same_password(self):
        # Not just the quorum that was fed to the card. If only one combination worked, the
        # interpolation would be wrong in a way a single happy-path test cannot see.
        for quorum in ((1, 2, 3, 4), (2, 4, 5, 6), (1, 3, 5, 6), (3, 4, 5, 6), (1, 2, 5, 6)):
            with self.subTest(quorum=quorum):
                prime, shares = enc.parse_share_file(self._file(quorum), list(quorum))
                self.assertEqual(enc.reconstruct_share_password(prime, shares), self.PASSWORD)

    def test_three_shares_do_not_recover_it(self):
        # Below the threshold must not reconstruct. A scheme that leaked at t-1 would be broken.
        prime, shares = enc.parse_share_file(self._file((1, 2, 3)), [1, 2, 3])
        self.assertNotEqual(enc.reconstruct_share_password(prime, shares), self.PASSWORD)

    def test_the_leading_zero_drop_is_preserved(self):
        # OpenSC converts with BN_bn2bin, which emits no leading zero byte, so a secret whose top
        # byte is zero comes back SEVEN bytes and the share file decrypts under those seven.
        # Padding it back to eight would rebuild a password the real tool never used (regalia#460).
        self.assertEqual(enc._minimal_bytes(0x00FFEEDDCCBBAA99), bytes.fromhex("ffeeddccbbaa99"))
        self.assertEqual(len(enc._minimal_bytes(0x00FFEEDDCCBBAA99)), 7)

    def test_a_file_mixing_two_ceremonies_is_refused(self):
        # Interpolating across two primes yields a confident WRONG password rather than an error.
        text = self._file((1, 2)) + "\n" + self._file((3, 4)).replace("e2:8c", "e3:8c")
        with self.assertRaises(ValueError) as caught:
            enc.parse_share_file(text)
        self.assertIn("two ceremonies", str(caught.exception))

    def test_duplicate_share_ids_are_refused_by_NAME(self):
        # ASSERT THE MESSAGE, not merely that something raised. Without the explicit check,
        # pow(0, -1, prime) raises ValueError("base is not invertible…") on its own — so a bare
        # assertRaises passes whether the guard exists or not, and the mutation that removes it
        # goes uncaught. That is a test measuring the interpreter, not the code.
        prime, _ = enc.parse_share_file(self._file((1,)), [1])
        with self.assertRaises(ValueError) as caught:
            enc.reconstruct_share_password(prime, [(1, self.SHARES[1]), (1, self.SHARES[1])])
        self.assertIn("same ID", str(caught.exception))

    def test_a_missing_share_is_named(self):
        with self.assertRaises(ValueError) as caught:
            enc.parse_share_file(self._file((1, 2)), [1, 5])
        self.assertIn("5", str(caught.exception))

    def test_a_file_with_no_prime_is_refused(self):
        with self.assertRaises(ValueError):
            enc.parse_share_file("Share ID    : 1\nShare value : aa:bb\n")

    def test_a_share_value_before_its_id_is_refused(self):
        with self.assertRaises(ValueError):
            enc.parse_share_file("Prime       : e2:8c\nShare value : aa:bb\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
