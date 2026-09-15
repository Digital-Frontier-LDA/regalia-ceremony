#!/usr/bin/env python3
"""Adversarial tests for derive-akash-address.py — the highest-stakes code in the ceremony:
a bug here records the WRONG funding address and money is sent somewhere unspendable.

Uses the secp256k1 generator point G as a fixed vector. ripemd160(sha256(compressed_G)) is
751e76e8199196d454941c45d1b3a323f1433bd6 — the canonical BIP-173 bech32 example witness
program — so the expected address is an INDEPENDENT check, not circular.
"""
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
_path = os.path.join(_SCRIPTS, "derive-akash-address.py")
_loader = importlib.machinery.SourceFileLoader("derive_addr", _path)
_spec = importlib.util.spec_from_loader("derive_addr", _loader)
da = importlib.util.module_from_spec(_spec)
_loader.exec_module(da)

# Canonical BIP-39 all-zero-entropy mnemonic. Its 64-byte seed (empty passphrase) is the
# published BIP-39 reference vector, and its akash address at the Cosmos default HD path
# m/44'/118'/0'/0/0 is cross-checked below against cosmpy — an INDEPENDENT implementation.
CANON_MNEMONIC = ("abandon abandon abandon abandon abandon abandon "
                  "abandon abandon abandon abandon abandon about")
CANON_SEED_HEX = ("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
                  "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
CANON_AKASH_ADDR = "akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0"

G_UNCOMP = bytes.fromhex(
    "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
G_COMP = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
EXPECT = "akash1w508d6qejxtdg4y5r3zarvary0c5xw7khx6akz"   # hash160(G) = BIP-173 ref vector


def spki(point):
    bitstr = b"\x03" + bytes([len(point) + 1]) + b"\x00" + point
    algid = b"\x30\x10" + bytes.fromhex("06072a8648ce3d0201") + bytes.fromhex("06052b8104000a")
    body = algid + bitstr
    return b"\x30" + bytes([len(body)]) + body


class TestDerive(unittest.TestCase):
    def test_golden_vector_compressed(self):
        self.assertEqual(da.derive(G_COMP, "akash"), EXPECT)

    def test_uncompressed_matches_compressed(self):
        self.assertEqual(da.derive(da.compress(G_UNCOMP), "akash"), EXPECT)

    def test_der_spki_matches(self):
        pt = da.point_from_der(spki(G_UNCOMP))
        self.assertEqual(da.derive(da.compress(pt), "akash"), EXPECT)

    def test_all_three_input_forms_agree(self):
        a = da.derive(da.compress(G_UNCOMP), "akash")
        b = da.derive(G_COMP, "akash")
        c = da.derive(da.compress(da.point_from_der(spki(G_UNCOMP))), "akash")
        self.assertEqual(a, b)
        self.assertEqual(b, c)

    def test_hash160_is_the_bip173_reference(self):
        # independent cross-check of the hash pipeline
        h = da._ripemd160(__import__("hashlib").sha256(G_COMP).digest())
        self.assertEqual(h.hex(), "751e76e8199196d454941c45d1b3a323f1433bd6")

    def test_wrong_curve_der_is_rejected(self):
        # prime256v1 (P-256) OID instead of secp256k1 — must NOT silently derive an address
        p256_oid = bytes.fromhex("06082a8648ce3d030107")
        algid = b"\x30\x13" + bytes.fromhex("06072a8648ce3d0201") + p256_oid
        bitstr = b"\x03" + bytes([len(G_UNCOMP) + 1]) + b"\x00" + G_UNCOMP
        body = algid + bitstr
        bad = b"\x30" + bytes([len(body)]) + body
        with self.assertRaises(ValueError):
            da.point_from_der(bad)

    def test_truncated_der_rejected(self):
        with self.assertRaises(ValueError):
            da.point_from_der(spki(G_UNCOMP)[:20])

    def test_bad_point_length_rejected(self):
        with self.assertRaises(ValueError):
            da.compress(b"\x04" + b"\x00" * 10)   # not 33/65 bytes

    def test_parity_flipped_uncompressed_point_rejected(self):
        # Single-bit HSM/reader glitch: flip the lowest bit of Y on the real
        # generator point. The bytes are still 65B 04||X||Y of the right shape,
        # but the point is NO LONGER on secp256k1. compress() trusts y[-1]&1 for
        # parity, so without an on-curve check it would silently emit 03||X and
        # derive a valid-looking but UNFUNDABLE address. Must raise instead.
        glitched = bytearray(G_UNCOMP)
        glitched[-1] ^= 0x01
        with self.assertRaises(ValueError):
            da.compress(bytes(glitched))

    def test_x_ge_p_compressed_point_rejected(self):
        # 33B compressed input whose X is all 0xff (>= field prime p) — off-curve.
        # Must raise, not derive an address.
        with self.assertRaises(ValueError):
            da.compress(b"\x02" + b"\xff" * 32)

    def test_off_curve_x_compressed_point_rejected(self):
        # x=5 has no square root mod p on secp256k1 (5^3+7=132 is a non-residue),
        # so 02||00..05 is not a valid compressed point. Must raise.
        with self.assertRaises(ValueError):
            da.compress(b"\x02" + (5).to_bytes(32, "big"))


class TestMnemonicToAddress(unittest.TestCase):
    """The Option-B recovery runbook (RECOVERY-TECHNICAL.md Step 4) requires deriving the
    akash funding address FROM the recovered BIP39 mnemonic, air-gapped, to verify it before
    sweeping funds. Without a shipped mnemonic->address tool that check is not executable
    offline and the operator must proceed on blind trust — the defect these tests guard."""

    def test_bip39_seed_matches_published_vector(self):
        # Independent anchor: the BIP-39 reference seed for the all-zero mnemonic.
        self.assertEqual(da._bip39_seed(CANON_MNEMONIC).hex(), CANON_SEED_HEX)

    def test_mnemonic_golden_akash_address(self):
        self.assertEqual(da.address_from_mnemonic(CANON_MNEMONIC), CANON_AKASH_ADDR)

    def test_wrong_bip39_passphrase_yields_different_address(self):
        # A BIP-39 passphrase changes the seed; the safeguard must reflect that so a wrong
        # one is caught by the Step-4 address mismatch rather than silently swept.
        self.assertNotEqual(da.address_from_mnemonic(CANON_MNEMONIC, passphrase="TREZOR"),
                            CANON_AKASH_ADDR)

    def test_non_bip39_word_is_rejected(self):
        # Transcription error off a metal plate/paper: a custodian mistypes a word into a
        # non-BIP39 token ('about' -> 'abandom'). The old code PBKDF2'd the raw string and
        # printed a plausible-but-WRONG akash address exit-0. On a set-once custodial path
        # that silently loses funds, so an unknown word MUST hard-fail here (defense in
        # depth before the manual on-chain address comparison), matching
        # bip39-slip39-backup.py's m.check().
        corrupted = CANON_MNEMONIC.rsplit(" ", 1)[0] + " abandom"
        with self.assertRaises(ValueError):
            da.address_from_mnemonic(corrupted)

    def test_bad_bip39_checksum_is_rejected(self):
        # All 12 words are valid BIP39 words but the checksum is wrong (12x 'abandon' has
        # checksum bits 0000; the all-zero entropy actually requires 'about'=0011 as the
        # last word). A checksum-breaking transcription slip must hard-fail, not derive.
        all_abandon = " ".join(["abandon"] * 12)
        with self.assertRaises(ValueError):
            da.address_from_mnemonic(all_abandon)

    def test_valid_mnemonic_still_derives(self):
        # The new checksum guard must not reject a genuinely valid mnemonic.
        self.assertEqual(da.address_from_mnemonic(CANON_MNEMONIC), CANON_AKASH_ADDR)

    def test_cli_rejects_corrupted_mnemonic_file(self):
        # End to end: a corrupted mnemonic file must exit non-zero and print NO address,
        # and must not echo the (secret) mnemonic words to stdout/stderr.
        corrupted = CANON_MNEMONIC.rsplit(" ", 1)[0] + " abandom"
        with tempfile.TemporaryDirectory() as d:
            mf = os.path.join(d, "funding.mnemonic")
            with open(mf, "w") as f:
                f.write(corrupted + "\n")
            r = subprocess.run([sys.executable, _path, "--mnemonic-file", mf],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, r.stdout)
            self.assertNotIn("akash1", r.stdout)
            self.assertNotIn("abandom", r.stdout + r.stderr)
            self.assertNotIn("abandon", r.stdout + r.stderr)

    def test_cli_derives_from_mnemonic_file(self):
        # The mnemonic is SECRET and must be supplied off-argv via a file (tmpfs in the
        # ceremony), never as an argv value that leaks to ps / /proc/<pid>/cmdline.
        with tempfile.TemporaryDirectory() as d:
            mf = os.path.join(d, "funding.mnemonic")
            with open(mf, "w") as f:
                f.write(CANON_MNEMONIC + "\n")
            r = subprocess.run([sys.executable, _path, "--mnemonic-file", mf],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), CANON_AKASH_ADDR)
            # the secret mnemonic must not be echoed back on stdout/stderr
            self.assertNotIn("abandon", r.stdout)
            self.assertNotIn("abandon", r.stderr)

    def test_cli_rejects_mnemonic_on_argv(self):
        # There must be NO argv option that accepts the raw mnemonic value (it would leak to
        # cmdline / ps / shell history). Passing the mnemonic positionally/as a flag fails.
        r = subprocess.run([sys.executable, _path, "--mnemonic", CANON_MNEMONIC],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(
        importlib.util.find_spec("cosmpy") is not None, "cosmpy not installed for cross-check")
    def test_cross_check_against_cosmpy(self):
        from cosmpy.aerial.wallet import LocalWallet  # independent BIP32/secp256k1 impl
        expected = str(LocalWallet.from_mnemonic(CANON_MNEMONIC, prefix="akash").address())
        self.assertEqual(da.address_from_mnemonic(CANON_MNEMONIC), expected)




class EvmRefusal(unittest.TestCase):
    """REQUIREMENTS B2 — Ethermint/EVM chains must be REFUSED, never guessed at.

    This tool derives bech32(hrp, ripemd160(sha256(compressed_pubkey))) — the Cosmos SDK address.
    EVM chains use keccak256 of the UNCOMPRESSED key instead. Deriving anyway returns a
    well-formed, checksummed, plausible and COMPLETELY WRONG address, which is the worst failure
    shape available: silent, confident, and discovered when funds do not arrive.
    """

    MNEMONIC = "abandon " * 11 + "about"

    def _run(self, *args):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(self.MNEMONIC)
            path = fh.name
        try:
            return subprocess.run(
                [sys.executable, _path, "--mnemonic-file", path, *args],
                capture_output=True, text=True)
        finally:
            os.unlink(path)

    # The published Ethereum address for the BIP39 all-zeros seed at m/44'/60'/0'/0/0.
    # This is what makes EVM support verified rather than plausible.
    ETH_VECTOR = "9858effd232b4033e47d90003d41ec34ecaeda94"

    @staticmethod
    def _bech32_data(addr):
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        data = [charset.index(c) for c in addr.split("1", 1)[1][:-6]]
        acc = bits = 0
        out = bytearray()
        for v in data:
            acc = (acc << 5) | v
            bits += 5
            while bits >= 8:
                bits -= 8
                out.append((acc >> bits) & 0xFF)
        return bytes(out)

    def test_evm_address_matches_the_published_ethereum_vector(self):
        """The whole justification for implementing rather than refusing."""
        r = self._run("--hrp", "evmos", "--evm")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self._bech32_data(r.stdout.strip()).hex(), self.ETH_VECTOR,
                         "the bech32 payload is not the published Ethereum address")

    def test_every_evm_chain_wraps_the_same_20_bytes(self):
        bodies = set()
        for hrp in ("evmos", "inj", "dym", "canto", "xpla", "zeta", "crc"):
            with self.subTest(hrp=hrp):
                r = self._run("--hrp", hrp, "--evm")
                self.assertEqual(r.returncode, 0, f"{hrp} failed: {r.stdout}{r.stderr}")
                bodies.add(self._bech32_data(r.stdout.strip()).hex())
        self.assertEqual(bodies, {self.ETH_VECTOR})

    def test_evm_and_cosmos_addresses_differ_for_the_same_key(self):
        """If these ever matched, one of the two derivations would be wrong."""
        evm = self._run("--hrp", "evmos", "--evm").stdout.strip()
        cos = self._run("--hrp", "cosmos").stdout.strip()
        self.assertNotEqual(self._bech32_data(evm), self._bech32_data(cos))

    def test_evm_prefix_without_the_flag_is_refused(self):
        for hrp in ("evmos", "inj", "dym", "canto", "xpla", "zeta", "crc"):
            with self.subTest(hrp=hrp):
                r = self._run("--hrp", hrp)
                self.assertNotEqual(r.returncode, 0, f"{hrp} guessed a derivation instead of refusing")
                self.assertIn("REFUSING", r.stdout + r.stderr)

    def test_evm_flag_with_a_cosmos_coin_type_is_refused(self):
        """Regression: an EXPLICIT coin-118 path was once silently rewritten to coin-60 because it
        happened to equal the default — the guard performing the substitution it exists to stop."""
        r = self._run("--evm", "--hd-path", "m/44'/118'/0'/0/0")
        self.assertNotEqual(r.returncode, 0, "an explicit coin-118 path was accepted under --evm")
        self.assertIn("coin type 118", r.stdout + r.stderr)

    def test_coin_type_60_is_refused_whatever_the_prefix(self):
        # The robust catch: the HD path is unambiguous even if someone invents a prefix we
        # have never heard of.
        r = self._run("--hd-path", "m/44'/60'/0'/0/0")
        self.assertNotEqual(r.returncode, 0, "a coin-type-60 path produced a Cosmos address")
        self.assertIn("coin type 60", r.stdout + r.stderr)

    def test_the_refusal_explains_itself(self):
        # A refusal an operator does not understand gets worked around with a different --hrp,
        # which is exactly the mistake being prevented.
        r = self._run("--hrp", "evmos")
        msg = r.stdout + r.stderr
        # A refusal must do three things, or an operator routes around it with a different --hrp,
        # which is the exact mistake being prevented. Note the message changed once EVM became
        # supported: it now points at the RIGHT ACTION rather than only warning of a wrong address.
        self.assertIn("keccak256", msg, "does not name the correct derivation")
        self.assertIn("--evm", msg, "does not tell the operator what to do instead")
        self.assertIn("Do NOT work around this", msg, "does not close the obvious workaround")

    def test_standard_cosmos_chains_still_work(self):
        # The guard must not over-refuse. These are all coin type 118 / Cosmos SDK.
        bodies = set()
        for hrp in ("akash", "cosmos", "osmo", "juno", "stars"):
            with self.subTest(hrp=hrp):
                r = self._run("--hrp", hrp)
                self.assertEqual(r.returncode, 0, f"{hrp} was refused but is a standard Cosmos chain")
                addr = r.stdout.strip()
                self.assertTrue(addr.startswith(hrp + "1"), addr)
                bodies.add(addr[len(hrp) + 1:-6])
        # One key, one derivation — the prefix is presentation, not a different address.
        self.assertEqual(len(bodies), 1, f"same seed produced different key material per chain: {bodies}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
