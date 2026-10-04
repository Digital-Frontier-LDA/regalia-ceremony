#!/usr/bin/env python3
"""offline-keys.py generate (regalia-ceremony#111, ADR-0002 D28): the four offline keys, the sealed file, the SLIP-39
share set of their master secret (k rebuild it, k-1 do not), the break-glass copy, and the record the new root signs.
Uses the real shamir-mnemonic and cryptography; age when installed (the emulator job installs age 1.3.2)."""
import os as _hermetic_os  # no real card, even run by hand (#104): no pcscd, the emulator stand-ins first
_hermetic_os.environ.setdefault("PCSCLITE_CSOCK_NAME", "/nonexistent/regalia-no-pcscd.comm")
_hermetic_os.environ["PATH"] = _hermetic_os.path.join(_hermetic_os.path.dirname(_hermetic_os.path.abspath(__file__)), "..", "bin") + _hermetic_os.pathsep + _hermetic_os.environ.get("PATH", "")
import base64
import hashlib
import importlib.machinery
import importlib.util
import itertools
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "scripts", "offline-keys.py")
_loader = importlib.machinery.SourceFileLoader("offline_keys", SCRIPT)
_spec = importlib.util.spec_from_loader("offline_keys", _loader)
ok = importlib.util.module_from_spec(_spec)
_loader.exec_module(ok)
HAVE_AGE = shutil.which("age") is not None and shutil.which("age-keygen") is not None


def fake_age(argv, input=None, capture_output=True):
    """age stood in for where it is not installed: an 'age file' that is the input XORed with a constant, so the
    no-plaintext check has something real to look at."""
    out = argv[argv.index("-o") + 1]
    with open(out, "wb") as f:
        f.write(b"age-encryption.org/v1\n" + bytes(b ^ 0x5A for b in input))
    return subprocess.CompletedProcess(argv, 0, b"", b"")


class Generate(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        patcher = unittest.mock.patch.dict(os.environ, {"CEREMONY_ALLOW_NONTMPFS": "1", "CEREMONY_ALLOW_SWAP": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.out = os.path.join(self.d, "out")
        os.mkdir(self.out)
        self.identity = os.path.join(self.d, "bg.key")
        self.recipient = os.path.join(self.d, "bg.recipient")
        if HAVE_AGE:
            if subprocess.run(["age-keygen", "-pq", "-o", self.identity], capture_output=True).returncode != 0:
                subprocess.run(["age-keygen", "-o", self.identity], check=True, capture_output=True)
            with open(self.recipient, "w") as f:
                f.write(subprocess.run(["age-keygen", "-y", self.identity], check=True, capture_output=True, text=True).stdout)
        else:
            with open(self.recipient, "w") as f:
                f.write("age1testrecipient0000000000000000000000000000000000000000000\n")

    def generate(self, k=4, n=6, **kw):
        run = subprocess.run if HAVE_AGE else fake_age
        return ok.generate(k, n, self.out, self.recipient, run=run, **kw)

    def path(self, name):
        return os.path.join(self.out, name)

    def shares(self):
        with open(self.path("offline-shares.txt")) as f:
            return f.read().split("\n")[:-1]

    def test_four_keys_sealed_split_backed_up_and_recorded(self):
        record = self.generate()
        for name in ok.FILES:
            self.assertTrue(os.path.exists(self.path(name)), name)
        self.assertEqual(oct(os.stat(self.path("offline-shares.txt")).st_mode & 0o777), "0o600")
        self.assertEqual(sorted(record["publics"]), ["pcr-initrd", "pcr-system", "root", "secure-boot"])
        self.assertEqual({p["alg"] for n, p in record["publics"].items() if n != "root"}, {"rsa-2048"})
        self.assertEqual(record["root_entry"]["alg"], "ed25519")
        self.assertEqual(len(record["root_entry"]["key"]), 64)
        with open(self.path("offline-keys.sealed.json"), "rb") as f:
            sealed = json.loads(f.read())
        self.assertEqual(record["files"]["offline-keys.sealed.json"], hashlib.sha256(open(self.path("offline-keys.sealed.json"), "rb").read()).hexdigest())
        # the sealed file is public: nothing of a private key in it, the publics in the clear
        self.assertNotIn("pkcs8", json.dumps(sealed))
        self.assertEqual(sealed["publics"], record["publics"])
        # the record verifies under the root entry it names
        with open(self.path("offline-keys.record.json"), "rb") as f:
            self.assertEqual(ok.verify_record(json.loads(f.read()))["master_id"], sealed["master_id"])

    def test_k_shares_open_the_sealed_file_and_k_minus_1_do_not(self):
        from shamir_mnemonic import combine_mnemonics
        self.generate(k=3, n=5)
        shares = self.shares()
        self.assertEqual(len(shares), 5)
        with open(self.path("offline-keys.sealed.json"), "rb") as f:
            sealed = json.loads(f.read())
        for subset in itertools.combinations(shares, 3):
            bundle = ok.unseal(combine_mnemonics(list(subset)), sealed)
            self.assertEqual(sorted(bundle["keys"]), ["pcr-initrd", "pcr-system", "root", "secure-boot"])
        with self.assertRaises(Exception):
            combine_mnemonics(shares[:2])
        # every key in the bundle is the one the header names
        from cryptography.hazmat.primitives import serialization
        bundle = ok.unseal(combine_mnemonics(shares[:3]), sealed)
        for name, entry in bundle["keys"].items():
            key = serialization.load_der_private_key(base64.b64decode(entry["pkcs8"]), None)
            spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            self.assertEqual(base64.b64encode(spki).decode(), sealed["publics"][name]["spki"], name)

    def test_another_set_or_an_altered_file_is_refused(self):
        from shamir_mnemonic import combine_mnemonics
        self.generate(k=2, n=3)
        with open(self.path("offline-keys.sealed.json"), "rb") as f:
            sealed = json.loads(f.read())
        with self.assertRaisesRegex(ok.Refused, "another master secret"):
            ok.unseal(b"\x07" * 32, sealed)
        master = combine_mnemonics(self.shares()[:2])
        altered = dict(sealed, publics=dict(sealed["publics"], root=sealed["publics"]["pcr-initrd"]))
        with self.assertRaisesRegex(ok.Refused, "does not open"):
            ok.unseal(master, altered)

    @unittest.skipUnless(HAVE_AGE, "age is not installed here (the emulator job installs it)")
    def test_the_break_glass_key_opens_the_backup_and_nothing_is_in_the_clear(self):
        from shamir_mnemonic import combine_mnemonics
        self.generate(k=2, n=3)
        plain = subprocess.run(["age", "-d", "-i", self.identity, self.path("offline-keys.breakglass.age")], check=True, capture_output=True).stdout
        bundle = json.loads(plain)
        with open(self.path("offline-keys.sealed.json"), "rb") as f:
            sealed = json.loads(f.read())
        self.assertEqual(bundle, ok.unseal(combine_mnemonics(self.shares()[:2]), sealed), "the backup and the Shamir set hold the same keys")
        with open(self.path("offline-keys.breakglass.age"), "rb") as f:
            raw = f.read()
        for entry in bundle["keys"].values():
            self.assertNotIn(entry["pkcs8"].encode(), raw)

    def test_a_backup_that_holds_a_key_in_the_clear_is_refused(self):
        def leaky(argv, input=None, capture_output=True):
            with open(argv[argv.index("-o") + 1], "wb") as f:
                f.write(b"age-encryption.org/v1\n" + input)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        with self.assertRaisesRegex(ok.Refused, "holds a key in the clear"):
            ok.generate(2, 3, self.out, self.recipient, run=leaky)
        self.assertEqual(os.listdir(self.out), [], "nothing is left: no share, no sealed file, no record")

    def test_a_record_altered_or_signed_by_another_key_is_refused(self):
        self.generate(k=2, n=3)
        with open(self.path("offline-keys.record.json"), "rb") as f:
            document = json.loads(f.read())
        changed = json.loads(json.dumps(document))
        changed["record"]["threshold"] = 1
        with self.assertRaisesRegex(ok.Refused, "does not verify"):
            ok.verify_record(changed)
        other = json.loads(json.dumps(document))
        other["record"]["root_entry"]["key"] = "00" * 32
        with self.assertRaises(ok.Refused):
            ok.verify_record(other)

    def test_the_record_prefix_is_never_a_membership_signing_input(self):
        """d9's amendment on #111: a record signature can never be read as a manifest signature, nor the reverse."""
        self.assertFalse(ok.RECORD_DOMAIN.startswith(ok.MEMBERSHIP_DOMAIN))
        self.assertFalse(ok.MEMBERSHIP_DOMAIN.startswith(ok.RECORD_DOMAIN))
        self.assertTrue(ok.RECORD_DOMAIN.endswith(b"\0") and ok.MEMBERSHIP_DOMAIN.endswith(b"\0"))
        self.assertNotIn(b"\0", ok.RECORD_DOMAIN[:-1])

    def test_refusals_before_anything_is_generated(self):
        for k, n in ((1, 3), (4, 3), (2, 17)):
            with self.assertRaisesRegex(ok.Refused, "2 <= k <= n <= 16"):
                self.generate(k=k, n=n)
        with open(self.path("offline-shares.txt"), "w") as f:
            f.write("left over")
        with self.assertRaisesRegex(ok.Refused, "already exists"):
            self.generate()
        os.unlink(self.path("offline-shares.txt"))
        with unittest.mock.patch.dict(os.environ, {"CEREMONY_ALLOW_NONTMPFS": "0"}), unittest.mock.patch.object(ok, "fs_type", lambda p: "ext4"):
            with self.assertRaisesRegex(ok.Refused, "on ext4, not a RAM file system"):
                self.generate()
        with unittest.mock.patch.dict(os.environ, {"CEREMONY_ALLOW_SWAP": "0"}), unittest.mock.patch.object(ok, "swap_in_use", lambda: ["/dev/zram0"]):
            with self.assertRaisesRegex(ok.Refused, "swap is on"):
                self.generate()
        with open(self.recipient, "w") as f:
            f.write("not a recipient\n")
        with self.assertRaisesRegex(ok.Refused, "does not hold an age recipient"):
            self.generate()
        self.assertEqual(os.listdir(self.out), [])

    def test_shares_rebuild_and_a_wrong_threshold_is_caught(self):
        """The split's own verification: a set whose k-1 shares rebuild the secret is refused."""
        master = bytearray(b"\x11" * 32)
        mnemonics, identifier = ok.split(master, 3, 4)
        self.assertEqual(len(mnemonics), 4)
        self.assertIsInstance(identifier, int)
        import shamir_mnemonic
        real = shamir_mnemonic.combine_mnemonics
        with unittest.mock.patch.object(shamir_mnemonic, "combine_mnemonics", lambda m, *a: bytes(master)):
            with self.assertRaisesRegex(ok.Refused, "2 shares rebuilt the master secret"):
                ok.split(master, 3, 4)
        self.assertIs(shamir_mnemonic.combine_mnemonics, real)

    def test_the_cli_takes_no_secret_on_argv(self):
        with open(SCRIPT) as f:
            text = f.read()
        for flag in ("--master", "--share", "--mnemonic", "--passphrase", "--secret", "--key"):
            self.assertNotIn('"%s"' % flag, text, "a secret-bearing option on the command line")


if __name__ == "__main__":
    unittest.main()
