#!/usr/bin/env python3
"""developer-keys.py (regalia-ceremony#124, ADR-0002 D29.2 and D30): the developers' set and the release key. The
release cards are a stand-in OpenPGP session (yubikit's interface), which records every call and can be made to fail
at each step; the fingerprint is checked against gpg's own; trust is checked against rc#121's card-record vectors."""
import os as _hermetic_os  # no real card, even run by hand (#104): no pcscd, the emulator stand-ins first
_hermetic_os.environ.setdefault("PCSCLITE_CSOCK_NAME", "/nonexistent/regalia-no-pcscd.comm")
_hermetic_os.environ["PATH"] = _hermetic_os.path.join(_hermetic_os.path.dirname(_hermetic_os.path.abspath(__file__)), "..", "bin") + _hermetic_os.pathsep + _hermetic_os.environ.get("PATH", "")
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import types
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


dk = _load("developer_keys", os.path.join(HERE, "..", "..", "scripts", "developer-keys.py"))
ok = dk.ok
cards = _load("card_vectors", os.path.join(HERE, "vectors", "card-ceremony-record", "make.py"))
HAVE_AGE = shutil.which("age") is not None and shutil.which("age-keygen") is not None
HAVE_GPG = shutil.which("gpg") is not None and shutil.which("gpgconf") is not None
try:
    from yubikit.openpgp import KEY_REF, KEY_STATUS, UIF
except ImportError:                      # the emulator image carries yubikey-manager; say so rather than skip silently
    KEY_REF = KEY_STATUS = UIF = None


def fake_age(argv, input=None, capture_output=True):
    out = argv[argv.index("-o") + 1]
    with open(out, "wb") as f:
        f.write(b"age-encryption.org/v1\n" + bytes(b ^ 0x5A for b in input))
    return subprocess.CompletedProcess(argv, 0, b"", b"")


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        env = {"CEREMONY_ALLOW_NONTMPFS": "1", "CEREMONY_ALLOW_SWAP": "1"}
        self.run_age = subprocess.run
        self.recipient = os.path.join(self.d, "bg.recipient")
        if HAVE_AGE:
            ident = os.path.join(self.d, "bg.key")
            if subprocess.run(["age-keygen", "-pq", "-o", ident], capture_output=True).returncode != 0:
                subprocess.run(["age-keygen", "-o", ident], check=True, capture_output=True)
                env.update(CEREMONY_ALLOW_CLASSICAL_BREAKGLASS="1", CEREMONY_SIMULATE="1")     # age before 1.3
            with open(self.recipient, "w") as f:
                f.write(subprocess.run(["age-keygen", "-y", ident], check=True, capture_output=True, text=True).stdout)
        else:
            self.run_age = fake_age
            with open(self.recipient, "w") as f:
                f.write("age1pq1" + "q" * 60 + "\n")
        patcher = unittest.mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.out = os.path.join(self.d, "out")
        os.mkdir(self.out)

    def generate(self, k=2, n=3):
        return dk.generate(k, n, self.out, self.recipient, run=self.run_age)

    def path(self, name):
        return os.path.join(self.out, name)

    def shares(self):
        with open(self.path(dk.FILES[1])) as f:
            return [line for line in f.read().splitlines() if line.strip()]


class Fingerprint(unittest.TestCase):
    @unittest.skipUnless(HAVE_GPG, "gpg is not installed here (the emulator job has it)")
    def test_the_v4_fingerprint_is_gpgs(self):
        """The fingerprint the cards are given is gpg's own for the same key and creation time."""
        for i in range(3):
            home = tempfile.mkdtemp(prefix="gf%d" % i)
            self.addCleanup(shutil.rmtree, home, True)
            self.addCleanup(subprocess.run, ["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)
            subprocess.run(["gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
                            "Release %d <r%d@example.invalid>" % (i, i), "ed25519", "sign", "never"], check=True, capture_output=True)
            listing = subprocess.run(["gpg", "--homedir", home, "--with-colons", "--list-keys"], check=True, capture_output=True, text=True).stdout
            created = int(next(line for line in listing.splitlines() if line.startswith("pub:")).split(":")[5])
            fpr = listing.split("fpr:::::::::")[1].split(":")[0]
            packet = subprocess.run(["gpg", "--homedir", home, "--export", fpr], check=True, capture_output=True).stdout
            # the first packet, a new-format public key packet (0xC6) or old-format (0x98/0x99): its body ends in 0x40 || key
            if packet[0] == 0x99:
                length, start = int.from_bytes(packet[1:3], "big"), 3
            elif packet[0] == 0x98:
                length, start = packet[1], 2
            else:
                self.assertEqual(packet[0], 0xC6)
                length, start = packet[1], 2
            body = packet[start:start + length]
            self.assertEqual(body[-33], 0x40)
            self.assertEqual(dk.v4_fingerprint(body[-32:], created), fpr)

    def test_refusals(self):
        with self.assertRaisesRegex(dk.Refused, "an Ed25519 public key is 32 bytes"):
            dk.v4_fingerprint(b"\0" * 31, 1)
        with self.assertRaisesRegex(dk.Refused, "the creation time is a 32-bit Unix time"):
            dk.v4_fingerprint(b"\0" * 32, 0)


class Generate(Case):
    def test_the_set_its_seal_its_break_glass_copy_and_a_pending_record(self):
        record = self.generate()
        self.assertEqual((record["status"], record["set"], record["threshold"], record["shares"]), ("pending", "developers", 2, 3))
        with open(self.path(dk.FILES[3])) as f:
            self.assertEqual(dk.verify_possession(json.load(f)), record)
        sealed = dk.load_sealed(self.path(dk.FILES[0]))
        release = sealed["publics"]["release"]
        self.assertEqual(release["fingerprint"], dk.v4_fingerprint(bytes.fromhex(release["key"]), release["created"]))
        self.assertEqual(sorted(sealed["publics"]), ["release"], "a key map, the release key only for now")
        key, indices = dk.open_key(sealed, io.StringIO("\n".join(self.shares()[1:3]) + "\n"))
        self.assertEqual((dk.raw_public(key).hex(), indices), (release["key"], [2, 3]))
        self.assertEqual(oct(os.stat(self.path(dk.FILES[1])).st_mode & 0o777), "0o600")
        with open(self.path(dk.FILES[2]), "rb") as f:
            self.assertTrue(f.read().startswith(b"age-encryption.org/v1"))

    def test_the_sets_are_separate(self):
        """A share of the offline keys' set never opens the developers' file, nor theirs ours."""
        self.generate()
        other = os.path.join(self.d, "offline")
        os.mkdir(other)
        ok.generate(2, 3, other, self.recipient, run=self.run_age)
        with open(os.path.join(other, ok.FILES[1])) as f:
            offline = [line for line in f.read().splitlines() if line.strip()]
        with self.assertRaisesRegex(dk.Refused, "these shares are of set"):
            dk.open_key(dk.load_sealed(self.path(dk.FILES[0])), io.StringIO("\n".join(offline[:2]) + "\n"))
        with self.assertRaisesRegex(dk.Refused, "is not the developers' sealed file"):
            dk.load_sealed(os.path.join(other, ok.FILES[0]))

    def test_refusals_leave_nothing_behind(self):
        with self.assertRaisesRegex(dk.Refused, "2 <= k <= n <= 16"):
            dk.generate(1, 3, self.out, self.recipient, run=self.run_age)

        def failing(argv, input=None, capture_output=True):
            return subprocess.CompletedProcess(argv, 1, b"", b"no")
        with self.assertRaisesRegex(dk.Refused, "age could not encrypt"):
            dk.generate(2, 3, self.out, self.recipient, run=failing)
        self.assertEqual(os.listdir(self.out), [])
        self.generate()
        with self.assertRaisesRegex(dk.Refused, "already exists"):
            self.generate()

    def test_forms_are_typed_back_before_the_shares_go(self):
        self.generate()
        shares = self.shares()
        sealed, made = self.path(dk.FILES[0]), self.path(dk.FILES[1])
        with self.assertRaisesRegex(dk.Refused, "forms 3 were not typed back"):
            dk.verify_forms(sealed, made, io.StringIO("\n".join(shares[:2]) + "\n"))
        wrong = shares[2].split()
        wrong[5] = "academic" if wrong[5] != "academic" else "acid"
        with self.assertRaisesRegex(dk.Refused, "not a valid SLIP-39 share"):
            dk.verify_forms(sealed, made, io.StringIO("\n".join(shares[:2] + [" ".join(wrong)]) + "\n"))
        self.assertTrue(os.path.exists(made))
        self.assertEqual(dk.verify_forms(sealed, made, io.StringIO("\n".join(shares) + "\n")), [1, 2, 3])
        self.assertFalse(os.path.exists(made), "the shares file is shredded once every form is proven")


class FakeCard:
    """yubikit's OpenPgpSession as the import uses it, recording each call; `fail` names a step that misbehaves."""

    def __init__(self, admin="87654321", user="654321", occupied=False, fail=None, uif=None, firmware="5.7.4"):
        self.admin, self.user, self.fail, self.calls, self.firmware = admin, user, fail, [], firmware
        self.status = KEY_STATUS.IMPORTED if occupied else KEY_STATUS.NONE
        self.uif, self.key, self.created, self.fpr = uif or UIF.OFF, None, None, b""

    def verify_pin(self, pin):
        self.calls.append("verify_pin")
        if pin != self.user:
            raise Exception("wrong PIN, 2 tries left")

    def verify_admin(self, pin):
        self.calls.append("verify_admin")
        if pin != self.admin:
            raise Exception("wrong admin PIN, 2 tries left")

    def get_key_information(self):
        return {KEY_REF.SIG: self.status}

    def set_uif(self, ref, uif):
        self.calls.append("set_uif")
        if self.uif in (UIF.FIXED, UIF.CACHED_FIXED):         # as a YubiKey: a fixed touch policy refuses every write
            raise Exception("security status not satisfied")
        if self.fail == "uif-before":
            return
        self.uif = uif

    def get_uif(self, ref):
        return UIF.CACHED_FIXED if self.fail == "uif-after" and self.key is not None else self.uif

    def put_key(self, ref, key):
        self.calls.append("put_key")
        self.key, self.status = key, KEY_STATUS.GENERATED if self.fail == "status" else KEY_STATUS.IMPORTED
        if self.fail == "put-raises":                       # the key written, then the connection lost
            self.fail = None
            raise Exception("the card stopped answering")

    def set_generation_time(self, ref, t):
        self.calls.append("set_generation_time")
        self.created = t

    def set_fingerprint(self, ref, fpr):
        self.calls.append("set_fingerprint")
        self.fpr = b"\x01" * 20 if self.fail == "fingerprint" else fpr

    def get_public_key(self, ref):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        if self.fail == "other-key":
            return ed25519.Ed25519PrivateKey.generate().public_key()
        return self.key.public_key()

    def get_application_related_data(self):
        return types.SimpleNamespace(discretionary=types.SimpleNamespace(fingerprints={KEY_REF.SIG: self.fpr}))

    def delete_key(self, ref):
        self.calls.append("delete_key")
        if self.fail_delete:
            raise Exception("the card did not answer")
        self.key, self.status = None, KEY_STATUS.NONE

    fail_delete = False


@unittest.skipUnless(KEY_REF is not None, "yubikey-manager is not installed here (the emulator job has it)")
class ReleaseImport(Case):
    SERIAL = "40000003"

    def setUp(self):
        super().setUp()
        self.generate()
        self.sealed = dk.load_sealed(self.path(dk.FILES[0]))

    def card_of(self, fake, serial=None):
        @contextlib.contextmanager
        def card(serial_typed):
            self.assertEqual(serial_typed, serial or self.SERIAL)
            yield fake, fake.firmware
        return card

    def run_import(self, fake=None, serial=None, replace=False, pins=("87654321", "654321"), typed=None):
        fake = fake or FakeCard()
        secrets_typed = iter(pins)
        return dk.release_import(self.path(dk.FILES[0]), serial or self.SERIAL, self.out, io.StringIO("\n".join(self.shares()[:2]) + "\n"),
                                 replace=replace, ask=lambda prompt: typed, ask_secret=lambda prompt: next(secrets_typed),
                                 card=self.card_of(fake, serial)), fake

    def test_the_key_goes_in_after_the_touch_policy_and_is_read_back(self):
        facts, fake = self.run_import()
        self.assertLess(fake.calls.index("set_uif"), fake.calls.index("put_key"), "the touch policy is set BEFORE the key goes in")
        release = self.sealed["publics"]["release"]
        self.assertEqual((facts["fingerprint"], facts["key"], facts["touch"], facts["imported"], facts["attested"], facts["firmware"]),
                         (release["fingerprint"], release["key"], "fixed", True, False, "5.7.4"))
        self.assertEqual((fake.uif, fake.created, fake.fpr.hex().upper()), (UIF.FIXED, release["created"], release["fingerprint"]))
        with open(self.path("release-import-%s.json" % self.SERIAL)) as f:
            self.assertEqual(json.load(f), facts)
        # the second release card, and a replacement later (D30.5): the same key, the same fingerprint
        second, _ = self.run_import(serial="40000004")
        self.assertEqual(second["fingerprint"], facts["fingerprint"])

    def test_refusals_before_anything_changes(self):
        cases = [
            (dict(serial="35718625"), "YubiKey 35718625 is a bench card: the ceremony never uses a bench serial"),
            (dict(pins=("12345678", "654321")), "a PIN typed is the factory default"),
            (dict(pins=("87654321", "123456")), "a PIN typed is the factory default"),
            (dict(pins=("11112222", "654321")), "refused a PIN"),
            (dict(fake=FakeCard(occupied=True)), "already holds a SIG key (IMPORTED): refused; replacing it takes --replace"),
            (dict(fake=FakeCard(occupied=True), replace=True, typed="40000004"), "the serial typed is not 40000003: nothing was changed"),
            (dict(fake=FakeCard(fail="uif-before")), "did not take a FIXED touch policy on SIG: nothing was imported"),
            (dict(fake=FakeCard(firmware="5.1.2")), "release card 40000003 runs firmware 5.1.2; the release key needs 5.2.3 or later: "
                                                    "nothing was changed"),
            (dict(fake=FakeCard(uif=UIF.CACHED_FIXED)), "has a CACHED_FIXED touch policy on SIG, which only a reset undoes: reset the "
                                                        "OpenPGP applet (ykman openpgp reset)"),
        ]
        for kw, reason in cases:
            fake = kw.get("fake") or FakeCard(fail=None)
            kw = dict(kw, fake=fake)
            with self.subTest(reason=reason), self.assertRaisesRegex(dk.Refused, re.escape(reason)):
                self.run_import(**kw)
            self.assertNotIn("put_key", fake.calls, reason)
            if "firmware" in reason:
                self.assertEqual(fake.calls, [], "the firmware is checked before anything is written, PINs included")
        self.assertFalse(any(n.startswith("release-import-") for n in os.listdir(self.out)))
        facts, fake = self.run_import(fake=FakeCard(occupied=True), replace=True, typed=self.SERIAL)
        self.assertIn("put_key", fake.calls)

    def test_a_rerun_and_replace_meet_the_fixed_touch_policy_already_set(self):
        """regalia-kms-d9 on #126: a FIXED touch policy refuses every write, so a rerun after a failed import and a
        --replace over the previous import must find it set, and not try to set it again."""
        fake = FakeCard(fail="fingerprint")
        with self.assertRaisesRegex(dk.Refused, "the key was deleted from it"):
            self.run_import(fake=fake)
        self.assertEqual((fake.uif, fake.status), (UIF.FIXED, KEY_STATUS.NONE))
        fake.fail, fake.calls = None, []
        facts, _ = self.run_import(fake=fake)
        self.assertNotIn("set_uif", fake.calls)
        self.assertEqual(facts["touch"], "fixed")
        os.unlink(self.path("release-import-%s.json" % self.SERIAL))
        replaced = FakeCard(occupied=True, uif=UIF.FIXED)
        facts, _ = self.run_import(fake=replaced, replace=True, typed=self.SERIAL)
        self.assertEqual((replaced.status, "set_uif" in replaced.calls), (KEY_STATUS.IMPORTED, False))

    def test_a_put_that_fails_part_way_is_cleaned_up(self):
        """regalia-kms-d9 on #126: put_key inside the scope that deletes: the card may hold the key after an error."""
        fake = FakeCard(fail="put-raises")
        with self.assertRaisesRegex(dk.Refused, "release card 40000003 is unusable for release \\(the card stopped answering\\): the key "
                                    "was deleted from it"):
            self.run_import(fake=fake)
        self.assertEqual((fake.calls[-1], fake.key, fake.status), ("delete_key", None, KEY_STATUS.NONE))

    def test_a_card_that_fails_the_read_back_has_the_key_taken_off(self):
        """regalia-kms-d9 on #124: never a release key on a card without FIXED touch, and no footgun left for a hand."""
        for fail, reason in (("uif-after", "the touch policy on SIG is not FIXED"), ("status", "SIG is not reported IMPORTED"),
                             ("other-key", "SIG holds another public key than the sealed one"),
                             ("fingerprint", "the fingerprint on SIG is not the computed v4 fingerprint")):
            fake = FakeCard(fail=fail)
            with self.subTest(fail=fail), self.assertRaisesRegex(dk.Refused, "release card 40000003 is unusable for release \\(%s.*the key "
                                                                 "was deleted from it and the slot read back empty" % reason):
                self.run_import(fake=fake)
            self.assertEqual((fake.calls[-1], fake.key), ("delete_key", None))
        fake = FakeCard(fail="uif-after")
        fake.fail_delete = True
        with self.assertRaisesRegex(dk.Refused, "is UNUSABLE and its SIG key could NOT be deleted .*reset its OpenPGP applet .*before it "
                                    "leaves the room"):
            self.run_import(fake=fake)
        self.assertFalse(any(n.startswith("release-import-") for n in os.listdir(self.out)))


class Trust(Case):
    """Possession is not authority: the release key is trusted only as a root-signed card record names it."""

    def setUp(self):
        super().setUp()
        self.generate()
        with open(self.path(dk.FILES[3])) as f:
            self.developers = json.load(f)
        self.release = self.developers["record"]["publics"]["release"]
        self.root = cards.raw(cards.ROOT)

    def card_record(self, key=None, fingerprint=None):
        record = cards.valid_record()
        record["release_key"].update(key=key or self.release["key"], fingerprint=fingerprint or self.release["fingerprint"])
        return cards.signed(record)

    def test_vouched_by_the_root_signed_card_record(self):
        entry = dk.vouched(self.developers, self.card_record(), self.root)
        self.assertEqual((entry["fingerprint"], entry["cards"]), (self.release["fingerprint"], ["40000003", "40000004"]))

    def test_a_self_signed_record_alone_is_trusted_by_nothing(self):
        with open(os.path.join(HERE, "vectors", "card-ceremony-record", "valid.json")) as f:
            another = json.load(f)                           # root-signed, but for another release key
        with self.assertRaises(dk.Refused) as caught:
            dk.vouched(self.developers, another, self.root)
        self.assertEqual(str(caught.exception), "the release key is not the one the root-signed card record names: it is pending, and "
                         "nothing trusts it")
        with self.assertRaisesRegex(dk.Refused, "the record names another root than the pinned one"):
            dk.vouched(self.developers, self.card_record(), cards.raw(cards.OTHER_ROOT))
        with self.assertRaisesRegex(dk.Refused, "the release key is not the one"):
            dk.vouched(self.developers, self.card_record(fingerprint="AB" * 20), self.root)

    def test_the_possession_record_is_checked(self):
        forged = copy.deepcopy(self.developers)
        forged["record"]["threshold"] = 3
        with self.assertRaisesRegex(dk.Refused, "is not signed by the release key it names"):
            dk.verify_possession(forged)
        promoted = copy.deepcopy(self.developers)
        promoted["record"]["status"] = "trusted"
        with self.assertRaisesRegex(dk.Refused, "pending until a root-signed card record names its key"):
            dk.verify_possession(promoted)


if __name__ == "__main__":
    unittest.main()
