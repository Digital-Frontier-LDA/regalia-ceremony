#!/usr/bin/env python3
"""owner-cards.py (regalia-ceremony#111 step 2, ADR-0002 D30.7) against a stand-in card. The stand-in is yubikit's
OpenPgpSession as the owner-card enrolment uses it: it "generates" the keys of a software gpg key made here, so a stand-in
for gpg's card dialogue can hand over a real certificate over exactly those keys; it keeps what is written to it
(fingerprints, times, touch policies) and attests each slot under the card-record vectors' stand-in Yubico hierarchy,
with the extensions a real card writes, or with the lie a test asks for."""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


oc = load("owner_cards", os.path.join(HERE, "..", "..", "scripts", "owner-cards.py"))
make = load("card_vectors", os.path.join(HERE, "vectors", "card-ceremony-record", "make.py"))
ok = oc.ok
ADMIN, USER = "87654321", "654321"


def software_key(home, name):
    """A gpg key like an owner card's certificate: Ed25519 primary [SC], cv25519 [E], Ed25519 [A]. Returns its fingerprint."""
    gpg = ["gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
    subprocess.run(gpg + ["--quick-gen-key", "%s <%s@example.invalid>" % (name, name), "ed25519", "cert,sign", "never"], check=True, capture_output=True)
    fpr = subprocess.run(["gpg", "--homedir", home, "--with-colons", "--list-keys"], check=True, capture_output=True,
                         text=True).stdout.split("fpr:::::::::")[1].split(":")[0]
    subprocess.run(gpg + ["--quick-add-key", fpr, "cv25519", "encr", "never"], check=True, capture_output=True)
    subprocess.run(gpg + ["--quick-add-key", fpr, "ed25519", "auth", "never"], check=True, capture_output=True)
    subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)
    return fpr


class FakeCard:
    """yubikit's OpenPgpSession, as enroll uses it."""

    def __init__(self, serial, keys, firmware="5.7.4", held=(), uif=None, lie=None, other_key=None, forgets=(), other_ca=False):
        from yubikit.openpgp import KEY_REF, KEY_STATUS, UIF
        self.KEY_REF, self.KEY_STATUS, self.UIF = KEY_REF, KEY_STATUS, UIF
        self.serial, self.firmware, self.keys, self.lie = serial, firmware, keys, lie or {}
        self.refs = {KEY_REF.SIG: "sig", KEY_REF.DEC: "dec", KEY_REF.AUT: "aut"}
        self.status = {ref: (KEY_STATUS.GENERATED if self.refs[ref] in held else KEY_STATUS.NONE) for ref in self.refs}
        self.uif = {ref: (uif or {}).get(self.refs[ref], UIF.OFF) for ref in self.refs}
        self.fingerprints, self.times, self.generated, self.pins = {}, {}, set(), []
        self.other_key, self.forgets = other_key, forgets       # an attestation over another key; writes the card drops
        self.other_ca = other_ca                                # a card CA that did not sign the leaves

    # a real card's access rules, per session (a new connection starts unverified): the admin PIN (PW3) for every
    # change, the user PIN (PW1) to attest (SW 6982 otherwise: regalia-kms-24's second bench run, 2026-10-05)
    def opened(self):
        self.verified = set()

    def need(self, which):
        if which not in self.verified:
            raise RuntimeError("APDU error: SW=0x6982 (security condition not satisfied: %s PIN)" % which)

    def verify_pin(self, pin):
        assert pin == USER, "the user PIN"
        self.pins.append("user")
        self.verified.add("user")

    def verify_admin(self, pin):
        assert pin == ADMIN, "the admin PIN"
        self.pins.append("admin")
        self.verified.add("admin")

    def get_key_information(self):
        return dict(self.status)

    def get_uif(self, ref):
        return self.uif[ref]

    def set_uif(self, ref, value):
        self.need("admin")
        assert self.uif[ref] not in (self.UIF.FIXED, self.UIF.CACHED_FIXED), "a fixed touch policy refuses every write"
        if "uif" not in self.forgets:
            self.uif[ref] = value

    def generate_ec_key(self, ref, oid):
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        slot = self.refs[ref]
        self.need("admin")
        if self.lie.get("fail_generate") == slot:
            if self.lie.get("interrupt"):
                raise KeyboardInterrupt
            raise RuntimeError("the card stopped answering")
        self.status[ref] = self.KEY_STATUS.GENERATED
        self.generated.add(slot)
        raw = bytes.fromhex(self.keys[slot]["point"])
        return x25519.X25519PublicKey.from_public_bytes(raw) if slot == "dec" else ed25519.Ed25519PublicKey.from_public_bytes(raw)

    def set_fingerprint(self, ref, fpr):
        self.need("admin")
        if "fingerprint" not in self.forgets:
            self.fingerprints[ref] = bytes(fpr)

    def set_generation_time(self, ref, ts):
        self.need("admin")
        self.times[ref] = ts

    def get_application_related_data(self):
        import types
        return types.SimpleNamespace(discretionary=types.SimpleNamespace(fingerprints=dict(self.fingerprints)))

    def attest_key(self, ref):
        self.need("user")
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        slot = self.refs[ref]
        raw = bytes.fromhex(self.keys[slot]["point"])
        public = x25519.X25519PublicKey.from_public_bytes(raw) if slot == "dec" else ed25519.Ed25519PublicKey.from_public_bytes(raw)
        if self.other_key == slot:
            public = make.key(36).public_key()
        claims = {"2": make._der_integer(1 if slot in self.generated else 2), "7": make._der_integer(int(self.serial)),
                  "8": make._der_octets(bytes([int(self.uif[ref])])), "4": make._der_octets(self.fingerprints.get(ref, b"\0" * 20)),
                  "5": make._der_octets(self.times.get(ref, 0).to_bytes(4, "big")), "3": make._der_octets(bytes([5, 7, 4]))}
        claims.update(self.lie.get(slot, {}))
        return make._cert("YubiKey OPGP Attestation " + slot.upper(), "YubiKey OPGP Attestation", make.key(35), public,
                          int(self.serial) * 10 + len(slot), tuple(sorted(claims.items())))

    def get_certificate(self, ref):
        assert ref == self.KEY_REF.ATT
        return make._cert("YubiKey OPGP Attestation", "Yubico OPGP Attestation B 1", make.YB1,
                          make.key(37 if self.other_ca else 35).public_key(), int(self.serial), ca=True)


class Enroll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vault = tempfile.mkdtemp()
        cls.identity, cls.recipient = os.path.join(cls.vault, "bg.key"), os.path.join(cls.vault, "bg.recipient")
        subprocess.run(["age-keygen", "-pq", "-o", cls.identity], check=True, capture_output=True)
        with open(cls.recipient, "w") as f:
            f.write(subprocess.run(["age-keygen", "-y", cls.identity], check=True, capture_output=True, text=True).stdout)
        cls.homes = {}
        for name in ("main", "backup", "other"):
            home = tempfile.mkdtemp(prefix="oc%s" % name[0])        # short: the agent's socket path has a length limit
            os.chmod(home, 0o700)
            cls.homes[name] = (home, software_key(home, "Owner " + name))

    @classmethod
    def tearDownClass(cls):
        for home, _ in cls.homes.values():
            subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)
            shutil.rmtree(home, True)
        shutil.rmtree(cls.vault, True)

    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.out, True)
        self.cards = {}

    def keys_of(self, which):
        home, fpr = self.homes[which]
        export = subprocess.run(["gpg", "--homedir", home, "--export", fpr], check=True, capture_output=True).stdout
        return oc.certificate_keys(export, oc.gpg_capabilities(home))

    def enroll(self, which="main", role="owner-main", serial="40000001", build_from=None, out=None, typed=None, seen=None, **card_kw):
        self.card = FakeCard(serial, self.keys_of(which), **card_kw)

        @contextlib.contextmanager
        def card(s):
            self.assertEqual(s, serial)
            self.card.opened()
            yield self.card, self.card.firmware

        def build(home, name, email, user_pin):
            self.assertEqual(user_pin, USER)
            with open(os.path.join(home, "scdaemon.conf")) as f:     # scdaemon through pcscd only (24's bench run)
                self.assertEqual(f.read(), "pcsc-shared\ndisable-ccid\n")
            source, fpr = self.homes[build_from or which]
            for entry in os.listdir(source):
                if not entry.startswith("S."):                    # not the agent's sockets
                    path = os.path.join(source, entry)
                    if os.path.isdir(path):
                        shutil.copytree(path, os.path.join(home, entry), dirs_exist_ok=True)   # the agent may have made it
                    else:
                        shutil.copy2(path, os.path.join(home, entry))
            return fpr
        pins = iter([ADMIN, USER])
        return oc.enroll(role, serial, "Owner", "owner@example.invalid", out or self.out, self.recipient, replace=typed is not None,
                         ask=lambda prompt: typed, ask_secret=lambda prompt: next(pins), card=card, build=build,
                         seen=seen or (lambda home, s: self.assertEqual(s, serial)))

    def test_a_card_enrolled_and_the_facts_it_proves(self):
        facts = self.enroll()
        keys = self.keys_of("main")
        self.assertEqual(facts["primary"], self.homes["main"][1])
        self.assertEqual({s: facts["keys"][s]["key"] for s in oc.SLOTS}, {s: keys[s]["point"] for s in oc.SLOTS})
        # on the card: the certificate's fingerprints and times, touch fixed on all three
        for ref, slot in self.card.refs.items():
            self.assertEqual(self.card.fingerprints[ref].hex().upper(), keys[slot]["fingerprint"])
            self.assertEqual(self.card.times[ref], keys[slot]["created"])
            self.assertEqual(self.card.uif[ref], self.card.UIF.FIXED)
        named = oc.outputs(self.out, "40000001")
        for slot in oc.SLOTS:
            with open(named[slot], "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), facts["attestation_sha256"][slot])
        self.assertTrue(os.path.exists(named["att"]))
        # gpg's revocation certificate: sealed to the break-glass recipient, its plaintext nowhere in --out (d9 on #140)
        revocation = subprocess.run(["age", "-d", "-i", self.identity, named["rev"]], check=True, capture_output=True).stdout
        self.assertIn(b"This is a revocation certificate", revocation, "gpg's own revocation file, as gpg wrote it")
        self.assertEqual(hashlib.sha256(revocation).hexdigest(), facts["revocation_sha256"])
        for name in os.listdir(self.out):
            path = os.path.join(self.out, name)
            if os.path.isfile(path):
                self.assertNotIn(revocation, open(path, "rb").read(), "%s holds the revocation in the clear" % name)
        self.assertEqual(ok.ssh_ed25519_raw(facts["ssh"], "ssh"), keys["aut"]["point"])
        self.assertFalse(os.path.exists(named["home"]), "the GnuPG home is removed")
        with open(os.path.join(self.out, "owner-card-40000001.json"), "rb") as f:
            self.assertEqual(json.loads(f.read()), facts)

    def test_the_two_cards_join_into_what_the_card_record_takes(self):
        main_out, backup_out = os.path.join(self.out, "main"), os.path.join(self.out, "backup")
        os.mkdir(main_out)
        os.mkdir(backup_out)
        self.enroll("main", "owner-main", "40000001", out=main_out)
        self.enroll("backup", "owner-backup", "40000002", out=backup_out)
        joined = oc.cards(os.path.join(main_out, "owner-card-40000001.json"), os.path.join(backup_out, "owner-card-40000002.json"), self.out)
        record = make.valid_record()
        self.assertEqual(sorted(joined), ["owner_keys", "ownerauth_recipients", "ssh_signers"], "the card record's --cards input")
        record.update(joined)
        self.assertIs(ok.card_record_check(record), record, "the joined facts pass the card record's every rule")
        with open(os.path.join(self.out, "owner-cards.gpg"), "rb") as f:
            both = f.read()
        self.assertEqual(len([t for t, _ in oc.packets(both) if t == 6]), 2, "both certificates, as step a imports them")
        with self.assertRaisesRegex(ok.Refused, "is not owner-main's facts"):
            oc.cards(os.path.join(backup_out, "owner-card-40000002.json"), os.path.join(main_out, "owner-card-40000001.json"), self.out)
        # d9 on #140: the facts are re-proved from the files beside them
        facts_path = os.path.join(main_out, "owner-card-40000001.json")
        kept = open(facts_path, "rb").read()
        for change, reason in ((lambda f: f["keys"]["dec"].update(fingerprint="AB" * 20), "DEC attestation does not say what its facts say"),
                               (lambda f: f["attestation_sha256"].update(aut="00" * 32), "AUT attestation is not the file beside it"),
                               (lambda f: f.update(ssh=oc.ssh_line("11" * 32)), "primary or SSH key is not its SIG or AUT key")):
            with self.subTest(reason=reason):
                edited = json.loads(kept)
                change(edited)
                with open(facts_path, "wb") as f:
                    f.write(json.dumps(edited).encode())
                with self.assertRaisesRegex(ok.Refused, reason):
                    oc.cards(facts_path, os.path.join(backup_out, "owner-card-40000002.json"), tempfile.mkdtemp(dir=self.out))
        with open(facts_path, "wb") as f:
            f.write(kept)

    def test_any_output_already_there_is_refused_before_the_card_is_touched(self):
        """d9 on #140: a second card into the same directory, or a leftover, never costs a card its keys."""
        for which in ("att", "aut", "rev", "home"):
            with self.subTest(which=which):
                out = tempfile.mkdtemp(dir=self.out)
                path = oc.outputs(out, "40000001")[which]
                os.mkdir(path) if which == "home" else open(path, "w").close()
                with self.assertRaisesRegex(ok.Refused, "already exist.*nothing is overwritten, and the card was not touched"):
                    self.enroll(out=out)
                self.assertEqual(self.card.generated, set())
        self.enroll()                                            # owner-main, then owner-backup into the same directory
        self.assertEqual(self.enroll("backup", "owner-backup", "40000002")["serial"], "40000002")

    def test_every_refusal_after_generation_says_the_card_needs_a_reset(self):
        def broken(home, name, email, pin):
            raise subprocess.CalledProcessError(2, ["gpg"])
        self.card = FakeCard("40000001", self.keys_of("main"))

        @contextlib.contextmanager
        def card(s):
            self.card.opened()
            yield self.card, self.card.firmware
        pins = iter([ADMIN, USER])
        with self.assertRaisesRegex(ok.Refused, "Owner card 40000001 now holds NEW keys: reset its OpenPGP applet"):
            oc.enroll("owner-main", "40000001", "O", "o@example.invalid", self.out, self.recipient, ask_secret=lambda p: next(pins), card=card,
                      build=broken, seen=lambda home, s: None)
        self.assertEqual(self.card.generated, set(oc.SLOTS))
        self.assertFalse(os.path.exists(oc.outputs(self.out, "40000001")["home"]), "the GnuPG home (and any revocation in it) is gone")
        with self.assertRaisesRegex(ok.Refused, "the SIG attestation is not signed by the card's attestation CA.*now holds NEW keys"):
            self.enroll(out=tempfile.mkdtemp(dir=self.out), other_ca=True)

    def test_a_classical_breakglass_recipient_is_refused_before_the_card_changes(self):
        classical = os.path.join(self.out, "classical.recipient")
        identity = os.path.join(self.out, "classical.key")
        subprocess.run(["age-keygen", "-o", identity], check=True, capture_output=True)
        with open(classical, "w") as f:
            f.write(subprocess.run(["age-keygen", "-y", identity], check=True, capture_output=True, text=True).stdout)
        self.recipient, kept = classical, self.recipient
        try:
            with self.assertRaisesRegex(ok.Refused, "holds a classical age recipient: the break-glass key is post-quantum"):
                self.enroll()
        finally:
            self.recipient = kept
        self.assertEqual(self.card.generated, set())

    def test_the_card_gpg_reaches_is_checked_before_anything_is_generated(self):
        """regalia-kms-24's bench run: scdaemon's own CCID driver took a Nitrokey. Now its home says pcsc-shared and
        disable-ccid, and the card ITS scdaemon reaches must be the owner card, before a key is generated."""
        def other(home, serial):
            raise ok.Refused("scdaemon reaches card 40000009, not owner card %s" % serial)
        with self.assertRaisesRegex(ok.Refused, "^scdaemon reaches card 40000009, not owner card 40000001$"):
            self.enroll(seen=other)
        self.assertEqual(self.card.generated, set(), "nothing was generated")
        self.assertFalse(os.path.exists(oc.outputs(self.out, "40000001")["home"]), "no leftover blocks a rerun")
        self.assertEqual(self.enroll()["serial"], "40000001")

    def test_an_interrupt_after_generation_still_says_the_card_needs_a_reset(self):
        import io
        def interrupted(home, name, email, pin):
            raise KeyboardInterrupt
        err = io.StringIO()
        pins = iter([ADMIN, USER])
        with unittest.mock.patch("sys.stderr", err), self.assertRaises(KeyboardInterrupt):
            oc.enroll("owner-main", "40000001", "O", "o@example.invalid", self.out, self.recipient, ask_secret=lambda prompt: next(pins),
                      card=self._card(), build=interrupted, seen=lambda h, s: None)
        self.assertIn("interrupted. Owner card 40000001 now holds NEW keys", err.getvalue())
        with unittest.mock.patch("sys.stderr", io.StringIO()) as err, self.assertRaises(KeyboardInterrupt):
            self.enroll(out=tempfile.mkdtemp(dir=self.out), lie={"fail_generate": "dec", "interrupt": True})
        self.assertIn("interrupted. Owner card 40000001 may now hold NEW keys", err.getvalue())

    def _card(self):
        self.card = FakeCard("40000001", self.keys_of("main"))

        @contextlib.contextmanager
        def card(s):
            self.card.opened()
            yield self.card, self.card.firmware
        return card

    def test_a_failure_part_way_through_the_writes_leaves_none_of_the_cards_files(self):
        """d9 on #140: ENOSPC after the certificate is written: no owner-card-<serial>.* is left, and after the card's
        reset the rerun proceeds."""
        real = oc._write_new
        written = []

        def full(path, data):
            if written:
                raise OSError(28, "No space left on device")
            written.append(path)
            return real(path, data)
        with unittest.mock.patch.object(oc, "_write_new", side_effect=full):
            with self.assertRaisesRegex(ok.Refused, "No space left on device.*now holds NEW keys"):
                self.enroll()
        self.assertTrue(written, "one file was written before the failure")
        self.assertEqual([n for n in os.listdir(self.out) if n.startswith("owner-card-40000001")], [], "no file of the failed card")
        self.assertEqual(self.enroll()["serial"], "40000001", "the rerun (after a reset) proceeds")

    def test_a_generation_that_stops_part_way_says_the_card_needs_a_reset(self):
        with self.assertRaisesRegex(ok.Refused, "the card stopped answering. Owner card 40000001 may now hold NEW keys: reset"):
            self.enroll(lie={"fail_generate": "dec"})
        self.assertEqual(self.card.generated, {"sig"})
        self.assertFalse(os.path.exists(oc.outputs(self.out, "40000001")["home"]))

    def test_the_card_gpg_reaches_is_read_from_scd_serialno(self):
        def answering(text):
            return lambda argv, **kw: subprocess.CompletedProcess(argv, 0, text, "")
        oc.card_seen_by_gpg("/h", "40000001", run=answering("S SERIALNO D2760001240103040006400000010000\nOK\n"))
        for text, reason in (("S SERIALNO D2760001240103040006400000090000\nOK\n", "scdaemon reaches card 40000009, not owner card 40000001"),
                             ("S SERIALNO 44454E4B30343034333830\nOK\n", "is not an OpenPGP card"),
                             ("ERR 100696144 No such device\n", "scdaemon reaches no card")):
            with self.subTest(reason=reason), self.assertRaisesRegex(ok.Refused, reason):
                oc.card_seen_by_gpg("/h", "40000001", run=answering(text))

    def test_the_aid_and_the_readers(self):
        self.assertEqual(oc.aid_serial("D2760001240103040006357186250000"), "35718625")
        for aid in ("44454E4B30343034333830", "D27600012402010400063571862500", ""):      # a Nitrokey HSM's (the bench), another applet, none
            with self.subTest(aid=aid), self.assertRaisesRegex(ok.Refused, "is not an OpenPGP card"):
                oc.aid_serial(aid)
        with self.assertRaisesRegex(ok.Refused, "is not a YubiKey's OpenPGP applet \\(manufacturer 000F"):
            oc.aid_serial("D2760001240103040" + "00F" + "357186250000")
        with self.assertRaisesRegex(ok.Refused, "does not carry a decimal \\(BCD\\) serial"):
            oc.aid_serial("D27600012401030400060218A5E10000")
        oc.only_this_reader(["Yubico YubiKey OTP+FIDO+CCID 00 00"], "40000001")
        for names in (["Yubico YubiKey OTP+FIDO+CCID 00 00", "Nitrokey Nitrokey HSM (DENK0404144) 01 00"], [],
                      ["Lenovo Integrated Smart Card Reader 00 00"]):
            with self.subTest(names=names), self.assertRaisesRegex(ok.Refused, "attach only owner card 40000001"):
                oc.only_this_reader(names, "40000001")

    def test_refused_before_the_card_changes(self):
        for kw, reason in (
                ({"serial": "35718625"}, "is a bench card"),
                ({"firmware": "5.2.1"}, "runs firmware 5.2.1; the owner keys need 5.2.3 or later"),
                ({"held": ("dec",)}, "already holds DEC: refused; replacing them takes --replace"),
                ({"held": ("sig",), "typed": "1"}, "the serial typed is not 40000001"),
                ({"uif": {"aut": 2}}, "has a fixed touch policy on AUT")):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ok.Refused, reason):
                    self.enroll(**kw)
                if hasattr(self, "card") and kw.get("serial") != "35718625":
                    self.assertEqual(self.card.generated, set(), "nothing was generated")
                    self.card = None
        pins = iter([oc.DEFAULT_ADMIN_PIN, USER])
        with self.assertRaisesRegex(ok.Refused, "a PIN typed is the factory default"):
            oc.enroll("owner-main", "40000001", "Owner", "o@example.invalid", self.out, self.recipient, ask_secret=lambda p: next(pins), card=None)

    def test_a_certificate_over_other_keys_is_refused(self):
        with self.assertRaisesRegex(ok.Refused, "the certificate's SIG key is not the one owner card 40000001 generated"):
            self.enroll(build_from="other")
        self.assertEqual(self.card.fingerprints, {}, "nothing was written to the card")
        self.assertFalse(os.path.exists(os.path.join(self.out, "owner-card-40000001.json")))

    def test_an_attestation_that_does_not_say_what_was_done_is_refused(self):
        for lie, says in (({"sig": {"2": make._der_integer(2)}}, "SIG attestation says not generated on the card"),
                          ({"dec": {"8": make._der_octets(b"\x00")}}, "DEC attestation says touch not fixed"),
                          ({"aut": {"7": make._der_integer(40000009)}}, "AUT attestation says another serial 40000009"),
                          ({"sig": {"4": make._der_octets(b"\x11" * 20)}}, "SIG attestation says another fingerprint"),
                          ({"dec": {"5": make._der_octets(b"\x00\x00\x00\x01")}}, "DEC attestation says another creation time")):
            with self.subTest(says=says):
                out = tempfile.mkdtemp(dir=self.out)
                with self.assertRaisesRegex(ok.Refused, says):
                    self.enroll(out=out, lie=lie)
                self.assertFalse(os.path.exists(os.path.join(out, "owner-card-40000001.json")), "no facts")

    def test_a_card_that_does_not_keep_what_is_written_or_attests_another_key(self):
        for kw, reason in (({"forgets": ("fingerprint",)}, "owner card 40000001 did not keep the SIG fingerprint"),
                           ({"forgets": ("uif",)}, "owner card 40000001 did not take a FIXED touch policy on SIG"),
                           ({"other_key": "aut"}, "AUT attestation says another key")):
            with self.subTest(reason=reason):
                out = tempfile.mkdtemp(dir=self.out)
                with self.assertRaisesRegex(ok.Refused, reason):
                    self.enroll(out=out, **kw)
                self.assertFalse(os.path.exists(os.path.join(out, "owner-card-40000001.json")))

    def test_one_card_in_both_roles_is_refused(self):
        a, b = os.path.join(self.out, "a"), os.path.join(self.out, "b")
        os.mkdir(a)
        os.mkdir(b)
        self.enroll("main", "owner-main", "40000001", out=a)
        self.enroll("main", "owner-backup", "40000001", out=b)
        with self.assertRaisesRegex(ok.Refused, "owner-main and owner-backup are one card \\(40000001\\)"):
            oc.cards(os.path.join(a, "owner-card-40000001.json"), os.path.join(b, "owner-card-40000001.json"), self.out)

    def test_the_certificate_is_read_from_its_own_packets(self):
        """certificate_keys' fingerprints are SHA-1 over each key packet: they are gpg's own."""
        home, fpr = self.homes["main"]
        keys = self.keys_of("main")
        listing = subprocess.run(["gpg", "--homedir", home, "--with-colons", "--list-keys"], check=True, capture_output=True, text=True).stdout
        fprs = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr")]
        self.assertEqual(sorted(k["fingerprint"] for k in keys.values()), sorted(fprs))
        self.assertEqual(keys["sig"]["fingerprint"], fpr)
        with self.assertRaisesRegex(ok.Refused, "subkeys are not exactly one ECDH encryption subkey and one EdDSA authentication subkey"):
            oc.certificate_keys(subprocess.run(["gpg", "--homedir", home, "--export", fpr], check=True, capture_output=True).stdout,
                                {fpr: "cs"})


class Dialogue(unittest.TestCase):
    """build_certificate's gpg dialogue against regalia-kms-24's bench transcripts (gpg 2.4.7, YubiKey 35718625,
    2026-10-05: ~/.cache/24/d306/gen2.log, add-dec.log, add-aut2.log): the questions gpg asked, in order, replayed;
    the answers must be the measured ones, the PIN on the command fd only (d9 on #140)."""

    TRANSCRIPTS = {  # question keys as gpg asked them, None where a status line came between
        "--full-generate-key": ["keygen.algo", "keygen.cardkey", "keygen.flags", "keygen.valid", "keygen.name", "keygen.email",
                                "keygen.comment", "passphrase.enter", None, "passphrase.enter", "KEY_CREATED P"],
        "addkey 2": ["keyedit.prompt", "keygen.algo", "keygen.cardkey", "keygen.flags", "keygen.valid", "passphrase.enter",
                     "KEY_CREATED S", "keyedit.prompt"],
        "addkey 3": ["keyedit.prompt", "keygen.algo", "keygen.cardkey", "keygen.flags", "keygen.flags", "keygen.valid",
                     "passphrase.enter", "KEY_CREATED S", "keyedit.prompt"]}

    def test_the_answers_and_the_pin(self):
        calls = []

        class FakeGpg:
            def __init__(self, argv, **kw):
                self.argv, self.answers = argv, []
                calls.append(self)
                which = "--full-generate-key" if "--full-generate-key" in argv else "addkey %d" % (1 + len(calls) - 1)
                lines = []
                for step in Dialogue.TRANSCRIPTS[which]:
                    if step is None:
                        lines.append("[GNUPG:] KEY_CONSIDERED %s 0\n" % ("9B" * 20))
                    elif step.startswith("KEY_CREATED"):
                        lines.append("[GNUPG:] %s %s\n" % (step, "9B" * 20))
                    else:
                        lines.append("[GNUPG:] GET_%s %s\n" % ("HIDDEN" if step == "passphrase.enter" else "LINE", step))
                self.stdin, self.stdout = self, iter(lines)

            def write(self, text):
                self.answers.append(text.rstrip("\n"))

            def flush(self):
                pass

            def wait(self):
                return 0
        primary = oc.build_certificate("/nonexistent", "Owner Main", "owner@example.invalid", USER, run=FakeGpg)
        self.assertEqual(primary, "9B" * 20)
        self.assertEqual([c.answers for c in calls], [
            ["14", "1", "Q", "0", "Owner Main", "owner@example.invalid", "", USER, USER],     # the PIN twice: the key, its revocation
            ["addkey", "14", "2", "Q", "0", USER, "save"],
            ["addkey", "14", "3", "S", "Q", "0", USER, "save"]])            # S toggled off leaves A (24: S then A left none)
        self.assertTrue(all(USER not in " ".join(c.argv) for c in calls), "the PIN is never in argv")

    def test_an_unexpected_question_is_refused(self):
        class Odd:
            def __init__(self, argv, **kw):
                self.stdin, self.stdout = self, iter(["[GNUPG:] GET_LINE keygen.size\n"])

            def write(self, text):
                raise AssertionError("nothing is answered")

            def flush(self):
                pass

            def wait(self):
                return 2
        with self.assertRaisesRegex(ok.Refused, "gpg asked keygen.size, which this dialogue does not answer"):
            oc.build_certificate("/nonexistent", "O", "o@example.invalid", USER, run=Odd)

    def test_a_question_asked_again_names_the_likely_cause(self):
        """24's bench run: with no key found on the card, gpg asked keygen.algo again."""
        class Again:
            def __init__(self, argv, **kw):
                self.stdin, self.stdout = self, iter(["[GNUPG:] GET_LINE keygen.algo\n", "[GNUPG:] GET_LINE keygen.algo\n"])

            def write(self, text):
                pass

            def flush(self):
                pass

            def wait(self):
                return 2
        with self.assertRaisesRegex(ok.Refused, "gpg asked keygen.algo again: .*scdaemon found no key on the card"):
            oc.build_certificate("/nonexistent", "O", "o@example.invalid", USER, run=Again)


if __name__ == "__main__":
    unittest.main()
