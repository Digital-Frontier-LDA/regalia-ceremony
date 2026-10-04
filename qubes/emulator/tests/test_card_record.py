#!/usr/bin/env python3
"""The card-ceremony record (regalia-ceremony#111 step 2, ADR-0002 D30): its rules (card_record_check), its pinned-root
verifier (verify_card_record), and the vectors regalia-kms's verifier tests against (vectors/card-ceremony-record)."""
import os as _hermetic_os  # no real card, even run by hand (#104): no pcscd, the emulator stand-ins first
_hermetic_os.environ.setdefault("PCSCLITE_CSOCK_NAME", "/nonexistent/regalia-no-pcscd.comm")
import copy
import importlib.machinery
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors", "card-ceremony-record")


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


ok = _load("offline_keys", os.path.join(HERE, "..", "..", "scripts", "offline-keys.py"))
make = _load("card_vectors", os.path.join(VECTORS, "make.py"))


class Vectors(unittest.TestCase):
    def test_the_committed_vectors_are_exactly_what_make_writes(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        make.write(d)
        made = sorted(os.listdir(d))
        committed = sorted(n for n in os.listdir(VECTORS) if os.path.isfile(os.path.join(VECTORS, n)) and n != "make.py")
        self.assertEqual(made, committed)
        for name in made:
            with open(os.path.join(d, name), "rb") as a, open(os.path.join(VECTORS, name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)

    def test_each_vector_verifies_or_is_refused_as_expect_json_says(self):
        with open(os.path.join(VECTORS, "expect.json")) as f:
            expect = json.load(f)
        with open(os.path.join(VECTORS, "root.hex")) as f:
            root = f.read().strip()
        self.assertEqual(sorted(expect), sorted(n for n in os.listdir(VECTORS) if n.endswith(".json") and n != "expect.json"))
        self.assertEqual(sorted(expect), ["bad-signature.json", "missing-dev-backup.json", "other-root.json", "release-is-owner.json",
                                          "unknown-field.json", "valid.json", "wrong-domain.json"])
        for name, expected in sorted(expect.items()):
            with self.subTest(vector=name), open(os.path.join(VECTORS, name)) as f:
                document = json.load(f)
                if expected == "ok":
                    self.assertEqual(ok.verify_card_record(document, root)["schema"], ok.SCHEMA_CARDS)
                else:
                    with self.assertRaises(ok.Refused) as caught:
                        ok.verify_card_record(document, root)
                    self.assertEqual(str(caught.exception), expected)

    def test_the_content_vectors_are_signed_correctly(self):
        """So they test the content rules, not the signature: each verifies under its root's key."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        for name in ("release-is-owner.json", "missing-dev-backup.json", "unknown-field.json", "other-root.json"):
            with open(os.path.join(VECTORS, name)) as f:
                document = json.load(f)
            key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(document["record"]["root_entry"]["key"]))
            key.verify(bytes.fromhex(document["signature"]), ok.RECORD_DOMAIN + ok.canonical(document["record"]))

    def test_the_signed_bytes_are_regalia_kms_membership_canonical_form(self):
        """regalia-kms's verifier canonicalises with ensure_ascii=True; an ASCII record makes the same bytes."""
        with open(os.path.join(VECTORS, "valid.json")) as f:
            record = json.load(f)["record"]
        self.assertEqual(ok.canonical(record), json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


class Rules(unittest.TestCase):
    """Every rule of card_record_check, each by its own refusal message."""

    def refused(self, change, reason):
        record = make.valid_record()
        change(record)
        with self.assertRaises(ok.Refused) as caught:
            ok.card_record_check(record)
        self.assertEqual(str(caught.exception), reason)

    def test_the_valid_record_passes(self):
        record = make.valid_record()
        self.assertIs(ok.card_record_check(copy.deepcopy(record)).__class__, dict)

    def test_refusals(self):
        cases = [
            (lambda r: r.pop("ssh_signers"), "the record is missing: ssh_signers"),
            (lambda r: r.update(extra=1), "the record has an unknown field: extra"),
            (lambda r: r.update(tool="café"), "the record.tool is not ASCII"),
            (lambda r: r.update(schema="regalia.card-ceremony-record/v0"),
             "schema must be regalia.card-ceremony-record/v1, event card-ceremony"),
            (lambda r: r.update(session="0" * 31), "session is 32 hex"),
            (lambda r: r.update(at="2026-10-04 12:00:00"), "at is YYYY-MM-DDTHH:MM:SSZ"),
            (lambda r: r.update(root_fingerprint="0" * 64), "root_fingerprint is not the SHA-256 of the root key"),
            (lambda r: r["owner_keys"].append(dict(r["owner_keys"][0])), "owner_keys holds exactly the two developer cards' SIG keys (D30.3)"),
            (lambda r: r["owner_keys"][0].update(serial="040000001"), "owner_keys[0].serial is a decimal YubiKey serial"),
            (lambda r: r["owner_keys"][0].update(alg="ecdsa-p256"), "owner_keys[0] is an Ed25519 key, 64 hex"),
            (lambda r: r["owner_keys"][1].update(attested=False), "owner_keys[1] is not attested: an owner key is generated on its card (D5)"),
            (lambda r: r["owner_keys"][1].update(role="dev-main"), "owner_keys has the roles dev-main and dev-backup, once each"),
            (lambda r: r["owner_keys"][1].update(serial="40000001"), "the two developer cards have distinct serials"),
            (lambda r: r["release_key"].update(fingerprint="c3" * 20), "release_key.fingerprint is 40 upper-case hex"),
            (lambda r: r["release_key"].update(attested=True), "the release key is imported, not attested (D29.2)"),
            (lambda r: r["release_key"].update(cards=["40000003"]), "release_key.cards are the two release cards' serials"),
            (lambda r: r["release_key"].update(cards=["40000001", "40000004"]),
             "a release card is also a developer card: the developer cards never hold the release key (D30.3)"),
            (lambda r: r["release_key"].update(key=r["owner_keys"][1]["key"]),
             "the release key is an owner key: the release cards hold no owner key (D30.3)"),
            (lambda r: r["ownerauth_recipients"].pop(), "ownerauth_recipients has one entry for each developer card"),
            (lambda r: r["ssh_signers"][1].update(serial="40000003"), "ssh_signers has one entry for each developer card"),
            (lambda r: r["ownerauth_recipients"][0].update(subkey=r["ownerauth_recipients"][0]["primary"]),
             "ownerauth_recipients[0] names a primary and a different encryption subkey, 40 upper-case hex"),
            (lambda r: r["ssh_signers"][0].update(key="ssh-rsa AAAA"), "ssh_signers[0].key is not an `ssh-ed25519 <base64>` line"),
            (lambda r: r["ssh_signers"][0].update(key=make.ssh_line(make.MAIN)),
             "a key is used twice among the root, the release key, the owner keys and the SSH keys"),
            (lambda r: r["release_key"].update(key=r["root_entry"]["key"]),
             "a key is used twice among the root, the release key, the owner keys and the SSH keys"),
        ]
        for change, reason in cases:
            with self.subTest(reason=reason):
                self.refused(change, reason)

    def test_the_verifier_takes_exactly_a_record_and_a_hex_signature(self):
        with open(os.path.join(VECTORS, "valid.json")) as f:
            document = json.load(f)
        root = make.raw(make.ROOT)
        for broken, reason in ((dict(document, extra=1), "not a record: exactly record and signature"),
                               (dict(document, signature=document["signature"].upper()), "the signature is 128 hex"),
                               (dict(document, signature={"sig": document["signature"]}), "the signature is 128 hex")):
            with self.subTest(reason=reason), self.assertRaises(ok.Refused) as caught:
                ok.verify_card_record(broken, root)
            self.assertEqual(str(caught.exception), reason)


if __name__ == "__main__":
    unittest.main()
