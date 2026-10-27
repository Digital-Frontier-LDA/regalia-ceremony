#!/usr/bin/env python3
"""The card-ceremony record (regalia-ceremony#111 step 2, ADR-0002 D30): its rules (card_record_check), its pinned-root
verifier (verify_card_record), and the vectors regalia-kms's verifier tests against (vectors/card-ceremony-record)."""
import os as _hermetic_os  # no real card, even run by hand (#104): no pcscd, the emulator stand-ins first
_hermetic_os.environ.setdefault("PCSCLITE_CSOCK_NAME", "/nonexistent/regalia-no-pcscd.comm")
_hermetic_os.environ["PATH"] = _hermetic_os.path.join(_hermetic_os.path.dirname(_hermetic_os.path.abspath(__file__)), "..", "bin") + _hermetic_os.pathsep + _hermetic_os.environ.get("PATH", "")
import copy
import importlib.machinery
import importlib.util
import hashlib
import json
import os
import re
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
        def tree(top):
            return sorted(os.path.relpath(os.path.join(dirpath, n), top) for dirpath, dirs, files in os.walk(top)
                          for n in files if "__pycache__" not in dirpath and n != "make.py" and not n.endswith(".pyc"))
        self.assertEqual(tree(d), tree(VECTORS))
        for name in tree(d):
            with open(os.path.join(d, name), "rb") as a, open(os.path.join(VECTORS, name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)

    def test_the_stand_in_attestations_chain_and_say_what_the_record_says(self):
        """regalia-kms#400's fixtures: each owner card's SIG, DEC and AUT leaf chains to the stand-in root through
        "Yubico OPGP Attestation B 1" and the card's CA; its extensions say generated on the card, this serial, touch
        fixed, and the record's fingerprint (SIG: the primary, DEC: the ownerauth subkey); its key is the record's (SIG:
        the owner key, AUT: the ssh_signers key); and the record names each leaf by the SHA-256 of its DER."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        where = os.path.join(VECTORS, "attestations")
        root = x509.load_pem_x509_certificate(open(os.path.join(where, "standin-yubico-root.pem"), "rb").read())
        b1 = x509.load_pem_x509_certificate(open(os.path.join(where, "standin-yubico-intermediates.pem"), "rb").read())
        b1.verify_directly_issued_by(root)
        record = json.load(open(os.path.join(VECTORS, "valid.json")))["record"]
        ext = lambda cert, n: cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.41482.5.%d" % n)).value.value
        raw = lambda key: key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        for owner, recipient, ssh in zip(record["owner_keys"], record["ownerauth_recipients"], record["ssh_signers"]):
            card = os.path.join(where, "owner-card-%s" % owner["serial"])
            ca = x509.load_der_x509_certificate(open(os.path.join(card, "att.der"), "rb").read())
            ca.verify_directly_issued_by(b1)
            for slot, fpr in (("sig", recipient["primary"]), ("dec", recipient["subkey"]), ("aut", None)):
                data = open(os.path.join(card, "%s.attest.der" % slot), "rb").read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), owner["attestation_sha256"][slot])
                leaf = x509.load_der_x509_certificate(data)
                leaf.verify_directly_issued_by(ca)
                self.assertEqual((ext(leaf, 2), ext(leaf, 7), ext(leaf, 8)), (b"\x02\x01\x01", b"\x02\x04" + int(owner["serial"]).to_bytes(4, "big"), b"\x04\x01\x02"))
                if fpr:
                    self.assertEqual(ext(leaf, 4), b"\x04\x14" + bytes.fromhex(fpr))
            self.assertEqual(raw(x509.load_der_x509_certificate(open(os.path.join(card, "sig.attest.der"), "rb").read()).public_key()), owner["key"])
            self.assertEqual(ok.ssh_ed25519_raw(ssh["key"], "ssh"), raw(x509.load_der_x509_certificate(open(os.path.join(card, "aut.attest.der"), "rb").read()).public_key()))

    def test_each_vector_verifies_or_is_refused_as_expect_json_says(self):
        with open(os.path.join(VECTORS, "expect.json")) as f:
            expect = json.load(f)
        with open(os.path.join(VECTORS, "root.hex")) as f:
            root = f.read().strip()
        self.assertEqual(sorted(expect), sorted(n for n in os.listdir(VECTORS) if n.endswith(".json") and n not in ("expect.json", "freshness-expect.json")))
        self.assertEqual(sorted(expect), ["bad-signature.json", "first-supersedes.json", "missing-owner-backup.json", "other-root.json",
                                          "release-is-owner.json", "sequence-2.json", "unknown-field.json", "valid.json", "wrong-domain.json"])
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
        for name in ("release-is-owner.json", "missing-owner-backup.json", "unknown-field.json", "other-root.json"):
            with open(os.path.join(VECTORS, name)) as f:
                document = json.load(f)
            key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(document["record"]["root_entry"]["key"]))
            key.verify(bytes.fromhex(document["signature"]), ok.RECORD_DOMAIN + ok.canonical(document["record"]))

    def test_the_signing_record_chains_the_two_card_records(self):
        """regalia-kms#403: sequence-2 supersedes valid.json by digest, and the signing record holds both, in order."""
        with open(os.path.join(VECTORS, "valid.json")) as f:
            first = json.load(f)["record"]
        with open(os.path.join(VECTORS, "sequence-2.json")) as f:
            second = json.load(f)["record"]
        self.assertEqual((first["sequence"], first["supersedes"]), (1, ""))
        self.assertEqual((second["sequence"], second["supersedes"]), (2, ok.card_record_digest(first)))
        self.assertEqual(ok.card_record_digest(first), __import__("hashlib").sha256(ok.canonical(first)).hexdigest())
        with open(os.path.join(VECTORS, "signing-record.jsonl")) as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual([(l["kind"], l["sequence"], l["digest"], l["key"]) for l in lines],
                         [("card-record", 1, ok.card_record_digest(first), first["root_entry"]["key"]),
                          ("card-record", 2, ok.card_record_digest(second), first["root_entry"]["key"])])

    def test_the_freshness_vectors_judge_as_freshness_expect_says(self):
        """The cases shared with regalia-kms's #403 consumer: each state directory copied, made 0700 with its marker
        0600, then read_signing_state and card_record_current; ok, or exactly the expected reason (contained)."""
        root = open(os.path.join(VECTORS, "root.hex")).read().strip()
        with open(os.path.join(VECTORS, "freshness-expect.json")) as f:
            expect = json.load(f)
        self.assertEqual(sorted(expect), sorted(os.listdir(os.path.join(VECTORS, "freshness"))))
        for case, want in sorted(expect.items()):
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, True)
            for name in os.listdir(os.path.join(VECTORS, "freshness", case)):
                shutil.copy(os.path.join(VECTORS, "freshness", case, name), d)
            os.chmod(d, 0o700)
            for name in (ok.SIGNING_STATE, ok.SIGNING_RECORD):
                if os.path.exists(os.path.join(d, name)):
                    os.chmod(os.path.join(d, name), 0o600)
            with open(os.path.join(VECTORS, want["record"])) as f:
                document = json.load(f)
            with self.subTest(case=case):
                if want["expect"] == "ok":
                    ok.card_record_current(document, root, ok.read_signing_state(d, root))
                else:
                    with self.assertRaises(ok.Refused) as caught:
                        ok.card_record_current(document, root, ok.read_signing_state(d, root))
                    self.assertIn(want["expect"], str(caught.exception))

    def test_the_log_is_read_whole_and_never_through_a_link(self):
        """d9 on #126: a log over the limit whose cut-off tail holds the newest line, and a log linked to an older copy,
        would each make an older card record read as the newest. Both are refused."""
        root = make.raw(make.ROOT)
        first, second = make.signed(make.valid_record()), make.signed(make.sequence_two())
        one = make.log_line(make.valid_record(), "2026-10-04T12:00:01Z")
        two = make.log_line(make.sequence_two(), "2026-10-05T12:00:01Z")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        marker = os.path.join(d, ok.SIGNING_STATE)
        with open(marker, "w") as f:
            json.dump({"schema": ok.SCHEMA_SIGNING_STATE, "root": root}, f)
        os.chmod(marker, 0o600)
        log = os.path.join(d, ok.SIGNING_RECORD)
        filler = json.dumps({"kind": "manifest", "pad": "x" * 1000})
        body = one + "\n" + "\n".join([filler] * (ok.MAX_SIGNING_RECORD // len(filler)))
        with open(log, "w") as f:
            f.write(body + "\n" + two + "\n")          # the newest line falls past the limit, on a line boundary
        os.chmod(log, 0o600)
        self.assertGreater(os.path.getsize(log), ok.MAX_SIGNING_RECORD)
        with self.assertRaisesRegex(ok.Refused, "is larger than 4194304 bytes: refused whole, never read in part"):
            ok.card_record_current(first, root, ok.read_signing_state(d, root))
        older = os.path.join(d, "older.jsonl")
        with open(older, "w") as f:
            f.write(one + "\n")
        os.chmod(older, 0o600)
        os.unlink(log)
        os.symlink(older, log)
        with self.assertRaisesRegex(ok.Refused, "signing-record.jsonl cannot be opened as a regular file"):
            ok.card_record_current(first, root, ok.read_signing_state(d, root))
        os.unlink(log)
        with open(log, "w") as f:
            f.write(one + "\n" + two + "\n")
        os.chmod(log, 0o644)
        with self.assertRaisesRegex(ok.Refused, "signing-record.jsonl must be a regular file of the directory's owner, mode 0600"):
            ok.read_signing_state(d, root)
        os.chmod(log, 0o600)
        self.assertEqual(ok.card_record_current(second, root, ok.read_signing_state(d, root))["sequence"], 2)

    def test_the_marker_must_be_the_owners_0600_regular_file(self):
        root = make.raw(make.ROOT)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        marker = os.path.join(d, ok.SIGNING_STATE)
        with open(marker, "w") as f:
            json.dump({"schema": ok.SCHEMA_SIGNING_STATE, "root": root}, f)
        with open(os.path.join(d, ok.SIGNING_RECORD), "w") as f:
            f.write("")
        os.chmod(marker, 0o644)
        with self.assertRaisesRegex(ok.Refused, "must be a regular file of the directory's owner, mode 0600"):
            ok.read_signing_state(d, root)
        os.unlink(marker)
        os.symlink(os.path.join(d, ok.SIGNING_RECORD), marker)
        with self.assertRaisesRegex(ok.Refused, "cannot be opened as a regular file"):
            ok.read_signing_state(d, root)
        os.unlink(marker)
        with open(marker, "w") as f:
            json.dump({"schema": ok.SCHEMA_SIGNING_STATE, "root": root, "extra": 1}, f)
        os.chmod(marker, 0o600)
        with self.assertRaisesRegex(ok.Refused, "has an unknown field: extra"):
            ok.read_signing_state(d, root)

    def test_only_the_newest_card_record_is_current(self):
        """regalia-kms#403: valid.json still verifies, but after sequence-2 it is superseded and refused as current."""
        root = open(os.path.join(VECTORS, "root.hex")).read().strip()
        docs = {n: json.load(open(os.path.join(VECTORS, n))) for n in ("valid.json", "sequence-2.json")}
        with open(os.path.join(VECTORS, "signing-record.jsonl")) as f:
            both = [json.loads(line) for line in f]
        self.assertEqual(ok.card_record_current(docs["sequence-2.json"], root, both)["sequence"], 2)
        self.assertEqual(ok.card_record_current(docs["valid.json"], root, both[:1])["sequence"], 1)
        # the K_A signer's lines (regalia-kms#464) between card records are objects with a kind, never counted (d9, 1e)
        anchors = [{"kind": k, "node_id": "a", "digest": "ab" * 32, "key": root, "at": "2026-10-05T00:00:00Z"}
                   for k in ("anchor-approval", "anchor-first", "anchor-increment")]
        self.assertEqual(ok.card_record_current(docs["sequence-2.json"], root, both[:1] + anchors + both[1:])["sequence"], 2)
        with self.assertRaisesRegex(ok.Refused, re.escape("not the newest the root signed (sequence 1 of 2)")):
            ok.card_record_current(docs["valid.json"], root, anchors + both[:1] + anchors + both[1:] + anchors)
        for document, lines, reason in (
                (docs["valid.json"], both, "this card record is not the newest the root signed (sequence 1 of 2)"),
                (docs["sequence-2.json"], both[1:], "the signing record's card-record lines are not 1..1 without a gap"),
                (docs["sequence-2.json"], [], "the signing record holds no card-record line"),
                (docs["sequence-2.json"], [both[0], dict(both[1], key="00" * 32)], "a card-record line names another root"),
                (docs["sequence-2.json"], [dict(both[0], digest="00" * 32), both[1]],
                 "this card record does not supersede the one before it in the signing record")):
            with self.subTest(reason=reason), self.assertRaisesRegex(ok.Refused, re.escape(reason)):
                ok.card_record_current(document, root, lines)

    def test_the_signed_bytes_are_regalia_kms_membership_canonical_form(self):
        """regalia-kms's verifier canonicalises with ensure_ascii=True; an ASCII record makes the same bytes."""
        with open(os.path.join(VECTORS, "valid.json")) as f:
            record = json.load(f)["record"]
        self.assertEqual(ok.canonical(record), json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


def marker(d, root):
    """The state directory's marker naming `root`, as the first card-record writer makes it."""
    path = os.path.join(d, ok.SIGNING_STATE)
    with open(path, "w") as f:
        json.dump({"schema": ok.SCHEMA_SIGNING_STATE, "root": root}, f)
    os.chmod(path, 0o600)


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
            (lambda r: r.update(sequence=0), "sequence is an integer from 1"),
            (lambda r: r.update(sequence=True), "sequence is an integer from 1"),
            (lambda r: r.update(supersedes="ab" * 32), "the first card record (sequence 1) supersedes nothing: supersedes is \"\""),
            (lambda r: r.update(sequence=2), "a card record after the first names the one it supersedes: the SHA-256 of its canonical "
                                             "bytes, 64 hex"),
            (lambda r: r.update(at="2026-10-04 12:00:00"), "at is YYYY-MM-DDTHH:MM:SSZ"),
            (lambda r: r.update(root_fingerprint="0" * 64), "root_fingerprint is not the SHA-256 of the root key"),
            (lambda r: r["owner_keys"].append(dict(r["owner_keys"][0])), "owner_keys holds exactly the two owner cards' SIG keys (D30.7)"),
            (lambda r: r["owner_keys"][0].update(serial="040000001"), "owner_keys[0].serial is a decimal YubiKey serial"),
            (lambda r: r["owner_keys"][0].update(alg="ecdsa-p256"), "owner_keys[0] is an Ed25519 key, 64 hex"),
            (lambda r: r["owner_keys"][1].update(attested=False), "owner_keys[1] is not attested: an owner key is generated on its card (D5)"),
            (lambda r: r["owner_keys"][1].update(role="owner-main"), "owner_keys has the roles owner-main and owner-backup, once each"),
            (lambda r: r["owner_keys"][1].update(serial="40000001"), "the two owner cards have distinct serials"),
            (lambda r: r["release_key"].update(fingerprint="c3" * 20), "release_key.fingerprint is 40 upper-case hex"),
            (lambda r: r["release_key"].update(attested=True), "the release key is imported, not attested (D29.2)"),
            (lambda r: r["release_key"].update(cards=["40000003"]), "release_key.cards are the two release cards' serials"),
            (lambda r: r["release_key"].update(cards=["40000001", "40000004"]),
             "a release card is also an owner card: the owner cards never hold the release key (D30.7)"),
            (lambda r: r["release_key"].update(key=r["owner_keys"][1]["key"]),
             "the release key is an owner key: the release cards hold no owner key (D30.7)"),
            (lambda r: r["ownerauth_recipients"].pop(), "ownerauth_recipients has one entry for each owner card"),
            (lambda r: r["ssh_signers"][1].update(serial="40000003"), "ssh_signers has one entry for each owner card"),
            (lambda r: r["ownerauth_recipients"][0].update(subkey=r["ownerauth_recipients"][0]["primary"]),
             "ownerauth_recipients[0] names a primary and a different encryption subkey, 40 upper-case hex"),
            (lambda r: r["ssh_signers"][0].update(key="ssh-rsa AAAA"), "ssh_signers[0].key is not an `ssh-ed25519 <base64>` line"),
            (lambda r: r["ssh_signers"][0].update(key=make.ssh_line(make.MAIN)),
             "a key is used twice among the root, the release key, the owner keys and the SSH keys"),
            (lambda r: r["release_key"].update(key=r["root_entry"]["key"]),
             "a key is used twice among the root, the release key, the owner keys and the SSH keys"),
            (lambda r: r["owner_keys"][0].pop("attestation_sha256"), "owner_keys[0] is missing: attestation_sha256"),
            (lambda r: r["owner_keys"][0]["attestation_sha256"].pop("dec"), "owner_keys[0].attestation_sha256 is missing: dec"),
            (lambda r: r["owner_keys"][0]["attestation_sha256"].pop("aut"), "owner_keys[0].attestation_sha256 is missing: aut"),
            (lambda r: r["owner_keys"][0]["attestation_sha256"].update(aut=r["owner_keys"][1]["attestation_sha256"]["sig"]), "an attestation certificate is named twice: each key has its own"),
            (lambda r: r["owner_keys"][1]["attestation_sha256"].update(sig="D1" * 32),
             "owner_keys[1].attestation_sha256 gives each certificate's SHA-256, 64 hex"),
            (lambda r: r["owner_keys"][1]["attestation_sha256"].update(sig=r["owner_keys"][0]["attestation_sha256"]["sig"]), "an attestation certificate is named twice: each key has its own"),
            (lambda r: r["ownerauth_recipients"][1].update(subkey=r["ownerauth_recipients"][0]["subkey"]),
             "an ownerauth fingerprint is used twice: each owner card has its own primary and its own decryption subkey, or one "
             "card would count twice in the proof (d9 on #121)"),
            (lambda r: r["ownerauth_recipients"][1].update(primary=r["ownerauth_recipients"][0]["primary"]),
             "an ownerauth fingerprint is used twice: each owner card has its own primary and its own decryption subkey, or one "
             "card would count twice in the proof (d9 on #121)"),
        ]
        for bench in ok.BENCH_YUBIKEYS:
            for where in ("owner", "release"):
                def change(r, bench=bench, where=where):
                    if where == "owner":
                        old = r["owner_keys"][1]["serial"]
                        r["owner_keys"][1]["serial"] = bench
                        for item in r["ownerauth_recipients"] + r["ssh_signers"]:
                            if item["serial"] == old:
                                item["serial"] = bench
                    else:
                        r["release_key"]["cards"][0] = bench
                cases.append((change, "a bench YubiKey is named (%s): the ceremony never uses a bench serial (D28.5, D30)" % bench))
        for change, reason in cases:
            with self.subTest(reason=reason):
                self.refused(change, reason)

    def test_a_value_of_the_wrong_type_anywhere_is_refused_never_a_crash(self):
        """coderabbitai on #121: every field of the valid record, swapped for a list, an object, a number, null or a
        boolean, gives Refused (not TypeError or another exception) from card_record_check."""
        def paths(value, at=()):
            yield at
            if isinstance(value, dict):
                for k, v in value.items():
                    yield from paths(v, at + (k,))
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    yield from paths(v, at + (i,))
        record = make.valid_record()
        count = 0
        for path in list(paths(record))[1:]:
            for wrong in ([["x"]], {"x": 1}, 7, None, True):
                broken = copy.deepcopy(record)
                parent = broken
                for step in path[:-1]:
                    parent = parent[step]
                if parent[path[-1]] == wrong or (isinstance(wrong, bool) and parent[path[-1]] is wrong):
                    continue
                parent[path[-1]] = copy.deepcopy(wrong)
                with self.subTest(path=path, wrong=wrong), self.assertRaises(ok.Refused):
                    ok.card_record_check(broken)
                count += 1
        self.assertGreater(count, 150)

    def test_the_signing_record_line(self):
        """append_card_record_line: one line per card record the root signs, in a 0700 directory of this user's, the
        file 0600, appended (never rewritten)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        first, second = make.valid_record(), make.sequence_two()
        with self.assertRaisesRegex(ok.Refused, "has no regalia-signing-state.json"):
            ok.append_card_record_line(d, first)                      # no marker: the root is unknown
        marker(d, first["root_entry"]["key"])
        ok.append_card_record_line(d, first)
        with open(os.path.join(d, ok.SIGNING_RECORD), "a") as f:           # the K_A signer's lines between them (#464)
            for kind in ("anchor-approval", "anchor-first", "anchor-increment"):
                f.write(json.dumps({"kind": kind, "node_id": "a", "at": "2026-10-05T00:00:00Z"}) + "\n")
        ok.append_card_record_line(d, second)
        with open(os.path.join(d, ok.SIGNING_RECORD)) as f:
            lines = [json.loads(line) for line in f if json.loads(line)["kind"] == "card-record"]
        self.assertEqual([(l["kind"], l["sequence"], l["digest"]) for l in lines],
                         [("card-record", 1, ok.card_record_digest(first)), ("card-record", 2, ok.card_record_digest(second))])
        self.assertEqual(oct(os.stat(os.path.join(d, ok.SIGNING_RECORD)).st_mode & 0o777), "0o600")
        os.chmod(d, 0o755)
        with self.assertRaisesRegex(ok.Refused, "must be a directory of this user's, mode 0700"):
            ok.append_card_record_line(d, first)

    def test_nothing_is_appended_that_the_reader_would_refuse(self):
        """CodeRabbit on #121: a log that is not the owner's 0600 file, and a record that does not continue the
        card-record lines (a duplicate, a gap, a fork, a second "first"), are refused before a byte is written."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        log = os.path.join(d, ok.SIGNING_RECORD)
        first, second = make.valid_record(), make.sequence_two()
        marker(d, first["root_entry"]["key"])
        with self.assertRaisesRegex(ok.Refused, "does not follow the signing record \\(sequence 1 superseding nothing expected, got 2"):
            ok.append_card_record_line(d, second)                     # a gap on an empty log
        ok.append_card_record_line(d, first)
        size = os.path.getsize(log)
        with self.assertRaisesRegex(ok.Refused, "sequence 2 superseding %s expected, got 1 superseding nothing" % ok.card_record_digest(first)):
            ok.append_card_record_line(d, first)                      # the same record again
        fork = dict(second, supersedes="0" * 64)
        with self.assertRaisesRegex(ok.Refused, "sequence 2 superseding %s expected, got 2 superseding 0{64}" % ok.card_record_digest(first)):
            ok.append_card_record_line(d, fork)                       # a record 2 that supersedes another record 1
        self.assertEqual(os.path.getsize(log), size, "nothing was appended")
        os.chmod(log, 0o644)
        with self.assertRaisesRegex(ok.Refused, "must be a regular file of the directory's owner, mode 0600: nothing was appended"):
            ok.append_card_record_line(d, second)
        self.assertEqual(os.path.getsize(log), size)
        os.chmod(log, 0o600)
        with open(log, "ab") as f:
            f.write(b'{"kind": "card-record", "sequ')                 # a torn last line: the reader refuses it, so does the writer
        with self.assertRaisesRegex(ok.Refused, "line 2 of the signing record is not JSON"):
            ok.append_card_record_line(d, second)

    def test_an_append_that_would_pass_the_size_limit_is_refused(self):
        """CodeRabbit on #121: a line that would take the log past MAX_SIGNING_RECORD is refused unwritten, since the
        reader refuses a larger log whole."""
        import unittest.mock
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        first, second = make.valid_record(), make.sequence_two()
        marker(d, first["root_entry"]["key"])
        ok.append_card_record_line(d, first)
        log = os.path.join(d, ok.SIGNING_RECORD)
        size = os.path.getsize(log)
        with unittest.mock.patch.object(ok, "MAX_SIGNING_RECORD", size + 10):
            with self.assertRaisesRegex(ok.Refused, "would pass %d bytes with this line: nothing was appended" % (size + 10)):
                ok.append_card_record_line(d, second)
        self.assertEqual(os.path.getsize(log), size)
        with unittest.mock.patch.object(ok, "MAX_SIGNING_RECORD", size * 3):
            ok.append_card_record_line(d, second)

    def test_only_a_valid_record_of_the_markers_root_is_appended(self):
        """CodeRabbit on #121: the appender judges the record by card_record_check, and binds it and every card-record
        line already logged to the root the directory's marker names."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        first = make.valid_record()
        marker(d, "11" * 32)
        with self.assertRaisesRegex(ok.Refused, "this card record is signed for another root than regalia-signing-state.json names"):
            ok.append_card_record_line(d, first)
        marker(d, first["root_entry"]["key"])
        broken = dict(first)
        del broken["ownerauth_recipients"]
        with self.assertRaises(ok.Refused):
            ok.card_record_check(broken)                              # the reader's own refusal...
        with self.assertRaisesRegex(ok.Refused, "ownerauth_recipients"):
            ok.append_card_record_line(d, broken)                     # ...is the appender's
        with open(os.path.join(d, ok.SIGNING_RECORD), "w") as f:
            f.write(json.dumps({"kind": "card-record", "sequence": 1, "digest": "0" * 64, "key": "11" * 32, "at": "2026-10-05T00:00:00Z"}) + "\n")
        os.chmod(os.path.join(d, ok.SIGNING_RECORD), 0o600)
        with self.assertRaisesRegex(ok.Refused, "the signing record holds a card-record line of another root: nothing was appended"):
            ok.append_card_record_line(d, dict(make.sequence_two()))

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
