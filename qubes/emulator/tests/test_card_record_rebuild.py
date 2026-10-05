#!/usr/bin/env python3
"""offline-keys.py card-record --rebuild-from-disc (regalia-kms#406, agreed with regalia-kms-1e and -d9): a lost
signing-state directory rebuilt from the disc's newest card record, bounded by the chain's card_record pin (after
genesis) or the sheet (before); the baseline line, its root-signed rebuild record, and N+1; and the readers' rules for
a rebuilt log, the pin deciding over any laptop log after genesis."""
import os as _hermetic_os  # no real card, even run by hand (#104): no pcscd, the emulator stand-ins first
_hermetic_os.environ.setdefault("PCSCLITE_CSOCK_NAME", "/nonexistent/regalia-no-pcscd.comm")
_hermetic_os.environ["PATH"] = _hermetic_os.path.join(_hermetic_os.path.dirname(_hermetic_os.path.abspath(__file__)), "..", "bin") + _hermetic_os.pathsep + _hermetic_os.environ.get("PATH", "")
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


ok = _load("offline_keys", os.path.join(HERE, "..", "..", "scripts", "offline-keys.py"))
writer = _load("writer_tests", os.path.join(HERE, "test_card_record_writer.py"))


class Rebuild(unittest.TestCase):
    """The writer's own fixture (an offline set, the cards' facts, two release imports), with records 1 and 2 signed in
    a state directory that is then lost."""
    sign, current = writer.Writer.sign, writer.Writer.current       # its helpers, not its tests

    def setUp(self):
        writer.Writer.setUp(self)
        self.sign(first=True)
        self.second, self.second_path = self.sign()
        self.lost = self.state
        self.state = os.path.join(self.d, "rebuilt")
        os.mkdir(self.state, 0o700)
        self.d2 = ok.card_record_digest(self.second)

    def rebuild(self, disc=None, pin=None, typed=()):
        answers = list(typed)

        def ask(prompt):
            if "sheet" in prompt:
                return answers.pop(0)
            text = shown.getvalue()
            sequence = text.split("superseded by ")[1].split(",")[0]
            digest = text.split("  digest ")[1].split("\n")[0]
            return answers.pop(0) if answers else "%s %s" % (sequence, digest[:8])
        shown = io.StringIO()
        with unittest.mock.patch("sys.stderr", shown):
            result = ok.card_record_rebuild(self.sealed, disc or self.second_path, self.state, self.out,
                                            io.StringIO("\n".join(self.shares[:2]) + "\n"), pin=pin, ask=ask)
        self.shown = shown.getvalue()
        return result

    def test_before_genesis_the_sheet_bounds_it(self):
        record, path, source = self.rebuild(typed=["2 " + self.d2[:16]])
        self.assertEqual((record["sequence"], record["supersedes"], source), (3, self.d2, "sheet"))
        self.assertIn("REBUILT, sheet-bounded", self.shown)
        self.assertEqual({k: record[k] for k in ok.CARD_FIELDS + ("release_key",)}, {k: self.second[k] for k in ok.CARD_FIELDS + ("release_key",)})
        lines = ok.read_signing_state(self.state, self.root)
        self.assertEqual([(l["kind"], l["sequence"]) for l in lines], [("card-record-baseline", 2), ("card-record", 3)])
        self.assertEqual(oct(os.stat(os.path.join(self.state, ok.REBUILD_RECORD)).st_mode & 0o777), "0o600")
        self.assertEqual(ok.card_record_current(json.load(open(path)), self.root, lines)["sequence"], 3)
        self.assertTrue(os.path.exists(os.path.join(self.out, "card-record-rebuild-2.record.json")), "a copy for the disc")
        # the writer goes on from the rebuilt log
        fourth, fourth_path = self.sign()
        self.assertEqual((fourth["sequence"], fourth["supersedes"]), (4, ok.card_record_digest(record)))
        self.assertEqual(self.current(fourth_path)["sequence"], 4)

    def test_after_genesis_the_chain_pin_bounds_it(self):
        record, _, source = self.rebuild(pin=(2, self.d2))
        self.assertEqual((record["sequence"], source), (3, "chain"))
        self.assertEqual(ok.read_signing_state(self.state, self.root)[0]["source"], "chain")

    def test_a_rollback_or_a_wrong_disc_copy_is_refused(self):
        first_path = os.path.join(self.out, "card-record-1.record.json")
        with self.assertRaisesRegex(ok.Refused, "the disc's card record 1 .* is not the one the chain pins \\(2, "):
            self.rebuild(disc=first_path, pin=(2, self.d2))
        with self.assertRaisesRegex(ok.Refused, "is not the sheet's newest: nothing was written"):
            self.rebuild(disc=first_path, typed=["2 " + self.d2[:16]])
        with self.assertRaisesRegex(ok.Refused, "is not the sheet's newest"):
            self.rebuild(typed=["2 " + "0" * 16])
        self.assertEqual(os.listdir(self.state), [], "nothing written into the state directory")

    def test_only_into_an_empty_state_directory(self):
        with self.assertRaisesRegex(ok.Refused, "a rebuild goes into an EMPTY state directory"):
            self.state, keep = self.lost, self.state
            self.rebuild(pin=(2, self.d2))

    def test_the_pin_beats_a_found_old_directory(self):
        """d9 on #406: after the rebuild, the old directory is found and signs its own 3; with the chain's pin (the
        rebuilt 3) every reader refuses the old one, whatever the old log says."""
        rebuilt, rebuilt_path, _ = self.rebuild(pin=(2, self.d2))
        pin = (3, ok.card_record_digest(rebuilt))
        self.state, self.out = self.lost, os.path.join(self.d, "old-out")
        os.mkdir(self.out, 0o700)
        old_third, old_path = self.sign()                     # the found directory signs "3" too, elsewhere
        self.assertNotEqual(ok.card_record_digest(old_third), pin[1])
        old_doc = json.load(open(old_path))
        with self.assertRaisesRegex(ok.Refused, "this card record is not the one the chain pins \\(sequence 3\\)"):
            ok.card_record_current(old_doc, self.root, ok.read_signing_state(self.lost, self.root), pin=pin)
        rebuilt_doc = json.load(open(rebuilt_path))
        self.assertEqual(ok.card_record_current(rebuilt_doc, self.root, ok.read_signing_state(os.path.join(self.d, "rebuilt"), self.root),
                                                pin=pin)["sequence"], 3)
        with self.assertRaisesRegex(ok.Refused, "the chain's pinned card record is not in this signing record"):
            ok.card_record_current(rebuilt_doc, self.root, ok.read_signing_state(self.lost, self.root), pin=pin)

    def test_the_rebuilt_log_rules(self):
        self.rebuild(pin=(2, self.d2))
        log = os.path.join(self.state, ok.SIGNING_RECORD)
        lines = [json.loads(l) for l in open(log)]
        base, third = lines
        cases = [([third, base], "a card-record-baseline line is not the first card line"),
                 ([base, base, third], "holds more than one card-record-baseline line"),
                 ([dict(base, source="memory"), third], "the card-record-baseline line is malformed"),
                 ([dict(base, key="00" * 32), third], "the card-record-baseline line names another root"),
                 ([base, dict(third, sequence=4)], "are not 3..3 without a gap after its baseline")]
        for given, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ok.Refused, reason):
                ok.card_lines_of(given, self.root)
        # M == N: only the baseline; record N is accepted, its supersedes unchecked, and that is said
        noted = []
        self.assertEqual(ok.card_record_current(json.load(open(self.second_path)), self.root, [base], note=noted.append)["sequence"], 2)
        self.assertEqual(noted, ["supersedes not checked: history before 2 rebuilt from chain"])
        # a baseline needs its root-signed rebuild record beside it, naming it
        rebuild_path = os.path.join(self.state, ok.REBUILD_RECORD)
        kept = open(rebuild_path, "rb").read()
        os.unlink(rebuild_path)
        with self.assertRaisesRegex(ok.Refused, "has a baseline but .* holds no card-record-rebuild.record.json"):
            ok.read_signing_state(self.state, self.root)
        with open(rebuild_path, "wb") as f:
            f.write(kept)
        os.chmod(rebuild_path, 0o600)
        with open(log, "w") as f:
            f.write(json.dumps(dict(base, sequence=1)) + "\n" + json.dumps(dict(third, sequence=2)) + "\n")
        with self.assertRaisesRegex(ok.Refused, "the rebuild record does not name the signing record's baseline"):
            ok.read_signing_state(self.state, self.root)
        document = json.loads(kept)
        document["signature"] = "00" * 64
        with open(rebuild_path, "w") as f:
            json.dump(document, f)
        with self.assertRaisesRegex(ok.Refused, "the rebuild record's signature does not verify"):
            ok.read_signing_state(self.state, self.root)

    def stub_tree(self, stdout, code=0):
        """A regalia-kms tree whose `manifest verify` prints `stdout` and exits `code` (the real verifier is regalia-kms's)."""
        tree = tempfile.mkdtemp(dir=self.d)
        os.makedirs(os.path.join(tree, "deploy", "baremetal"))
        for name in ("deploy/__init__.py", "deploy/baremetal/__init__.py"):
            open(os.path.join(tree, name), "w").close()
        with open(os.path.join(tree, "deploy", "baremetal", "manifest.py"), "w") as f:
            f.write("import sys\nassert sys.argv[1:3] == ['verify', '--chain']\nsys.stdout.write(%r)\nsys.exit(%d)\n" % (stdout, code))
        return tree, ok.tree_digest(tree)

    def test_the_pin_is_computed_from_the_chain_never_typed(self):
        """d9 on #406: the pin is the verified chain's, from regalia-kms's verifier run from a digest-checked tree."""
        chain = os.path.join(self.d, "chain.json")
        open(chain, "w").write("[]")
        tree, digest = self.stub_tree("chain verified: 3 envelopes, epoch 3, digest x\nCARD-RECORD-PIN 2 %s\n" % self.d2)
        self.assertEqual(ok.chain_pin(chain, self.root, tree, digest), (2, self.d2))
        for out, code, reason in (("chain verified: 1 envelopes\n", 0, "carries no card_record pin"),
                                  ("CONFLICT\n", 1, "regalia-kms did not verify the chain under this root"),
                                  ("CARD-RECORD-PIN 2 %s\nmore\n" % self.d2, 0, "carries no card_record pin")):
            tree, digest = self.stub_tree(out, code)
            with self.subTest(reason=reason), self.assertRaisesRegex(ok.Refused, reason):
                ok.chain_pin(chain, self.root, tree, digest)
        tree, digest = self.stub_tree("CARD-RECORD-PIN 2 %s\n" % self.d2)
        with self.assertRaisesRegex(ok.Refused, "the regalia-kms tree's digest is not --tool-digest"):
            ok.chain_pin(chain, self.root, tree, "0" * 64)

    def test_a_rerun_after_a_crash_releases_or_names_what_was_left(self):
        """d9 on #406: a crash after N+1's line is finished by the same command; a pending N+1 left in OUT before
        anything was written is named, not met with a bare File exists."""
        with unittest.mock.patch.object(ok.os, "rename", side_effect=OSError("power cut")):
            with self.assertRaises(OSError):
                self.rebuild(pin=(2, self.d2))
        record, path, source = self.rebuild(pin=(2, self.d2), typed=["unused"])
        self.assertEqual((record["sequence"], os.path.basename(path), source), (3, "card-record-3.record.json", "chain"))
        self.assertEqual(self.current(path)["sequence"], 3)
        shutil.rmtree(self.state)
        os.mkdir(self.state, 0o700)
        os.unlink(path)
        open(os.path.join(self.out, "card-record-3.pending.json"), "w").write("{")
        with self.assertRaisesRegex(ok.Refused, "a crashed rebuild left card-record-3.pending.json in OUT: remove it by name and rebuild"):
            self.rebuild(pin=(2, self.d2))

    def test_the_pin_as_regalia_manifest_prints_it(self):
        digest = "ab" * 32
        self.assertEqual(ok.parse_pin("CARD-RECORD-PIN 7 " + digest), (7, digest))
        self.assertEqual(ok.parse_pin("7:" + digest), (7, digest))
        for bad in ("", "CARD-RECORD-PIN", "CARD-RECORD-PIN 0 " + digest, "7 " + digest[:-2], "x:" + digest):
            with self.subTest(pin=bad), self.assertRaisesRegex(ok.Refused, "the pin is 'CARD-RECORD-PIN"):
                ok.parse_pin(bad)


if __name__ == "__main__":
    unittest.main()
