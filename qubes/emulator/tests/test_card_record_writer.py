#!/usr/bin/env python3
"""offline-keys.py card-record (regalia-ceremony#111, regalia-kms#403): the writer of the root-signed card-ceremony
record. The first run creates the state directory's marker; each run continues the signing record's sequence and
supersedes chain; the record is released only after its line is logged, and a rerun after a crash finishes or
discards what the last run left. Every record it writes is judged by the consumer's own check, card_record_current."""
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
make = _load("card_vectors", os.path.join(HERE, "vectors", "card-ceremony-record", "make.py"))
HAVE_AGE = shutil.which("age") is not None and shutil.which("age-keygen") is not None


def fake_age(argv, input=None, capture_output=True):
    out = argv[argv.index("-o") + 1]
    with open(out, "wb") as f:
        f.write(b"age-encryption.org/v1\n" + bytes(b ^ 0x5A for b in input))
    return subprocess.CompletedProcess(argv, 0, b"", b"")


class Writer(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        env = {"CEREMONY_ALLOW_NONTMPFS": "1", "CEREMONY_ALLOW_SWAP": "1"}
        run = subprocess.run
        recipient = os.path.join(self.d, "bg.recipient")
        if HAVE_AGE:
            ident = os.path.join(self.d, "bg.key")
            if subprocess.run(["age-keygen", "-pq", "-o", ident], capture_output=True).returncode != 0:
                subprocess.run(["age-keygen", "-o", ident], check=True, capture_output=True)
                env.update(CEREMONY_ALLOW_CLASSICAL_BREAKGLASS="1", CEREMONY_SIMULATE="1")     # age before 1.3
            with open(recipient, "w") as f:
                f.write(subprocess.run(["age-keygen", "-y", ident], check=True, capture_output=True, text=True).stdout)
        else:
            run = fake_age
            with open(recipient, "w") as f:
                f.write("age1pq1" + "q" * 60 + "\n")
        patcher = unittest.mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gen, self.state, self.out = (os.path.join(self.d, n) for n in ("gen", "state", "out"))
        for d in (self.gen, self.state, self.out):
            os.mkdir(d, 0o700)
        ok.generate(2, 3, self.gen, recipient, run=run)
        self.sealed = os.path.join(self.gen, ok.FILES[0])
        with open(os.path.join(self.gen, ok.FILES[1])) as f:
            self.shares = [line for line in f.read().splitlines() if line.strip()]
        self.root = ok.root_entry_of(json.load(open(self.sealed)))
        record = make.valid_record()
        self.cards = os.path.join(self.d, "cards.json")
        with open(self.cards, "w") as f:
            json.dump({k: record[k] for k in ok.CARD_FIELDS}, f)
        self.imports = []
        for serial in record["release_key"]["cards"]:
            path = os.path.join(self.d, "release-import-%s.json" % serial)
            with open(path, "w") as f:
                json.dump({"schema": ok.SCHEMA_RELEASE_IMPORT, "serial": serial, "key": record["release_key"]["key"],
                           "fingerprint": record["release_key"]["fingerprint"], "touch": "fixed", "imported": True, "attested": False}, f)
            self.imports.append(path)

    def sign(self, first=False, confirm=None, imports=None, cards=None):
        """One run; the operator types `confirm`, or what the screen asked for (the sequence and the digest's first
        8 hex, read back from what was shown)."""
        shown = io.StringIO()
        with unittest.mock.patch("sys.stderr", shown):
            def typed(prompt):
                text = shown.getvalue()
                sequence = text.split("CARD RECORD ")[1].split(" ")[0]
                digest = text.split("digest ")[1].split("\n")[0]
                return confirm if confirm is not None else "%s %s" % (sequence, digest[:8])
            return ok.card_record(self.sealed, cards or self.cards, imports or self.imports, self.state, self.out,
                                  io.StringIO("\n".join(self.shares[:2]) + "\n"), first=first, ask=typed)

    def current(self, path):
        with open(path) as f:
            return ok.card_record_current(json.load(f), self.root, ok.read_signing_state(self.state, self.root))

    def test_the_first_run_makes_the_marker_and_record_one(self):
        record, path = self.sign(first=True)
        self.assertEqual((record["sequence"], record["supersedes"], os.path.basename(path)), (1, "", "card-record-1.record.json"))
        marker = os.path.join(self.state, ok.SIGNING_STATE)
        self.assertEqual(json.load(open(marker)), {"schema": ok.SCHEMA_SIGNING_STATE, "root": self.root})
        self.assertEqual(oct(os.stat(marker).st_mode & 0o777), "0o600")
        self.assertEqual(self.current(path)["sequence"], 1, "the consumer's own check accepts it")
        self.assertEqual(os.listdir(self.out), ["card-record-1.record.json"])

    def test_each_run_continues_the_log_and_supersedes_the_last(self):
        first, first_path = self.sign(first=True)
        second, second_path = self.sign()
        self.assertEqual((second["sequence"], second["supersedes"]), (2, ok.card_record_digest(first)))
        self.assertEqual(self.current(second_path)["sequence"], 2)
        with self.assertRaisesRegex(ok.Refused, "not the newest the root signed \\(sequence 1 of 2\\)"):
            self.current(first_path)

    def test_refusals_change_nothing(self):
        with self.assertRaisesRegex(ok.Refused, "has no regalia-signing-state.json"):
            self.sign()                                          # not first, and no marker
        self.sign(first=True)
        with self.assertRaisesRegex(ok.Refused, "--first-card-record is for a state directory with no signing record"):
            self.sign(first=True)
        before = (sorted(os.listdir(self.out)), open(os.path.join(self.state, ok.SIGNING_RECORD)).read())
        with self.assertRaisesRegex(ok.Refused, "the confirmation typed is not \"2 [0-9a-f]{8}\": nothing was signed"):
            self.sign(confirm="2 00000000")
        other = os.path.join(self.d, "other.json")
        with open(other, "w") as f:
            json.dump(dict(json.load(open(self.imports[0])), key="00" * 32), f)
        with self.assertRaisesRegex(ok.Refused, "the two release cards hold different keys"):
            self.sign(imports=[self.imports[0], other])
        bench = os.path.join(self.d, "bench.json")
        cards = json.load(open(self.cards))
        cards["owner_keys"][0]["serial"] = "35718625"
        for item in cards["ownerauth_recipients"] + cards["ssh_signers"]:
            if item["serial"] == "40000001":
                item["serial"] = "35718625"
        with open(bench, "w") as f:
            json.dump(cards, f)
        with self.assertRaisesRegex(ok.Refused, "a bench YubiKey is named"):
            self.sign(cards=bench)
        self.assertEqual((sorted(os.listdir(self.out)), open(os.path.join(self.state, ok.SIGNING_RECORD)).read()), before)

    def test_a_marker_without_a_card_record_line_is_not_this_writers(self):
        with open(os.path.join(self.state, ok.SIGNING_STATE), "w") as f:
            json.dump({"schema": ok.SCHEMA_SIGNING_STATE, "root": self.root}, f)
        os.chmod(os.path.join(self.state, ok.SIGNING_STATE), 0o600)
        with open(os.path.join(self.state, ok.SIGNING_RECORD), "w") as f:
            f.write(json.dumps({"kind": "manifest", "epoch": 1}) + "\n")
        os.chmod(os.path.join(self.state, ok.SIGNING_RECORD), 0o600)
        with self.assertRaisesRegex(ok.Refused, "has a marker but no card-record line"):
            self.sign()

    def test_a_crash_before_the_line_is_discarded_and_signed_again(self):
        """The first run crashes after the marker and the pending record, before its line: a rerun with the flag
        accepts this root's marker, discards the pending record (no line names it) and signs record 1 again."""
        with unittest.mock.patch.object(ok, "append_card_record_line", side_effect=OSError("power cut")):
            with self.assertRaisesRegex(OSError, "power cut"):
                self.sign(first=True)
        self.assertEqual(os.listdir(self.out), ["card-record-1.pending.json"])
        self.assertFalse(os.path.exists(os.path.join(self.state, ok.SIGNING_RECORD)))
        record, path = self.sign(first=True)
        self.assertEqual((record["sequence"], os.listdir(self.out)), (1, ["card-record-1.record.json"]))
        self.assertEqual(self.current(path)["sequence"], 1)

    def test_a_crash_after_the_line_is_released_by_the_rerun(self):
        """The line is logged, the release (rename) never happened: the rerun releases exactly that record, and signs
        nothing new."""
        self.sign(first=True)
        real_rename = os.rename
        with unittest.mock.patch.object(ok.os, "rename", side_effect=OSError("power cut")):
            with self.assertRaisesRegex(OSError, "power cut"):
                self.sign()
        self.assertIn("card-record-2.pending.json", os.listdir(self.out))
        lines = open(os.path.join(self.state, ok.SIGNING_RECORD)).read().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIs(ok.os.rename, real_rename)
        record, path = self.sign()
        self.assertEqual((record["sequence"], os.path.basename(path)), (2, "card-record-2.record.json"))
        self.assertEqual(len(open(os.path.join(self.state, ok.SIGNING_RECORD)).read().splitlines()), 2, "nothing new was logged")
        self.assertEqual(self.current(path)["sequence"], 2)


if __name__ == "__main__":
    unittest.main()
