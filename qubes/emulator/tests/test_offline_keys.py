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
import re
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


class Case(unittest.TestCase):
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

    def forms(self, lines, partial=False):
        import io
        return ok.verify_forms(self.path("offline-keys.sealed.json"), self.path("offline-shares.txt"), io.StringIO("\n".join(lines) + "\n"), partial)


class Generate(Case):
    def test_four_keys_sealed_split_backed_up_and_recorded(self):
        record = self.generate()
        for name in ok.FILES:
            self.assertTrue(os.path.exists(self.path(name)), name)
        self.assertEqual(oct(os.stat(self.path("offline-shares.txt")).st_mode & 0o777), "0o600")
        self.assertEqual(sorted(record["publics"]), ["pcr-initrd", "pcr-system", "root", "secure-boot"])
        self.assertEqual({p["alg"] for n, p in record["publics"].items() if n != "root"}, {"rsa-2048"})
        self.assertEqual(record["root_entry"]["alg"], "ed25519")
        self.assertEqual(record["root_fingerprint"], hashlib.sha256(bytes.fromhex(record["root_entry"]["key"])).hexdigest(),
                         "the fingerprint regalia-kms#360's --genesis and enrol check take")
        self.assertEqual(len(record["root_entry"]["key"]), 64)
        with open(self.path("offline-keys.sealed.json"), "rb") as f:
            sealed = json.loads(f.read())
        with open(self.path("offline-keys.sealed.json"), "rb") as f:
            self.assertEqual(record["files"]["offline-keys.sealed.json"], hashlib.sha256(f.read()).hexdigest())
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

    def test_every_form_typed_back_is_checked_and_then_the_shares_are_shredded(self):
        """regalia-kms-d9 on #114: the copies the holders keep are proven while the shares still exist."""
        self.generate(k=2, n=3)
        shares = self.shares()
        checked, missing = self.forms(["  " + s.upper().replace(" ", "   ") + " " for s in reversed(shares)])
        self.assertEqual((checked, missing), ([0, 1, 2], []), "case and spacing as a person types them")
        self.assertFalse(os.path.exists(self.path("offline-shares.txt")), "the shares file is shredded once every form is proven")

    def test_a_form_copied_wrong_or_of_another_set_or_missing_is_refused(self):
        from shamir_mnemonic import generate_mnemonics
        self.generate(k=2, n=3)
        shares = self.shares()
        words = shares[1].split()
        slipped = " ".join(words[:5] + [words[6]] + words[6:])                  # a word copied twice, one dropped
        with self.assertRaisesRegex(ok.Refused, "not a valid SLIP-39 share"):
            self.forms([shares[0], slipped, shares[2]])
        foreign = generate_mnemonics(1, [(2, 3)], b"\x05" * 32)[0][0]
        with self.assertRaisesRegex(ok.Refused, "belongs to another set"):
            self.forms([shares[0], foreign, shares[2]])
        with self.assertRaisesRegex(ok.Refused, "forms 3 were not typed back"):
            self.forms(shares[:2])
        with self.assertRaisesRegex(ok.Refused, "typed back twice"):
            self.forms([shares[0], shares[0], shares[1]])
        self.assertTrue(os.path.exists(self.path("offline-shares.txt")), "nothing is shredded after a refusal")
        # a VALID share of another split that happens to carry this set's 15-bit identifier: its checksum and its
        # identifier pass; only the comparison with the share actually made catches it
        from shamir_mnemonic import shamir
        with open(self.path("offline-keys.record.json")) as f:
            record = json.load(f)["record"]
        ems = shamir.EncryptedMasterSecret.from_master_secret(b"\x05" * 32, b"", record["slip39_identifier"], True, 1)
        twin = shamir.split_ems(1, [(2, 3)], ems)[0][1].mnemonic()
        with self.assertRaisesRegex(ok.Refused, "form 2 typed back is not the share made for it"):
            self.forms([shares[0], twin, shares[2]])
        checked, missing = self.forms(shares[:2], partial=True)
        self.assertEqual((checked, missing), ([0, 1], [2]))

    def test_each_key_signs_for_the_public_key_published(self):
        """regalia-kms-d9 on #114: an operation proof per key, before sealing."""
        record = self.generate(k=2, n=3)
        self.assertEqual(record["operation_proof"], {n: "verified" for n, _ in ok.KEYS})
        with open(self.path("offline-keys.sealed.json"), "rb") as f:
            self.assertEqual(json.loads(f.read())["slip39_identifier"], record["slip39_identifier"])
        real = ok.publics
        def swapped(keys):
            out = real(keys)
            out["pcr-system"] = out["pcr-initrd"]
            return out
        shutil.rmtree(self.out)
        os.mkdir(self.out)
        with unittest.mock.patch.object(ok, "publics", swapped):
            with self.assertRaisesRegex(ok.Refused, "key pcr-system does not sign for the public key that would be published"):
                self.generate(k=2, n=3)
        self.assertEqual(os.listdir(self.out), [])

    def test_a_share_typed_at_a_terminal_is_not_echoed(self):
        """The end-to-end run on #111 found the shares echoed: read from a terminal, echo is off for the read."""
        import pty
        import select
        import termios
        import threading
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        stream = os.fdopen(slave, "r")
        self.addCleanup(stream.close)
        secret = "furl lily academic agency angry elder"

        def type_it():
            import time
            time.sleep(0.3)
            os.write(master, (secret + "\n").encode() + b"\x04")
        threading.Thread(target=type_it, daemon=True).start()
        got = ok.read_hidden(stream, "shares")
        self.assertEqual(got.strip(), secret)
        echoed = b""
        while select.select([master], [], [], 0.2)[0]:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            echoed += chunk
        self.assertNotIn(b"furl", echoed, "the share was echoed to the terminal")
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO, "echo is restored after the read")

    def test_the_cli_takes_no_secret_on_argv(self):
        with open(SCRIPT) as f:
            text = f.read()
        for flag in ("--master", "--share", "--mnemonic", "--passphrase", "--secret", "--private-key"):
            self.assertNotIn('"%s"' % flag, text, "a secret-bearing option on the command line")


class Sign(Case):
    """A signing session: exactly k shares of THIS set on standard input; the keys handed only to regalia-kms's
    `manifest sign` (the root) or `uki.py sign` (the three boot keys), each as a sealed memfd; the session recorded first
    and signed by the root. The two tools are stood in for by a tree of their own that checks what it was given."""

    FAKE_TOOL = r'''
import fcntl, hashlib, os, sys
args = sys.argv[1:]
assert args[0] == "sign", args
def val(flag):
    return args[args.index(flag) + 1]
assert os.environ.get("PATH") == "/usr/bin:/bin" and set(os.environ) <= {"PATH", "LC_ALL", "LC_CTYPE"}, sorted(os.environ)
lines = ["session " + val("--offline-session")]
for flag in [a for a in args if a.endswith("key-fd")]:
    fd = int(val(flag))
    assert os.readlink("/proc/self/fd/%d" % fd).startswith("/memfd:"), "not a memfd"
    assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE, "not sealed"
    data = b""
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        data += chunk
    assert data.startswith(b"-----BEGIN PRIVATE KEY-----"), data[:30]
    lines.append("%s %s" % (flag, hashlib.sha256(data).hexdigest()))
    if "leak" in args:
        with open(os.path.join(os.path.dirname(val("--out")), "kept.pem"), "wb") as f:
            f.write(data)
    if "leak-elsewhere" in args:
        with open(os.path.join(val("--elsewhere"), "k"), "wb") as f:
            f.write(data)
    if "touch-tree" in args:
        with open(os.path.join("deploy", "baremetal", "kept.py"), "w") as f:
            f.write("x = 1\n")
print("tool stdout")
print("tool stderr", file=sys.stderr)
if "exit3" in args:
    sys.exit(3)
if "nooutput" not in args:
    with open(val("--out"), "w") as f:
        f.write("\n".join(lines) + "\n")
'''

    def setUp(self):
        super().setUp()
        self.record = self.generate(k=3, n=5)
        self.all = self.shares()
        self.sealed = self.path("offline-keys.sealed.json")
        self.session_dir = os.path.join(self.d, "session")
        os.mkdir(self.session_dir)
        self.tree = os.path.join(self.d, "regalia-kms")
        os.makedirs(os.path.join(self.tree, "deploy", "baremetal"))
        open(os.path.join(self.tree, "deploy", "__init__.py"), "w").close()
        open(os.path.join(self.tree, "deploy", "baremetal", "__init__.py"), "w").close()
        for module in ("manifest", "uki"):
            with open(os.path.join(self.tree, "deploy", "baremetal", module + ".py"), "w") as f:
                f.write(self.FAKE_TOOL)
        self.digest = ok.tree_digest(self.tree)
        import sys
        patcher = unittest.mock.patch.object(ok, "PYTHON", sys.executable)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.elsewhere = os.path.join(self.d, "elsewhere")          # stands in for /tmp and /dev/shm
        os.mkdir(self.elsewhere)
        patcher = unittest.mock.patch.object(ok, "SCAN_DIRS", (self.elsewhere,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def command(self, tool, *extra, out=None):
        import sys
        out = out or os.path.join(self.session_dir, "%s.out" % tool)
        if tool == "manifest":
            flags = ["--signer", "root", "--key-fd", "{keyfd:root}"]
        else:
            flags = ["--initrd-key-fd", "{keyfd:pcr-initrd}", "--system-key-fd", "{keyfd:pcr-system}", "--secure-boot-key-fd", "{keyfd:secure-boot}"]
        return [sys.executable, "-Es", "-m", "deploy.baremetal." + tool, "sign"] + flags + ["--offline-session", "{session}", "--out", out] + list(extra)

    def sign(self, command, shares=None, outputs=None, digest=None, who="Owner"):
        import io
        self.sinks = {"stdout": io.BytesIO(), "stderr": io.BytesIO()}
        outs = outputs if outputs is not None else [command[command.index("--out") + 1]]
        return ok.sign(self.sealed, who, self.session_dir, io.StringIO("\n".join(shares or self.all[1:4]) + "\n"), command,
                       self.tree, digest or self.digest, outs, sinks=self.sinks)

    def pem(self, name):
        from shamir_mnemonic import combine_mnemonics
        from cryptography.hazmat.primitives import serialization
        with open(self.sealed, "rb") as f:
            bundle = ok.unseal(combine_mnemonics(self.all[:3]), json.loads(f.read()))
        key = serialization.load_der_private_key(base64.b64decode(bundle["keys"][name]["pkcs8"]), None)
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def records(self):
        found = sorted(n for n in os.listdir(self.session_dir) if n.startswith("session-"))
        out = []
        for name in found:
            with open(os.path.join(self.session_dir, name)) as f:
                out.append(ok.verify_record(json.load(f)))
        return out

    def test_the_root_goes_only_to_manifest_sign_as_a_sealed_memfd_and_the_session_is_recorded(self):
        session, record_path = self.sign(self.command("manifest"))
        with open(os.path.join(self.session_dir, "manifest.out")) as f:
            lines = f.read().split()
        self.assertEqual(lines[:2], ["session", session["session"]], "the tool was told the session's id")
        self.assertEqual(lines[2:], ["--key-fd", hashlib.sha256(self.pem("root")).hexdigest()], "it read the root, PEM, to EOF")
        [verified] = self.records()
        self.assertEqual((verified["event"], verified["tool"], verified["keys"], verified["who"], verified["exit"], verified["share_indices"]),
                         ("sign", "manifest", ["root"], "Owner", 0, [2, 3, 4]))
        self.assertEqual(verified["root_entry"], self.record["root_entry"])
        self.assertEqual(verified["tool_digest"], self.digest)
        self.assertEqual(verified["stdout_sha256"], hashlib.sha256(b"tool stdout\n").hexdigest())
        self.assertEqual(self.sinks["stdout"].getvalue(), b"tool stdout\n", "the operator sees the tool's output")
        with open(os.path.join(self.session_dir, "manifest.out"), "rb") as f:
            self.assertEqual(list(verified["outputs"].values()), [hashlib.sha256(f.read()).hexdigest()])
        self.assertEqual(verified["key_material_found"], [])

    def test_the_three_boot_keys_go_together_to_uki_sign(self):
        self.sign(self.command("uki"))
        with open(os.path.join(self.session_dir, "uki.out")) as f:
            lines = f.read().splitlines()
        self.assertEqual(lines[1:], ["--initrd-key-fd %s" % hashlib.sha256(self.pem("pcr-initrd")).hexdigest(),
                                     "--system-key-fd %s" % hashlib.sha256(self.pem("pcr-system")).hexdigest(),
                                     "--secure-boot-key-fd %s" % hashlib.sha256(self.pem("secure-boot")).hexdigest()])
        self.assertEqual(self.records()[0]["keys"], ["pcr-initrd", "pcr-system", "secure-boot"])

    def test_any_other_command_or_entitlement_is_refused_before_a_share_is_read(self):
        import sys
        manifest = self.command("manifest")
        cases = [
            ("--exec runs only", ["/bin/sh", "-c", "cat /proc/self/fd/3"]),
            ("--exec runs only", [sys.executable, "-c", "pass", "-m", "deploy.baremetal.manifest", "sign"]),
            ("must carry --offline-session", [a for a in manifest if a not in ("--offline-session", "{session}")]),
            ("must carry --signer root", [("pcr-system" if a == "root" else a) for a in manifest]),
            ("not entitled to: {keyfd:root}", self.command("uki", "--extra", "{keyfd:root}")),
            ("not entitled to: {keyfd:pcr-initrd}", manifest + ["{keyfd:pcr-initrd}"]),
        ]
        for reason, command in cases:
            with self.assertRaisesRegex(ok.Refused, re.escape(reason)):
                self.sign(command, shares=["not a share"], outputs=[])
        with self.assertRaisesRegex(ok.Refused, "not the tree the image's evidence names"):
            self.sign(manifest, shares=["not a share"], digest="00" * 32)
        open(os.path.join(self.session_dir, "manifest.out"), "w").close()
        with self.assertRaisesRegex(ok.Refused, "already exists"):
            self.sign(manifest, shares=["not a share"])
        self.assertEqual(self.records(), [])

    def test_the_genesis_form_of_manifest_sign_is_allowed(self):
        """regalia-kms#360: `manifest sign --genesis` (epoch 1, no chain) takes the root the same way."""
        import sys
        genesis = [sys.executable, "-Es", "-m", "deploy.baremetal.manifest", "sign", "--genesis", "--root-key", "ab" * 32,
                   "--proposal", "p.json", "--signer", "root", "--key-fd", "{keyfd:root}", "--offline-session", "{session}",
                   "--state-dir", "s", "--out", "e1.json", "--chain-out", "c.json"]
        self.assertEqual(ok.check_command(genesis), ("manifest", ("root",)))

    def test_the_tree_digest_covers_every_file_under_deploy_and_refuses_links(self):
        with open(os.path.join(self.tree, "deploy", "baremetal", "regalia.service"), "w") as f:
            f.write("[Service]\n")
        self.assertNotEqual(ok.tree_digest(self.tree), self.digest, "a unit file is part of the pinned tree")
        os.symlink("/etc/passwd", os.path.join(self.tree, "deploy", "baremetal", "link"))
        with self.assertRaisesRegex(ok.Refused, "is a link"):
            ok.tree_digest(self.tree)

    def test_wrong_counts_duplicates_and_another_set_are_refused_before_anything_opens(self):
        from shamir_mnemonic import generate_mnemonics
        command = self.command("manifest")
        for shares, reason in ((self.all[:2], "2 shares given; this set needs exactly 3"), (self.all[:4], "4 shares given"),
                               ([self.all[0], self.all[0], self.all[1]], "a share was given twice"),
                               (generate_mnemonics(1, [(3, 5)], b"\x09" * 32)[0][:3], "not of the set this file was sealed under")):
            with self.assertRaisesRegex(ok.Refused, reason):
                self.sign(command, shares=shares)
        self.assertEqual(self.records(), [])
        self.assertFalse(os.path.exists(os.path.join(self.session_dir, "manifest.out")), "the tool never ran")

    def test_the_command_line_runs_a_session(self):
        """coderabbitai on #115: the CLI, not only the function. --exec's REMAINDER once overwrote the subcommand's name."""
        import contextlib
        import io
        command = self.command("manifest")
        argv = ["sign", "--sealed", self.sealed, "--who", "Owner", "--out", self.session_dir, "--tool-root", self.tree,
                "--tool-digest", self.digest, "--output", command[command.index("--out") + 1], "--exec"] + command
        import types
        stdout = io.StringIO()
        fake_sys = types.SimpleNamespace(stdin=io.StringIO("\n".join(self.all[1:4]) + "\n"),
                                         stdout=types.SimpleNamespace(buffer=io.BytesIO()), stderr=io.StringIO())
        fake_sys.stderr.buffer = io.BytesIO()
        with unittest.mock.patch.object(ok, "sys", fake_sys), contextlib.redirect_stdout(stdout):
            self.assertEqual(ok.main(argv), 0, fake_sys.stderr.getvalue())
        self.assertIn("SIGNED by manifest with root (shares 2,3,4)", stdout.getvalue())
        self.assertEqual(len(self.records()), 1)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(ok.main(["tree-digest", "--root", self.tree]), 0)
        self.assertEqual(out.getvalue().strip(), self.digest)

    def test_a_failing_command_is_recorded_then_refused(self):
        with self.assertRaisesRegex(ok.Refused, "the command exited 3: the session is recorded"):
            self.sign(self.command("manifest", "exit3"))
        [record] = self.records()
        self.assertEqual(record["exit"], 3)

    def test_a_key_left_in_the_ram_directory_is_found_recorded_and_refused(self):
        with self.assertRaisesRegex(ok.Refused, "KEY MATERIAL LEFT IN .* kept.pem"):
            self.sign(self.command("uki", "leak"))
        self.assertEqual(self.records()[0]["key_material_found"], ["kept.pem"])

    def test_a_key_left_in_tmp_or_dev_shm_is_found_too(self):
        """regalia-kms-d9 on #115: the scan covers where else a tool could write, not only the session directory."""
        with self.assertRaisesRegex(ok.Refused, "KEY MATERIAL LEFT"):
            self.sign(self.command("manifest", "leak-elsewhere", "--elsewhere", self.elsewhere))
        self.assertEqual(self.records()[0]["key_material_found"], [os.path.join(self.elsewhere, "k")])

    def test_a_tree_the_command_changed_is_recorded_and_refused(self):
        with self.assertRaisesRegex(ok.Refused, "the regalia-kms tree changed while the command ran"):
            self.sign(self.command("manifest", "touch-tree"))
        record = self.records()[0]
        self.assertNotEqual(record["tool_digest_after"], record["tool_digest"])

    def test_an_output_the_command_did_not_write_is_recorded_and_refused(self):
        with self.assertRaisesRegex(ok.Refused, "the command did not write"):
            self.sign(self.command("manifest", "nooutput"))
        self.assertEqual(list(self.records()[0]["outputs"].values()), [None])

    def test_a_session_needs_a_ram_directory_and_a_name(self):
        with unittest.mock.patch.dict(os.environ, {"CEREMONY_ALLOW_NONTMPFS": "0"}), unittest.mock.patch.object(ok, "fs_type", lambda p: "ext4"):
            with self.assertRaisesRegex(ok.Refused, "not a RAM file system"):
                self.sign(self.command("manifest"))
        with self.assertRaisesRegex(ok.Refused, "--who names the person signing"):
            self.sign(self.command("manifest"), who="")

    def test_verify_forms_records_what_it_checked_signed_by_the_root(self):
        """regalia-kms-d9 on #114: with --partial, the unchecked forms are in the evidence, not only on the screen."""
        self.forms(self.all[:4], partial=True)
        records = [n for n in os.listdir(self.out) if n.startswith("forms-verified-")]
        self.assertEqual(len(records), 1)
        with open(self.path(records[0])) as f:
            record = ok.verify_record(json.load(f))
        self.assertEqual((record["event"], record["checked"], record["not_checked"]), ("forms-verified", [1, 2, 3, 4], [5]))
        self.assertEqual(record["root_entry"], self.record["root_entry"])

if __name__ == "__main__":
    unittest.main()
