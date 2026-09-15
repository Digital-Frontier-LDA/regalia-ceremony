#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import sys
import unittest

# THE REPO ROOT HAS TO BE ON sys.path BEFORE THIS IMPORT, because this file is run as a SCRIPT --
# `python3 .../test_bundle.py` from run-tests.sh -- not discovered. `unittest discover -s kms/tests`
# happens to put the root on sys.path, which is why the nine other importers of source_lexing work
# without this; run any of them directly from another directory and they fail the same way. This
# one is the only one invoked as a script today, and it failed in CI with
# "ModuleNotFoundError: No module named 'ceremony'" while passing locally from the repo root.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))

from ceremony.qubes.emulator.tests.source_lexing import shell_code  # noqa: E402


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("bundle_tool", HERE / "bundle-tool.py")
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(TOOL)
SIGN_SPEC = importlib.util.spec_from_file_location("sign_release", HERE / "sign-release.py")
SIGN = importlib.util.module_from_spec(SIGN_SPEC)
assert SIGN_SPEC.loader
SIGN_SPEC.loader.exec_module(SIGN)


class BundleMetadataTests(unittest.TestCase):
    def make_tree(self):
        temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(temp.name)
        (root / "install.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "payload").write_bytes(b"reviewed bytes")
        package = {"name": "fixture", "version": "1", "sha256": "0" * 64}
        (root / "package-lock.json").write_text(json.dumps({"schema": "regalia.offline-package-lock/v1", "packages": [package]}))
        (root / "provenance.json").write_text(json.dumps({"schema": "regalia.offline-provenance/v1", "debian_release": "12"}))
        (root / "sbom.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [package]}))
        self.write_manifest(root)
        return temp, root

    def write_manifest(self, root):
        lines = []
        for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"):
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
        (root / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")

    def test_complete_tree_verifies(self):
        temp, root = self.make_tree()
        self.addCleanup(temp.cleanup)
        TOOL.verify(root)

    def test_tamper_is_rejected(self):
        temp, root = self.make_tree()
        self.addCleanup(temp.cleanup)
        (root / "payload").write_bytes(b"substituted")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            TOOL.verify(root)

    def test_uncovered_file_is_rejected(self):
        temp, root = self.make_tree()
        self.addCleanup(temp.cleanup)
        (root / "uncovered").write_text("x")
        with self.assertRaisesRegex(ValueError, "coverage mismatch"):
            TOOL.verify(root)

    def test_symlink_is_rejected(self):
        temp, root = self.make_tree()
        self.addCleanup(temp.cleanup)
        (root / "link").symlink_to("payload")
        with self.assertRaisesRegex(ValueError, "symlink"):
            TOOL.verify(root)

    def test_signed_release_binds_artifact_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            artifact = root / "bundle.tar.gz"
            artifact.write_bytes(b"deterministic artifact")
            release = root / "RELEASE.json"
            TOOL.release_manifest(artifact, release, "a" * 40, 1_800_000_000, "20250809T000000Z")
            private = root / "private.pem"
            public = root / "public.pem"
            signature = root / "RELEASE.sig.der"
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", private], check=True)
            subprocess.run(["openssl", "ec", "-in", private, "-pubout", "-out", public], check=True, capture_output=True)
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", private, "-out", signature, release], check=True)
            good = subprocess.run([HERE / "verify-release.sh", artifact, release, signature, public], check=False)
            self.assertEqual(good.returncode, 0)
            artifact.write_bytes(b"tampered")
            bad = subprocess.run([HERE / "verify-release.sh", artifact, release, signature, public], check=False)
            self.assertNotEqual(bad.returncode, 0)

    def test_raw_p256_signature_is_strictly_der_encoded(self):
        encoded = SIGN.raw_p256_to_der(bytes.fromhex("80" + "00" * 31 + "01".rjust(64, "0")))
        self.assertEqual(encoded[0], 0x30)
        self.assertIn(b"\x02\x21\x00\x80", encoded)
        with self.assertRaisesRegex(ValueError, "scalar"):
            SIGN.raw_p256_to_der(b"\0" * 64)

    def test_builder_rejects_untracked_bundle_inputs(self):
        build = shell_code((HERE / "build.sh").read_text(encoding="utf-8"))
        self.assertIn("--untracked-files=all", build)
        self.assertIn('safe.directory="$REPO"', build)
        self.assertIn("qubes", build)
        self.assertIn("debian/offline-bundle", build)


if __name__ == "__main__":
    unittest.main()
