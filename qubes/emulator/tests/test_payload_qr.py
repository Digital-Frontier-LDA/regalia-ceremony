#!/usr/bin/env python3
"""Adversarial tests for payload-qr.py — the chunked-QR archival path for the encrypted
Tier-0 recovery payload.

This is the copy meant to be readable when the M-DISC has rotted and every chip card is dead,
so the properties that matter are the ones that make a pile of paper squares reassemblable by
someone who has never seen this repo:

  * a split ALWAYS round-trips (verified, never assumed — the emitter self-checks)
  * every chunk line is newline-free, so a line-based container cannot silently split one
    (this is a REGRESSION test: the first implementation chunked age's ASCII armor directly,
     whose 64-column newlines corrupted reassembly through a file)
  * a missing chunk is named, not silently tolerated
  * a single corrupted character is caught by the digest, never returned as "recovered"
  * chunks from two different payloads cannot be spliced together
  * plaintext is REFUSED — the emitter will not print an unencrypted secret onto paper
  * the digest covers the DECODED payload, which is what the recoverer verifies
"""
import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
SCRIPT = os.path.join(_SCRIPTS, "payload-qr.py")
ARMOR = "-----BEGIN AGE ENCRYPTED FILE-----"


def run(*args, **kw):
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True, **kw)


def fake_payload(nbytes=2600):
    """An age-armored-looking blob big enough to span several chunks."""
    body = "".join("%04d" % (i % 10000) for i in range(nbytes // 4))
    return (ARMOR + "\n" + body + "\n-----END AGE ENCRYPTED FILE-----\n").encode()


class PayloadQrTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "payload.age")
        self.payload = fake_payload()
        with open(self.src, "wb") as fh:
            fh.write(self.payload)
        self.qr = os.path.join(self.tmp, "qr")

    def split_ok(self, path=None):
        r = run("--split", path or self.src, "--outdir", self.qr)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def chunk_lines(self):
        with open(os.path.join(self.qr, "chunks.txt")) as fh:
            return fh.read().splitlines()

    # ---------------------------------------------------------------- round-trip
    def test_split_join_round_trips_exactly(self):
        self.split_ok()
        out = os.path.join(self.tmp, "rebuilt.age")
        r = run("--join", os.path.join(self.qr, "chunks.txt"), "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), self.payload)

    def test_payload_spans_multiple_chunks(self):
        self.split_ok()
        self.assertGreater(len(self.chunk_lines()), 1,
                           "test payload should span >1 chunk or it exercises nothing")

    def test_one_png_per_chunk(self):
        self.split_ok()
        pngs = [f for f in os.listdir(self.qr) if f.endswith(".png")]
        self.assertEqual(len(pngs), len(self.chunk_lines()))

    # ------------------------------------------------------- the newline regression
    def test_chunk_lines_contain_no_embedded_newlines(self):
        """REGRESSION: chunking the armor directly put its 64-column newlines inside a chunk,
        so writing the chunks to a file and reading them back split one chunk into two and the
        reassembly corrupted. base64 keeps every chunk on exactly one line."""
        self.split_ok()
        with open(os.path.join(self.qr, "chunks.txt")) as fh:
            lines = fh.read().splitlines()
        for ln in lines:
            self.assertNotIn("\n", ln)
            # 4 fields exactly: magic, idx/total, digest, data
            self.assertEqual(len(ln.split(" ")), 4, "chunk line must have exactly 4 fields: %.40s" % ln)

    def test_chunk_data_is_valid_base64(self):
        self.split_ok()
        joined = "".join(ln.split(" ", 3)[3] for ln in self.chunk_lines())
        self.assertEqual(base64.b64decode(joined, validate=True), self.payload)

    # ------------------------------------------------------------------ integrity
    def test_missing_chunk_is_named_not_tolerated(self):
        self.split_ok()
        partial = os.path.join(self.tmp, "partial.txt")
        with open(partial, "w") as fh:
            fh.write(self.chunk_lines()[0] + "\n")
        r = run("--join", partial, "--out", os.path.join(self.tmp, "x.age"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MISSING chunk", r.stdout + r.stderr)

    def test_single_character_corruption_is_caught(self):
        self.split_ok()
        lines = self.chunk_lines()
        lines[0] = lines[0][:-1] + ("A" if lines[0][-1] != "A" else "B")
        bad = os.path.join(self.tmp, "corrupt.txt")
        with open(bad, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        r = run("--join", bad, "--out", os.path.join(self.tmp, "x.age"))
        self.assertNotEqual(r.returncode, 0, "a corrupted chunk must never be returned as recovered")
        self.assertRegex(r.stdout + r.stderr, "CHECKSUM MISMATCH|not valid base64")

    def test_chunks_from_different_payloads_cannot_be_spliced(self):
        self.split_ok()
        first = self.chunk_lines()[0]
        other_src = os.path.join(self.tmp, "other.age")
        with open(other_src, "wb") as fh:
            fh.write(fake_payload(3000))
        other_qr = os.path.join(self.tmp, "qr2")
        self.assertEqual(run("--split", other_src, "--outdir", other_qr).returncode, 0)
        with open(os.path.join(other_qr, "chunks.txt")) as fh:
            second = fh.read().splitlines()[1]
        mixed = os.path.join(self.tmp, "mixed.txt")
        with open(mixed, "w") as fh:
            fh.write(first + "\n" + second + "\n")
        r = run("--join", mixed, "--out", os.path.join(self.tmp, "x.age"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("DIFFERENT payloads", r.stdout + r.stderr)

    def test_digest_covers_the_decoded_payload(self):
        """The printed checksum must be over the file the recoverer saves and decrypts, not
        over its base64 — otherwise the verify step in the instructions cannot be followed."""
        self.split_ok()
        digest = self.chunk_lines()[0].split(" ")[2]
        self.assertEqual(digest, hashlib.sha256(self.payload).hexdigest()[:16])

    # ------------------------------------------------------------------ fail-closed
    def test_refuses_plaintext_payload(self):
        plain = os.path.join(self.tmp, "plain.txt")
        with open(plain, "w") as fh:
            fh.write("derivation_wallet_mnemonic_v2: abandon abandon abandon about\n")
        r = run("--split", plain, "--outdir", os.path.join(self.tmp, "qrp"))
        self.assertNotEqual(r.returncode, 0, "must not print a plaintext secret onto archival paper")
        self.assertIn("PLAINTEXT", r.stdout + r.stderr)

    def test_allow_plaintext_is_an_explicit_override(self):
        plain = os.path.join(self.tmp, "plain.txt")
        with open(plain, "w") as fh:
            fh.write("throwaway drill value\n")
        r = run("--split", plain, "--outdir", os.path.join(self.tmp, "qrp"), "--allow-plaintext")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_refuses_empty_payload(self):
        empty = os.path.join(self.tmp, "empty.age")
        open(empty, "wb").close()
        r = run("--split", empty, "--outdir", os.path.join(self.tmp, "qre"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("EMPTY", r.stdout + r.stderr)

    # ------------------------------------------------------------------ instructions
    def test_instructions_are_emitted_and_self_contained(self):
        """The reassembly rule must travel WITH the paper. If it only existed in this script,
        a dead M-DISC would turn the sheets into unreadable squares."""
        self.split_ok()
        with open(os.path.join(self.qr, "INSTRUCTIONS.txt")) as fh:
            txt = fh.read()
        for needed in ("base64 -d", "sha256", "age -d", ARMOR):
            self.assertIn(needed, txt, "instructions must mention %r" % needed)

    def test_selftest_subcommand_passes(self):
        r = run("--selftest")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
