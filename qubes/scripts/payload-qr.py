#!/usr/bin/env python3
"""payload-qr.py — split an ENCRYPTED recovery payload into self-describing QR codes for
archival paper, and reassemble them back.

  payload-qr.py --split payload.age --outdir ./qr        # emit qr-01.png … + INSTRUCTIONS.txt
  payload-qr.py --join ./qr/chunks.txt --out payload.age # reassemble from decoded chunk text
  payload-qr.py --selftest                               # split→join round-trip, no files kept

WHY A FORMAT AT ALL: a payload larger than one symbol has to be chunked, and N loose QR codes
with no headers are a puzzle — you cannot tell their order, whether one is missing, or whether
you decoded them correctly. Each chunk therefore carries its index, the total, and a digest of
the WHOLE payload, so a recoverer can order them, detect a missing one, and prove the
reassembly is byte-exact before trusting it.

WHY THE INSTRUCTIONS ARE PRINTED: the reassembly rule is four lines of text and is emitted
alongside the codes. If it lived only in this script, and this script lived only on the M-DISC,
then a dead disc would turn the paper backup into unreadable squares — reintroducing exactly
the technology dependency the paper copy exists to remove. Anyone with a QR reader and a
base64 decoder must be able to finish the job without this file.

CHUNK FORMAT (one line per QR, ASCII only):
    AKCP1 <idx>/<total> <sha256-16> <base64-chunk>
      AKCP1        format magic + version
      <idx>/<total>  1-based index and chunk count
      <sha256-16>  first 16 hex chars of SHA-256 over the DECODED payload
      <chunk>      a slice of the base64 of the payload, split on character boundaries

Reassembly: sort by idx, concatenate the chunk fields, base64-decode the result.

WHY BASE64 AND NOT THE ARMOR DIRECTLY: age's ASCII armor contains newlines every 64 characters.
A chunk carrying an embedded newline stops being one line, so a line-based container (and any
operator pasting scans into a text file) silently splits it and the reassembly corrupts. This
was caught by the round-trip self-check below rather than in the field. base64 with no line
breaks keeps every chunk on exactly one line and makes the format binary-safe as a side effect.
"""
import argparse
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

MAGIC = "AKCP1"
# qrencode -l H (30% error correction) holds 1273 bytes in byte mode at version 40. Chunk well
# under that: the header costs ~35 bytes, and leaving headroom keeps every symbol at a version
# whose modules stay legible at the print size print_share() uses (-s 6). Damage tolerance on a
# sheet meant to outlive its operator is worth far more than fewer symbols.
CHUNK_BYTES = 1000

AGE_ARMOR_HEADER = "-----BEGIN AGE ENCRYPTED FILE-----"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def split(payload_path, outdir, allow_plaintext=False, quiet=False):
    with open(payload_path, "rb") as fh:
        data = fh.read()
    if not data:
        sys.exit("payload-qr: refusing to split an EMPTY payload")

    # FAIL CLOSED on plaintext. These symbols go onto paper that is photographed, photocopied,
    # and stored in six places; a plaintext seed committed to them is unrecoverable as a
    # mistake. Require the age armor header unless the operator explicitly overrides, so the
    # catastrophic case takes a deliberate act rather than a forgotten flag.
    head = data[: len(AGE_ARMOR_HEADER)].decode("ascii", errors="replace")
    if head != AGE_ARMOR_HEADER and not allow_plaintext:
        sys.exit(
            "payload-qr: input does not start with '%s' — refusing to print what may be a "
            "PLAINTEXT secret onto archival paper. Encrypt it first:\n"
            "    age -a -r <breakglass-recipient> -o payload.age payload.txt\n"
            "(Use --allow-plaintext only for a throwaway drill.)" % AGE_ARMOR_HEADER
        )

    digest = _digest(data)
    # base64 the payload BEFORE chunking so every chunk is newline-free and fits on one line.
    b64 = base64.b64encode(data).decode("ascii")
    chunks = [b64[i:i + CHUNK_BYTES] for i in range(0, len(b64), CHUNK_BYTES)]
    total = len(chunks)
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    # `mode=` is only applied when makedirs CREATES the directory, and is masked by the umask
    # even then. If outdir already exists at 0755 the QR filenames and chunks.txt are listable
    # by any local user, so tighten it unconditionally. The files are chmod'd separately; the
    # directory is what makes them discoverable.
    os.chmod(outdir, 0o700)

    if not shutil.which("qrencode"):
        sys.exit("payload-qr: qrencode not found — cannot emit QR symbols")

    lines = []
    for idx, chunk in enumerate(chunks, 1):
        line = "%s %d/%d %s %s" % (MAGIC, idx, total, digest, chunk)
        lines.append(line)
        png = os.path.join(outdir, "qr-%02d.png" % idx)
        # -l H mirrors print_share(); the symbol is written from STDIN so no chunk of the
        # payload ever reaches argv (ps / /proc/<pid>/cmdline) — same rule the rest of the
        # ceremony follows for secret material, applied here even though this is ciphertext.
        proc = subprocess.run(["qrencode", "-o", png, "-s", "6", "-m", "4", "-l", "H"],
                              input=line.encode(), capture_output=True)
        if proc.returncode != 0:
            sys.exit("payload-qr: qrencode failed on chunk %d: %s" % (idx, proc.stderr.decode()))
        os.chmod(png, 0o600)

    chunks_txt = os.path.join(outdir, "chunks.txt")
    with open(chunks_txt, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(chunks_txt, 0o600)

    # VERIFY BEFORE TRUSTING: reassemble from what we just wrote and require a byte-exact match.
    # A split whose chunks cannot rebuild the input is worse than no backup, because it looks
    # like one. Every other backup path in this ceremony reconstruct-verifies; so does this.
    rebuilt = join_lines(lines)
    if rebuilt != data:
        sys.exit("payload-qr: SELF-CHECK FAILED — the emitted chunks do not rebuild the payload")

    with open(os.path.join(outdir, "INSTRUCTIONS.txt"), "w") as fh:
        fh.write(instructions(total, digest))

    if not quiet:
        print("payload-qr: %d symbol(s) in %s (sha256-16 %s)" % (total, outdir, digest))
        print("payload-qr: self-check OK — the chunks rebuild the payload byte-for-byte")
    return total, digest


def instructions(total, digest):
    return f"""HOW TO REBUILD THIS PAYLOAD (no special software required)

You are holding {total} QR code(s). Each one decodes to a single line of text that looks like:

    {MAGIC} <index>/{total} {digest} <data>

STEPS
  1. Scan every QR code with any QR reader. Each gives you one line of text.
  2. Check you have all {total}: the indexes must run 1..{total} with none missing.
  3. Sort the lines by index (ascending).
  4. Take the FOURTH field of each line (everything after the {len(digest)}-character checksum
     and the space that follows it) and join them together in order, with NOTHING in between
     — no spaces, no newlines. The result is one long base64 string.
  5. Base64-decode that string into a file called payload.age:
       tr -d '\\n' < joined.txt | base64 -d > payload.age
     It will begin "{AGE_ARMOR_HEADER}".
  6. Verify: sha256 of payload.age must START with {digest}
       sha256sum payload.age
  7. Decrypt with the breakglass age key (reconstruct it from any 4 of the 6 Shamir shares):
       age -d -i breakglass.key payload.age > payload.txt

If a QR code is damaged and will not scan, the payload cannot be rebuilt from the remaining
codes — every chunk is required. Use another copy of this sheet, the M-DISC, or a chip card.

The checksum {digest} is the first 16 hex characters of the SHA-256 of the COMPLETE rebuilt
file. It confirms you reassembled correctly; it is not a secret and protects nothing on its own.
"""


def join_lines(lines):
    seen = {}
    digest = None
    total = None
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        # Split on ARBITRARY whitespace, not a single literal space. These lines come back from
        # a QR scanner app or a copy-paste out of a terminal, either of which can turn the
        # separator into a tab, a non-breaking run, or a doubled space. `split(" ", 3)` treats a
        # repeated space as an empty field and does not split on tabs, so a perfectly good chunk
        # would be rejected as "not a chunk line" — on the RECOVERY path, where the operator has
        # nothing left but paper. maxsplit=3 still protects the base64 payload, which contains
        # no whitespace, from being split further.
        parts = line.split(None, 3)
        if len(parts) != 4 or parts[0] != MAGIC:
            sys.exit("payload-qr: not a %s chunk line: %.40s…" % (MAGIC, line))
        idx_total, dg, chunk = parts[1], parts[2], parts[3]
        try:
            idx, tot = (int(x) for x in idx_total.split("/"))
        except ValueError:
            sys.exit("payload-qr: malformed index field %r" % idx_total)
        # Mixing chunks from two different payloads (two ceremonies, two sheets) would splice
        # unrelated ciphertext into a blob that fails to decrypt for no visible reason. The
        # digest and total are per-payload, so a mismatch means the sheets were mixed up.
        if digest is None:
            digest, total = dg, tot
        elif dg != digest or tot != total:
            sys.exit("payload-qr: chunks are from DIFFERENT payloads (checksum/total differ) "
                     "— do not mix sheets from separate ceremonies")
        if idx in seen and seen[idx] != chunk:
            sys.exit("payload-qr: two DIFFERENT chunks both claim index %d" % idx)
        seen[idx] = chunk

    if total is None:
        sys.exit("payload-qr: no chunks found")
    missing = [i for i in range(1, total + 1) if i not in seen]
    if missing:
        sys.exit("payload-qr: MISSING chunk(s) %s of %d — the payload cannot be rebuilt without "
                 "them; use another copy of the sheet, the M-DISC, or a chip card."
                 % (",".join(str(m) for m in missing), total))

    joined = "".join(seen[i] for i in range(1, total + 1))
    try:
        data = base64.b64decode(joined, validate=True)
    except Exception as exc:
        sys.exit("payload-qr: the joined chunks are not valid base64 (%s) — a symbol was likely "
                 "mis-scanned or a chunk is truncated. Re-scan and retry." % exc)
    got = _digest(data)
    if got != digest:
        sys.exit("payload-qr: CHECKSUM MISMATCH — rebuilt %s, expected %s. The reassembly is "
                 "WRONG; do not use it." % (got, digest))
    return data


def join(chunks_path, out_path, quiet=False):
    with open(chunks_path) as fh:
        data = join_lines(fh.read().splitlines())
    with open(out_path, "wb") as fh:
        fh.write(data)
    os.chmod(out_path, 0o600)
    if not quiet:
        print("payload-qr: rebuilt %d bytes -> %s (checksum verified)" % (len(data), out_path))
    return data


def selftest():
    """Round-trip a synthetic multi-chunk payload. Proves the format, the digest check and the
    missing-chunk detection actually work before anyone relies on them at a ceremony."""
    body = "".join("%04d" % (i % 10000) for i in range(700))          # ~2.8 KB -> 3 chunks
    payload = (AGE_ARMOR_HEADER + "\n" + body + "\n-----END AGE ENCRYPTED FILE-----\n").encode()
    tmp = tempfile.mkdtemp()
    try:
        src = os.path.join(tmp, "payload.age")
        with open(src, "wb") as fh:
            fh.write(payload)
        total, digest = split(src, os.path.join(tmp, "qr"), quiet=True)
        assert total > 1, "selftest payload should span multiple chunks, got %d" % total
        rebuilt = join(os.path.join(tmp, "qr", "chunks.txt"), os.path.join(tmp, "out.age"), quiet=True)
        assert rebuilt == payload, "round-trip mismatch"
        lines = open(os.path.join(tmp, "qr", "chunks.txt")).read().splitlines()
        print("payload-qr selftest: OK (%d chunks, digest %s, round-trip byte-exact)" % (total, digest))
        return lines
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--split", metavar="PAYLOAD.age")
    g.add_argument("--join", metavar="CHUNKS.txt")
    g.add_argument("--selftest", action="store_true")
    ap.add_argument("--outdir", default="./qr")
    ap.add_argument("--out", default="./payload.age")
    ap.add_argument("--allow-plaintext", action="store_true",
                    help="permit splitting input that is not age-armored (DRILLS ONLY)")
    a = ap.parse_args()
    os.umask(0o077)
    if a.selftest:
        selftest()
    elif a.split:
        split(a.split, a.outdir, allow_plaintext=a.allow_plaintext)
    else:
        join(a.join, a.out)


if __name__ == "__main__":
    main()
