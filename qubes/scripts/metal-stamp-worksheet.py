#!/usr/bin/env python3
"""Metal-plate (punch-set) backup helper for SLIP-0039 Shamir shares.

A SLIP-39 share is 20 (or 33) words; every word in the 1024-word list is uniquely
identified by its first 4 letters, so a fire/water/decay-proof metal backup only needs
the 4-letter UPPERCASE prefix of each word stamped with a letter/number punch set.

  worksheet (default): turn a share into the numbered prefix grid to STAMP
      metal-stamp-worksheet.py --in share.txt --case-id DF-BG-03 --share "ssss? no, SLIP-39 3/6"
  verify: read the prefixes you stamped back and reconstruct the full words, so a
      mis-stamp is caught BEFORE you rely on the plate
      metal-stamp-worksheet.py --verify --in stamped-prefixes.txt

SECRET-BEARING: the prefixes ARE the share. Run only on the air-gapped vault qube;
treat the worksheet like a share (seal it / shred it). Reads the share from a file or
stdin — never from argv (which `ps` would expose).
"""
import argparse
import glob
import os
import sys

def load_wordlist():
    try:
        from shamir_mnemonic import wordlist as wl
        return list(wl.WORDLIST)
    except Exception:
        pass
    try:
        import shamir_mnemonic
        return list(shamir_mnemonic.wordlist.WORDLIST)
    except Exception:
        pass
    for p in glob.glob(os.path.expanduser("~/.local/pipx/venvs/shamir-mnemonic/lib/python*/site-packages")):
        if p not in sys.path:
            sys.path.insert(0, p)
    try:
        from shamir_mnemonic import wordlist as wl
        return list(wl.WORDLIST)
    except Exception as e:
        sys.exit("error: cannot load the SLIP-39 wordlist (need the shamir-mnemonic package): %s" % e)

def read_tokens(path):
    data = sys.stdin.read() if path in ("-", None) else open(path).read()
    return data.split()

def worksheet(words, wordset, case_id, share, cols):
    bad = [w for w in words if w not in wordset]
    if bad:
        sys.exit("error: these are not SLIP-39 words: %s" % ", ".join(bad[:5]))
    out = []
    out.append("METAL-PLATE STAMPING WORKSHEET  (SLIP-0039, 4-letter prefixes)")
    out.append("Case: %s   Share: %s   Words: %d" % (case_id or "____", share or "____", len(words)))
    out.append("Stamp each token below (UPPERCASE; punch set A-Z). Then run --verify.")
    out.append("")
    row = []
    for i, w in enumerate(words, 1):
        row.append("%02d %s" % (i, w[:4].upper()))
        if len(row) == cols:
            out.append("   ".join(row)); row = []
    if row:
        out.append("   ".join(row))
    out.append("")
    out.append("After stamping: read the plate back into a file and run")
    out.append("  metal-stamp-worksheet.py --verify --in <that file>")
    out.append("then `shamir recover` with the reconstructed words to prove the plate.")
    return "\n".join(out) + "\n"

def verify(prefixes, wordlist):
    # The 4-letter prefix MUST uniquely identify a word (SLIP-39 guarantees this for its
    # 1024-word list). Assert it, so a wordlist change can never silently map a prefix to
    # the wrong word.
    by_prefix = {}
    for w in wordlist:
        k = w[:4].upper()
        if k in by_prefix:
            sys.exit("error: wordlist has a 4-letter prefix collision (%s, %s) — cannot verify safely"
                     % (by_prefix[k], w))
        by_prefix[k] = w
    words, errs = [], []
    for i, tok in enumerate(prefixes, 1):
        key = tok.strip().upper()[:4]
        if key in by_prefix:
            words.append(by_prefix[key])
        else:
            errs.append("token %d %r -> no SLIP-39 word" % (i, tok))
    if errs:
        sys.exit("VERIFY FAILED:\n  " + "\n  ".join(errs))

    # CRITICAL: prefix-validity alone does NOT catch a mis-stamp that lands on a DIFFERENT
    # but still-valid word (ACADEMIC -> ACID). The SLIP-39 share carries an RS1024 checksum,
    # so a single wrong word fails it. Validate the reconstructed share against that checksum
    # — that is the real "catch a mis-stamp before relying on the plate" guarantee. We do NOT
    # print the reconstructed words unless the checksum passes (a wrong share is not a share).
    share = " ".join(words)
    try:
        from shamir_mnemonic.share import Share
        Share.from_mnemonic(share)
    except ImportError:
        # library missing: fall back to validity-only, but say so loudly (don't overclaim).
        out = ["VERIFY PARTIAL — %d prefixes are valid SLIP-39 words, but the SLIP-39 checksum"
               % len(words),
               "could NOT be validated (shamir-mnemonic not installed). Install it and re-verify,",
               "or prove the plate with `shamir recover` before trusting it.",
               "Reconstructed share:", "", share, ""]
        return "\n".join(out) + "\n"
    except Exception as e:
        # checksum failed -> a word is wrong (mis-stamp to another valid word). Do NOT print
        # the wrong reconstruction; it is not a usable share.
        sys.exit("VERIFY FAILED: the reconstructed share FAILS its SLIP-39 checksum (%s).\n"
                 "  A prefix was mis-stamped to a different valid word. Re-check the plate "
                 "against the worksheet; do NOT rely on it." % type(e).__name__)
    out = ["VERIFY OK — %d prefixes reconstruct a SLIP-39 share with a VALID checksum." % len(words),
           "(One wrong word would fail the checksum; this share is internally consistent.)",
           "Reconstructed share (feed >= threshold such shares to `shamir recover` to fully prove):",
           "", share, ""]
    return "\n".join(out) + "\n"

def main():
    ap = argparse.ArgumentParser(description="SLIP-39 metal-plate stamping worksheet / verify.")
    ap.add_argument("--in", dest="inp", default="-", help="input file (words for worksheet, prefixes for --verify); '-' = stdin")
    ap.add_argument("--out", default="", help="write to a file instead of stdout (recommended; it's secret-bearing)")
    ap.add_argument("--verify", action="store_true", help="read stamped prefixes and reconstruct the words")
    ap.add_argument("--case-id", default="")
    ap.add_argument("--share", default="")
    ap.add_argument("--cols", type=int, default=4)
    a = ap.parse_args()
    wl = load_wordlist()
    toks = read_tokens(a.inp)
    if not toks:
        sys.exit("error: no input read")
    text = verify(toks, wl) if a.verify else worksheet(toks, set(wl), a.case_id, a.share, a.cols)
    if a.out:
        # The worksheet encodes a SLIP-39 share — create it 0600 regardless of umask.
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        # O_CREAT's mode is IGNORED when a.out already exists; fchmod the fd to 0600 BEFORE
        # writing so a pre-existing/loose --out file never exposes the share mid-write.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        sys.stderr.write("wrote %s (SECRET, mode 0600 — seal or shred it)\n" % a.out)
    else:
        # The worksheet's 4-letter prefixes ARE the SLIP-39 share. Warn on a TTY so it isn't
        # casually screenshotted/logged (scrollback/tee/recording); prefer --out to a tmpfs file.
        # Parity with bip39-slip39-backup.py and slip39-mint.py.
        if sys.stderr.isatty():
            sys.stderr.write("WARNING: writing SECRET share material to stdout — do not log/screenshot. "
                             "Prefer --out <tmpfs file>.\n")
        sys.stdout.write(text)

if __name__ == "__main__":
    main()
