#!/usr/bin/env python3
"""Back up a BIP39 wallet mnemonic (funding / derivation root) as SLIP-0039 shares.

OPTION B custody: the funding wallet is a SEED whose recovery is a Shamir/metal/DVD
backup, NOT the HSM. tx-signer/cosmjs use a BIP39 mnemonic; this bridges it to SLIP-0039
k-of-n word-shares so it backs up with the same flow as everything else (and the shares
feed metal-stamp-worksheet.py for metal plates). The round-trip is EXACT: BIP39 -> entropy
-> SLIP-39 split -> recover -> entropy -> BIP39 returns the identical mnemonic (so the
derived akash address is unchanged). Recovery needs NO HSM — lose/break the HSM and the
seed is still recoverable from any k shares.

  split   (default): BIP39 mnemonic -> n SLIP-39 word-shares (k needed)
      bip39-slip39-backup.py --in funding.mnemonic --threshold 4 --shares 6 --out shares.txt
  recover: >=k SLIP-39 shares -> the original BIP39 mnemonic
      bip39-slip39-backup.py --recover --in collected-shares.txt

SECRET-BEARING. Air-gapped vault qube only. Reads from file/stdin, never argv. Output is
the seed (recover) or its shares (split) — seal/shred it.
"""
import argparse
import os
import sys

def load():
    try:
        from mnemonic import Mnemonic
        from shamir_mnemonic import generate_mnemonics, combine_mnemonics
        return Mnemonic, generate_mnemonics, combine_mnemonics
    except Exception as e:
        sys.exit("error: need the 'mnemonic' and 'shamir-mnemonic' packages: %s" % e)

def read(path):
    return (sys.stdin.read() if path in ("-", None) else open(path).read())

def resolve_passphrase(args):
    """Resolve the SLIP-39 passphrase WITHOUT forcing it onto argv. The passphrase gates
    recovery and is UNRECOVERABLE from the shares — a wrong one silently yields a different
    seed — so leaking it is as bad as leaking the mnemonic itself. Order (mirrors
    slip39-mint's resolve_passphrase): SLIP39_PASSPHRASE env > --passphrase-file <path> >
    --passphrase <value>. env/file inputs are stripped (an editor's trailing newline is not
    part of the passphrase); an argv value is used verbatim but WARNS loudly, because it is
    visible in ps / /proc/<pid>/cmdline / shell history. The warning never echoes the value."""
    env = os.environ.get("SLIP39_PASSPHRASE")
    if env is not None:
        return env.strip()
    pf = getattr(args, "passphrase_file", "") or ""
    if pf:
        return read(pf).strip()
    val = getattr(args, "passphrase", "") or ""
    if val:
        sys.stderr.write("WARNING: a passphrase was passed on the command line — it is visible in "
                         "ps / /proc/<pid>/cmdline / shell history. Use SLIP39_PASSPHRASE env or "
                         "--passphrase-file <tmpfs path> instead.\n")
    return val

def main():
    ap = argparse.ArgumentParser(description="BIP39 wallet mnemonic <-> SLIP-0039 shares (Option B backup).")
    ap.add_argument("--in", dest="inp", default="-", help="input file ('-' = stdin)")
    ap.add_argument("--out", default="", help="write output to a file (recommended; it's secret-bearing)")
    # the three actions are mutually exclusive (default = split a mnemonic into shares)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--recover", action="store_true", help="recover the BIP39 mnemonic from >=k SLIP-39 shares")
    mode.add_argument("--from-entropy", action="store_true",
                      help="input is HEX entropy (e.g. dice/coin rolls), not a mnemonic: encode it to a BIP39 "
                           "mnemonic. Keeps the software RNG OUT of the trust path — you supply the entropy.")
    ap.add_argument("--threshold", type=int, default=4, help="k (shares needed to recover)")
    ap.add_argument("--shares", type=int, default=6, help="n (total shares)")
    ap.add_argument("--passphrase", default="",
                    help="SLIP-39 passphrase (default empty; must match on recover). AVOID passing "
                         "on argv — it leaks to ps / cmdline / shell history. Prefer SLIP39_PASSPHRASE "
                         "env or --passphrase-file.")
    ap.add_argument("--passphrase-file", default="",
                    help="file to read the SLIP-39 passphrase from (off-argv; trailing whitespace "
                         "trimmed). Overridden by SLIP39_PASSPHRASE env if set.")
    a = ap.parse_args()
    Mnemonic, generate_mnemonics, combine_mnemonics = load()
    m = Mnemonic("english")
    pw = resolve_passphrase(a).encode()
    if pw:
        # A SLIP-39 passphrase is NOT recoverable from the shares: a wrong/forgotten one
        # silently yields DIFFERENT bytes (no error), i.e. a wrong seed -> wrong address ->
        # funds lost with no warning. For a set-once custodial backup this is a footgun;
        # default empty and record the passphrase requirement in the recovery runbook.
        sys.stderr.write("WARNING: a non-empty SLIP-39 passphrase is set. Recovery REQUIRES the EXACT "
                         "passphrase — a wrong one silently produces a DIFFERENT seed (no error). "
                         "Record it with the custodians, or use the empty default.\n")

    if a.from_entropy:
        hexstr = "".join(read(a.inp).split()).lower()
        try:
            ent = bytes.fromhex(hexstr)
        except ValueError:
            sys.exit("error: --from-entropy expects hex (no 0x). 16/20/24/28/32 bytes = 12/15/18/21/24 words.")
        if len(ent) not in (16, 20, 24, 28, 32):
            sys.exit("error: entropy must be 128/160/192/224/256 bits (got %d bits)." % (len(ent) * 8))
        out = m.to_mnemonic(ent).strip() + "\n"   # deterministic encode; no RNG used
    elif a.recover:
        shares = read(a.inp).split("\n")
        shares = [s.strip() for s in shares if s.strip()]
        if not shares:
            sys.exit("error: no shares read")
        ent = combine_mnemonics(shares, pw)
        out = m.to_mnemonic(ent).strip() + "\n"
    else:
        words = " ".join(read(a.inp).split())
        if not m.check(words):
            sys.exit("error: input is not a valid BIP39 mnemonic")
        ent = m.to_entropy(words)
        groups = generate_mnemonics(1, [(a.threshold, a.shares)], bytes(ent), pw)[0]
        # RECONSTRUCT-VERIFY before emitting: prove k shares rebuild the EXACT mnemonic, so we
        # never hand out shares that don't actually recover. Check TWO distinct k-subsets (the
        # first k and the last k) — defense in depth on the funding seed, not just one subset.
        subsets = [groups[:a.threshold], groups[a.shares - a.threshold:]]
        for sub in subsets:
            if m.to_mnemonic(combine_mnemonics(sub, pw)) != words:
                sys.exit("error: reconstruct-verify FAILED — generated shares do not rebuild the mnemonic; aborting.")
        hdr = "# SLIP-0039 %d-of-%d backup of a BIP39 wallet mnemonic. RECONSTRUCT-VERIFIED:\n" \
              "# any %d shares rebuild the exact mnemonic. Distribute one share per custodian;\n" \
              "# stamp each to metal (metal-stamp-worksheet.py). Recover: --recover.\n" % (
                  a.threshold, a.shares, a.threshold)
        out = hdr + "\n".join(groups) + "\n"

    if a.out:
        # The output holds SLIP-39 shares (or, with --recover, the recovered mnemonic) —
        # create it 0600 regardless of the caller's umask so it is never group/world readable.
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        # O_CREAT's mode is IGNORED when a.out already exists (O_TRUNC just truncates it),
        # so a pre-existing/attacker-planted file keeps its looser perms. fchmod the fd to
        # 0600 BEFORE writing any secret — never leave a read window while the seed shares
        # are on disk. (chmod'ing only after the write would expose them for the whole write.)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(out)
        sys.stderr.write("wrote %s (SECRET, mode 0600 — seal or shred it)\n" % a.out)
    else:
        # Output is secret (SLIP-39 shares, or with --recover your seed). Warn on a TTY so it
        # isn't casually screenshotted/logged; prefer --out to a tmpfs file.
        if sys.stderr.isatty():
            sys.stderr.write("WARNING: writing SECRET material to stdout — do not log/screenshot. "
                             "Prefer --out <tmpfs file>.\n")
        sys.stdout.write(out)

if __name__ == "__main__":
    main()
