#!/usr/bin/env python3
"""slip39-mint.py — mint a FRESH SLIP-0039 master secret as k-of-n shares, SAFELY.

Replaces the `shamir create` CLI in the ceremony, which (a) prints the master secret to
stdout — so redirecting its output captures the secret into the very file that holds the
shares, defeating Shamir — and (b) distributes shares with no reconstruct-verify. This tool:

  * never emits the master secret anywhere (it lives only in RAM, recoverable from the shares)
  * reconstruct-verifies that the generated shares actually rebuild the secret — checking
    EVERY k-of-n subset when that is cheap (<= 200 combinations), so you never hand out a
    set that doesn't recover
  * writes ONLY the shares, 0600, never world-readable

  slip39-mint.py --threshold 4 --shares 6 --out shares.txt
  slip39-mint.py --threshold 4 --shares 6 --from-entropy --entropy-file dice.hex   # operator entropy
  <dice.hex slip39-mint.py --threshold 4 --shares 6 --from-entropy --out shares.txt # or via stdin

The operator-supplied master-secret entropy is read from a file/stdin, NEVER as an argv
value: an argv secret would leak to ps / /proc/<pid>/cmdline for the run and, durably, to
the operator's shell history (ceremony.sh disables history only in its own shell). This
mirrors bip39-slip39-backup.py, which also reads its entropy off-argv.

Recover with: bip39-slip39-backup.py --recover  (or `shamir recover`), then use the secret.
"""
import argparse
import itertools
import os
import secrets
import sys


def load():
    try:
        from shamir_mnemonic import generate_mnemonics, combine_mnemonics
    except Exception as exc:  # pragma: no cover
        sys.exit(f"error: shamir-mnemonic not installed ({exc}); pip install 'shamir-mnemonic[cli]'")
    return generate_mnemonics, combine_mnemonics


def read(path):
    # Read secret-bearing input from a file or stdin ('-' / None) — never from argv.
    return sys.stdin.read() if path in ("-", None) else open(path).read()


def resolve_passphrase(args):
    """Resolve the SLIP-39 passphrase WITHOUT forcing it onto argv. The passphrase is
    recovery-critical AND unrecoverable from the shares, so leaking it is as bad as leaking
    the secret. Order (mirrors sle4442-manager's resolve_secret): SLIP39_PASSPHRASE env >
    --passphrase-file <path> > --passphrase <value>. env/file inputs are stripped (an
    editor's trailing newline is not part of the passphrase); an argv value is used verbatim
    but WARNS loudly, because it is visible in ps / /proc/<pid>/cmdline / shell history. The
    warning never echoes the passphrase itself."""
    env = os.environ.get("SLIP39_PASSPHRASE")
    if env is not None:
        return env.strip()
    pf = getattr(args, "passphrase_file", None)
    if pf:
        return read(pf).strip()
    val = getattr(args, "passphrase", "") or ""
    if val:
        sys.stderr.write("WARNING: a passphrase was passed on the command line — it is visible in "
                         "ps / /proc/<pid>/cmdline / shell history. Use SLIP39_PASSPHRASE env or "
                         "--passphrase-file <tmpfs path> instead.\n")
    return val


def main():
    ap = argparse.ArgumentParser(description="mint a fresh SLIP-0039 secret as k-of-n shares (safely)")
    ap.add_argument("--threshold", type=int, default=4, help="k (shares needed to recover)")
    ap.add_argument("--shares", type=int, default=6, help="n (total shares)")
    ap.add_argument("--strength", type=int, default=128, choices=(128, 256),
                    help="master-secret bits (default 128)")
    ap.add_argument("--from-entropy", action="store_true",
                    help="use operator-supplied hex entropy as the master secret (keeps the "
                         "software RNG out of the trust path). The hex is read from --entropy-file "
                         "or stdin — NEVER from argv; length must be 16 or 32 bytes")
    ap.add_argument("--entropy-file", default="-",
                    help="file to read --from-entropy hex from ('-' = stdin). Never pass the "
                         "secret on argv (it leaks to ps / cmdline / shell history).")
    ap.add_argument("--passphrase", default="",
                    help="SLIP-39 passphrase (default empty; must match on recover). AVOID passing "
                         "on argv — it leaks to ps / cmdline / shell history. Prefer SLIP39_PASSPHRASE "
                         "env or --passphrase-file.")
    ap.add_argument("--passphrase-file", default="",
                    help="file to read the SLIP-39 passphrase from (off-argv; trailing whitespace "
                         "trimmed). Overridden by SLIP39_PASSPHRASE env if set.")
    ap.add_argument("--out", default="", help="write shares here (0600). Default stdout.")
    a, extra = ap.parse_known_args()
    if extra:
        # A stray positional almost certainly means the operator tried to pass the entropy
        # hex on argv (the old, leaky interface). Refuse — and do NOT echo the argument, so
        # the refusal itself never prints the secret.
        sys.exit("error: unexpected argument(s); never pass the entropy hex on argv — it leaks "
                 "to ps / /proc/<pid>/cmdline and shell history. Use --from-entropy with "
                 "--entropy-file <path> (or pipe the hex on stdin).")
    if not (2 <= a.threshold <= a.shares <= 16):
        sys.exit("error: require 2 <= threshold <= shares <= 16")

    generate_mnemonics, combine_mnemonics = load()
    pw = resolve_passphrase(a).encode()
    if pw:
        # A SLIP-39 passphrase is NOT recoverable from the shares: a wrong/forgotten one
        # silently yields a DIFFERENT secret (no error). For a set-once backup, default empty
        # and record the passphrase with the custodians if you must use one.
        sys.stderr.write("WARNING: a non-empty SLIP-39 passphrase is set. Recovery REQUIRES the EXACT "
                         "passphrase — a wrong one silently produces a DIFFERENT secret (no error).\n")

    if a.from_entropy:
        hexstr = "".join(read(a.entropy_file).split())   # off-argv: file or stdin, whitespace-tolerant
        try:
            secret = bytes.fromhex(hexstr)
        except ValueError:
            sys.exit("error: --from-entropy input must be hex (no 0x)")
        if len(secret) not in (16, 32):
            sys.exit("error: entropy must be 16 or 32 bytes (128/256-bit)")
    else:
        secret = secrets.token_bytes(a.strength // 8)   # CSPRNG

    shares = generate_mnemonics(1, [(a.threshold, a.shares)], secret, pw)[0]
    if len(shares) != a.shares:
        sys.exit("error: library returned %d shares, expected %d" % (len(shares), a.shares))

    # RECONSTRUCT-VERIFY: every k-of-n subset must rebuild the EXACT secret (cheap to check
    # exhaustively for ceremony-sized n). If any subset fails, refuse — an unverified split
    # is not a backup.
    from math import comb
    n_subsets = comb(a.shares, a.threshold)
    subsets = itertools.combinations(range(a.shares), a.threshold)
    checked = 0
    if n_subsets > 200:
        # too many to enumerate; check a deterministic spread (first-k, last-k, strided)
        picks = [tuple(range(a.threshold)),
                 tuple(range(a.shares - a.threshold, a.shares)),
                 tuple(range(0, a.shares, max(1, a.shares // a.threshold)))[:a.threshold]]
        subsets = (s for s in picks if len(set(s)) == a.threshold)
    for combo in subsets:
        chosen = [shares[i] for i in combo]
        if combine_mnemonics(chosen, pw) != secret:
            sys.exit("error: reconstruct-verify FAILED for subset %s — refusing to distribute" % (combo,))
        checked += 1
    if checked == 0:
        sys.exit("error: no subset was verified")

    body = ("# SLIP-0039 %d-of-%d. RECONSTRUCT-VERIFIED: %d subset(s) rebuild the secret.\n"
            "# Recoverable ONLY from >= %d of these shares (the secret itself is never written).\n" %
            (a.threshold, a.shares, checked, a.threshold)) + "\n".join(shares) + "\n"

    if a.out:
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        # O_CREAT's mode is IGNORED when a.out already exists; fchmod the fd to 0600 BEFORE
        # writing so a pre-existing/loose --out file never exposes the shares mid-write.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(body)
        sys.stderr.write("wrote %s (SECRET shares, 0600 — seal/shred). Master secret NOT written anywhere.\n" % a.out)
    else:
        if sys.stderr.isatty():
            sys.stderr.write("WARNING: shares on stdout — do not log/screenshot; prefer --out <tmpfs file>.\n")
        sys.stdout.write(body)


if __name__ == "__main__":
    main()
