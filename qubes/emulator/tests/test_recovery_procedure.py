#!/usr/bin/env python3
"""Validate the DOCUMENTED offline recovery procedure (recovery/RECOVERY-TECHNICAL.md).

A recoverer follows that runbook with no repo, no network, no second chance. These tests
exercise the exact commands it tells them to run — back up a BIP-39 mnemonic as 4-of-6
SLIP-39 shares, then recover from a file of 4 shares (one per line) — and lock in the
passphrase footgun guard (a non-empty passphrase must warn; a wrong passphrase yields a
different seed, so it must never be used silently).
"""
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
BACKUP = os.path.join(SCRIPTS, "bip39-slip39-backup.py")


def have_lib():
    try:
        import shamir_mnemonic, mnemonic  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(have_lib(), "shamir-mnemonic/mnemonic not installed")
class TestRecoveryProcedure(unittest.TestCase):
    def setUp(self):
        from mnemonic import Mnemonic
        self.mn = Mnemonic("english").generate(128)
        self.dir = tempfile.mkdtemp()

    def _run(self, *args, **kw):
        return subprocess.run([sys.executable, BACKUP, *args], capture_output=True, text=True, **kw)

    def _shares(self, out_path):
        return [l for l in open(out_path).read().splitlines()
                if l and not l.startswith("#") and len(l.split()) >= 16]

    def test_backup_then_recover_from_4_share_file_roundtrips(self):
        # backup (the ceremony's option c)
        seed_in = os.path.join(self.dir, "seed.in")
        open(seed_in, "w").write(self.mn)
        shares_out = os.path.join(self.dir, "slip39.txt")
        r = self._run("--in", seed_in, "--threshold", "4", "--shares", "6", "--out", shares_out)
        self.assertEqual(r.returncode, 0, r.stderr)
        shares = self._shares(shares_out)
        self.assertEqual(len(shares), 6)
        # recovery procedure (runbook lines 46-49): put 4 shares one-per-line, --recover
        four = os.path.join(self.dir, "four.txt")
        open(four, "w").write("\n".join(shares[:4]) + "\n")
        rec = self._run("--recover", "--in", four)
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.assertEqual(rec.stdout.strip(), self.mn, "recovered mnemonic != original")

    def test_recover_from_a_different_4_subset_also_works(self):
        seed_in = os.path.join(self.dir, "seed.in"); open(seed_in, "w").write(self.mn)
        shares_out = os.path.join(self.dir, "s.txt")
        self._run("--in", seed_in, "--threshold", "4", "--shares", "6", "--out", shares_out)
        shares = self._shares(shares_out)
        four = os.path.join(self.dir, "four2.txt")
        open(four, "w").write("\n".join([shares[2], shares[3], shares[4], shares[5]]) + "\n")
        rec = self._run("--recover", "--in", four)
        self.assertEqual(rec.stdout.strip(), self.mn)

    def test_nonempty_passphrase_warns(self):
        seed_in = os.path.join(self.dir, "seed.in"); open(seed_in, "w").write(self.mn)
        out = os.path.join(self.dir, "p.txt")
        r = self._run("--in", seed_in, "--threshold", "4", "--shares", "6",
                      "--passphrase", "secret-pass", "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("passphrase", r.stderr.lower())
        self.assertIn("WARNING", r.stderr)

    def test_wrong_passphrase_yields_a_different_mnemonic(self):
        # this is WHY the warning exists: recovery with the wrong passphrase silently differs
        seed_in = os.path.join(self.dir, "seed.in"); open(seed_in, "w").write(self.mn)
        out = os.path.join(self.dir, "pp.txt")
        self._run("--in", seed_in, "--threshold", "4", "--shares", "6",
                  "--passphrase", "correct", "--out", out)
        shares = self._shares(out)
        four = os.path.join(self.dir, "f.txt"); open(four, "w").write("\n".join(shares[:4]) + "\n")
        good = self._run("--recover", "--in", four, "--passphrase", "correct").stdout.strip()
        bad = self._run("--recover", "--in", four, "--passphrase", "WRONG").stdout.strip()
        self.assertEqual(good, self.mn)
        self.assertNotEqual(bad, self.mn, "a wrong passphrase must yield a different mnemonic (it does — hence the warning)")

    def _run_env(self, *args, env=None, **kw):
        run_env = dict(os.environ)
        if env:
            run_env.update(env)
        return subprocess.run([sys.executable, BACKUP, *args],
                              capture_output=True, text=True, env=run_env, **kw)

    def test_passphrase_via_env_off_argv_roundtrips(self):
        # REGRESSION: the SLIP-39 passphrase gates recovery and is UNRECOVERABLE from the
        # shares — leaking it is as bad as leaking the seed. It must have an off-argv path
        # (env SLIP39_PASSPHRASE), the same protection given to the mnemonic input and to
        # slip39-mint. The passphrase must NOT appear anywhere on stdout/stderr, and the
        # env passphrase must actually be applied (recovery needs it).
        pw = "correct horse battery staple"
        seed_in = os.path.join(self.dir, "seed.in"); open(seed_in, "w").write(self.mn)
        out = os.path.join(self.dir, "env.txt")
        r = self._run_env("--in", seed_in, "--threshold", "4", "--shares", "6", "--out", out,
                          env={"SLIP39_PASSPHRASE": pw})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(pw, r.stdout)
        self.assertNotIn(pw, r.stderr)                       # never echo the passphrase
        shares = self._shares(out)
        four = os.path.join(self.dir, "envfour.txt"); open(four, "w").write("\n".join(shares[:4]) + "\n")
        got = self._run_env("--recover", "--in", four, env={"SLIP39_PASSPHRASE": pw}).stdout.strip()
        self.assertEqual(got, self.mn, "env passphrase not applied consistently on split+recover")
        # and the env passphrase was NOT ignored: recovering with no passphrase must differ
        wrong = self._run("--recover", "--in", four).stdout.strip()
        self.assertNotEqual(wrong, self.mn, "env passphrase was ignored (shares recover without it)")

    def test_passphrase_via_file_off_argv_roundtrips(self):
        pw = "custodian-only-phrase"
        seed_in = os.path.join(self.dir, "seed.in"); open(seed_in, "w").write(self.mn)
        pf = os.path.join(self.dir, "pass.txt"); open(pf, "w").write(pw + "\n")  # trailing NL trimmed
        out = os.path.join(self.dir, "file.txt")
        r = self._run("--in", seed_in, "--threshold", "4", "--shares", "6",
                      "--passphrase-file", pf, "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(pw, r.stdout)
        self.assertNotIn(pw, r.stderr)
        shares = self._shares(out)
        four = os.path.join(self.dir, "filefour.txt"); open(four, "w").write("\n".join(shares[:4]) + "\n")
        got = self._run("--recover", "--in", four, "--passphrase-file", pf).stdout.strip()
        self.assertEqual(got, self.mn, "file passphrase not applied consistently on split+recover")

    def test_passphrase_on_argv_warns_about_leak(self):
        # The legacy --passphrase argv path must still work but WARN that it leaks to
        # ps / /proc/<pid>/cmdline / shell history, without echoing the passphrase value.
        pw = "leaky-argv-phrase"
        seed_in = os.path.join(self.dir, "seed.in"); open(seed_in, "w").write(self.mn)
        out = os.path.join(self.dir, "argv.txt")
        r = self._run("--in", seed_in, "--threshold", "4", "--shares", "6",
                      "--passphrase", pw, "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ps", r.stderr.lower())                # warns about the argv leak
        self.assertNotIn(pw, r.stderr)                       # never echo the passphrase
        self.assertNotIn(pw, r.stdout)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)


class TestRecoveryRunbookHsmDkekRestore(unittest.TestCase):
    """The self-contained runbook must cover the born-in-HSM (DKEK) custody path too.

    ceremony.sh step_hsm_funding (the optional Nitrokey HSM signer path) creates the funding
    key NON-EXPORTABLE inside the HSM; its ONLY backup is the DKEK-wrapped blob
    (funding-wrapped.bin) + the password-protected DKEK share (dkek.pbe) + the 4-of-6
    sc-hsm-tool password shares. There are NO SLIP-39 funding shares in that path.
    step_archive burns dkek.pbe + funding-wrapped.bin onto EVERY M-DISC and step_recovery_card
    stamps the DVD card with --hsm-funding, which points the recoverer at RECOVERY-TECHNICAL.md
    as the 'Full runbook'. If this runbook only documents the SLIP-39 seed recovery, a recoverer
    holding an HSM-backed funding key is stranded — the money is unrecoverable. This pins the
    runbook to actually carry the DKEK restore (fresh SmartCard-HSM -> import DKEK -> unwrap-key
    -> read pubkey -> derive + match the recorded anchor).
    """

    def _md(self):
        # recovery/ is a sibling of scripts/ in both the repo and the baked image
        # (/opt/vault-ceremony/{scripts,recovery}); resolve it from CEREMONY_SCRIPTS.
        recovery = os.environ.get("CEREMONY_RECOVERY") or os.path.join(SCRIPTS, "..", "recovery")
        with open(os.path.join(recovery, "RECOVERY-TECHNICAL.md")) as f:
            return f.read()

    def test_runbook_documents_the_dkek_hsm_restore(self):
        t = self._md()
        low = t.lower()
        # the burned artifacts a recoverer actually holds on the M-DISC
        self.assertIn("funding-wrapped.bin", t,
                      "runbook must name the DKEK-wrapped funding backup burned on the disc")
        self.assertIn("dkek.pbe", low,
                      "runbook must name the DKEK share file burned on the disc")
        # the real restore command sequence (mirrors ceremony.sh step_hsm_funding)
        self.assertIn("--import-dkek-share", t,
                      "runbook must tell the recoverer to import the DKEK share")
        self.assertIn("--unwrap-key", t,
                      "runbook must tell the recoverer to sc-hsm-tool --unwrap-key the funding key")
        self.assertIn("--dkek-shares", t,
                      "runbook must document initialising a fresh HSM with the DKEK domain")
        # after restore, prove control by matching the recorded pubkey/address anchor
        self.assertIn("derive-akash-address.py --der", t,
                      "runbook must verify the restored HSM pubkey against the recorded anchor")

    def test_case_contents_lists_the_dkek_password_shares(self):
        # Section 1 tells the recoverer what is physically in each sealed case. Under the HSM
        # custody path the share material is the 4-of-6 DKEK PASSWORD shares, not SLIP-39 words;
        # listing only SLIP-39/metal strands the HSM-path recoverer at the first step.
        low = self._md().lower()
        self.assertIn("dkek", low,
                      "Section 1 case contents must acknowledge the DKEK password shares (HSM custody)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
