#!/usr/bin/env python3
"""Adversarial tests for slip39-mint.py — the safe replacement for `shamir create`.

Locks in the three properties that make it set-once-safe:
  * the master secret is NEVER emitted (not to stdout, not to the --out file)
  * every k-of-n subset reconstructs (verified, not assumed)
  * --from-entropy is honoured exactly (operator-supplied entropy ends up as the secret)
"""
import importlib.machinery
import importlib.util
import itertools
import os
import subprocess
import sys
import tempfile
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
SCRIPT = os.path.join(_SCRIPTS, "slip39-mint.py")


def have_lib():
    try:
        import shamir_mnemonic  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(have_lib(), "shamir-mnemonic not installed")
class TestMint(unittest.TestCase):
    def _run(self, *args, stdin=None, env=None):
        run_env = None
        if env is not None:
            run_env = dict(os.environ)
            run_env.update(env)
        return subprocess.run([sys.executable, SCRIPT, *args],
                              capture_output=True, text=True, input=stdin, env=run_env)

    def _run_entropy(self, ent_hex, *args):
        # Supply operator entropy OFF-ARGV via stdin (--entropy-file default '-'),
        # the way the ceremony must — never as an argv value.
        return self._run("--from-entropy", *args, stdin=ent_hex)

    def _shares(self, text):
        return [l for l in text.splitlines()
                if l and not l.startswith("#") and len(l.split()) >= 16]

    def test_master_secret_never_on_stdout(self):
        ent = "00112233445566778899aabbccddeeff"
        r = self._run_entropy(ent, "--threshold", "4", "--shares", "6")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(ent, r.stdout)              # the secret must not appear
        self.assertNotIn(ent, r.stderr)

    def test_master_secret_never_in_out_file(self):
        ent = "0123456789abcdef0123456789abcdef"
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "shares.txt")
            r = self._run_entropy(ent, "--threshold", "4", "--shares", "6", "--out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            blob = open(out).read()
            self.assertNotIn(ent, blob, "master secret leaked into the shares file")
            # also: file must be 0600
            self.assertEqual(os.stat(out).st_mode & 0o077, 0)

    def test_entropy_via_file_is_honoured(self):
        # The operator supplies entropy through --entropy-file (a tmpfs path), off argv.
        from shamir_mnemonic import combine_mnemonics
        ent = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        with tempfile.TemporaryDirectory() as d:
            ef = os.path.join(d, "dice.hex")
            with open(ef, "w") as f:
                f.write(ent.hex() + "\n")
            r = self._run("--from-entropy", "--entropy-file", ef,
                          "--threshold", "3", "--shares", "5")
            self.assertEqual(r.returncode, 0, r.stderr)
            shares = self._shares(r.stdout)
            self.assertEqual(combine_mnemonics(shares[:3], b""), ent)

    def test_every_subset_recovers(self):
        from shamir_mnemonic import combine_mnemonics
        ent = bytes.fromhex("aabbccddeeff00112233445566778899")
        r = self._run_entropy(ent.hex(), "--threshold", "4", "--shares", "6")
        shares = self._shares(r.stdout)
        self.assertEqual(len(shares), 6)
        for combo in itertools.combinations(shares, 4):
            self.assertEqual(combine_mnemonics(list(combo), b""), ent,
                             "a 4-of-6 subset failed to recover the exact entropy")

    def test_from_entropy_is_the_recovered_secret(self):
        from shamir_mnemonic import combine_mnemonics
        ent = bytes.fromhex("ffffffffffffffffffffffffffffffff")
        r = self._run_entropy(ent.hex(), "--threshold", "3", "--shares", "5")
        shares = self._shares(r.stdout)
        self.assertEqual(combine_mnemonics(shares[:3], b""), ent)

    def test_secret_never_accepted_as_argv_value(self):
        # REGRESSION: the SLIP-39 master secret must NEVER be passable as an argv value.
        # An argv secret leaks to ps/proc/<pid>/cmdline for the run and, durably, to the
        # operator's shell history (ceremony.sh disables history only in its OWN shell).
        # The operator must supply entropy off-argv (--entropy-file / stdin). Passing a
        # hex value directly on argv must be REFUSED (non-zero exit), and the refusal must
        # not itself echo the secret.
        ent = "00112233445566778899aabbccddeeff"
        r = self._run("--threshold", "4", "--shares", "6", "--from-entropy", ent)
        self.assertNotEqual(r.returncode, 0,
                            "tool accepted the master secret as an argv value "
                            "(leaks to cmdline / ps / shell history)")
        self.assertNotIn(ent, r.stdout)
        self.assertNotIn(ent, r.stderr)

    def test_passphrase_never_accepted_only_via_argv(self):
        # REGRESSION: the SLIP-39 passphrase is recovery-critical and UNRECOVERABLE from the
        # shares. It must have an OFF-ARGV path (env / file), the same protection already
        # given to the entropy and to the sle4442 payload — otherwise an operator who opts
        # into a passphrase is forced to leak it to ps / /proc/<pid>/cmdline / shell history.
        from shamir_mnemonic import combine_mnemonics
        ent = "00112233445566778899aabbccddeeff"
        secret = bytes.fromhex(ent)
        pw = "correct horse battery staple"

        # via env var SLIP39_PASSPHRASE
        r = self._run("--from-entropy", "--threshold", "3", "--shares", "5",
                      stdin=ent, env={"SLIP39_PASSPHRASE": pw})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(pw, r.stdout)
        self.assertNotIn(pw, r.stderr)                       # never echo the passphrase
        shares = self._shares(r.stdout)
        self.assertEqual(combine_mnemonics(shares[:3], pw.encode()), secret)
        self.assertNotEqual(combine_mnemonics(shares[:3], b""), secret,
                            "env passphrase was ignored (shares recover without it)")

    def test_passphrase_via_file_is_honoured(self):
        from shamir_mnemonic import combine_mnemonics
        ent = "0123456789abcdef0123456789abcdef"
        secret = bytes.fromhex(ent)
        pw = "custodian-only-phrase"
        with tempfile.TemporaryDirectory() as d:
            pf = os.path.join(d, "pass.txt")
            with open(pf, "w") as f:
                f.write(pw + "\n")                            # trailing newline must be trimmed
            r = self._run("--from-entropy", "--threshold", "3", "--shares", "5",
                          "--passphrase-file", pf, stdin=ent)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(pw, r.stdout)
            self.assertNotIn(pw, r.stderr)
            shares = self._shares(r.stdout)
            self.assertEqual(combine_mnemonics(shares[:3], pw.encode()), secret)

    def test_passphrase_on_argv_warns(self):
        # The legacy --passphrase argv path must still work but WARN loudly that it leaks,
        # and the warning must not echo the passphrase value itself.
        ent = "00112233445566778899aabbccddeeff"
        pw = "leaky-argv-phrase"
        r = self._run("--from-entropy", "--threshold", "3", "--shares", "5",
                      "--passphrase", pw, stdin=ent)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ps", r.stderr.lower())
        self.assertNotIn(pw, r.stderr)
        self.assertNotIn(pw, r.stdout)

    def test_out_file_tightened_before_write_window(self):
        # REGRESSION: os.open(O_CREAT|O_TRUNC) IGNORES its mode arg when --out already exists,
        # so a pre-existing/attacker-planted 0644 file keeps its loose perms while the SLIP-39
        # shares are streamed onto it — a chmod(0600) that runs only AFTER the write leaves a
        # window in which any local user can read the master-secret shares. The tool must
        # fchmod the fd to 0600 BEFORE writing. Proven white-box: import the module in-process
        # and interpose on os.fdopen (called right after os.open, before the write) to read the
        # fd's on-disk mode at that instant.
        loader = importlib.machinery.SourceFileLoader("mint_mod", os.path.abspath(SCRIPT))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)  # __name__ != "__main__" so main() does not auto-run
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "shares.txt")
            open(out, "w").close()
            os.chmod(out, 0o644)  # adversary pre-plants a group/world-readable --out
            captured = {}
            real_fdopen = os.fdopen

            def spy_fdopen(fd, *a, **k):
                captured["mode"] = os.fstat(fd).st_mode & 0o777
                return real_fdopen(fd, *a, **k)

            old_argv = sys.argv
            os.fdopen = spy_fdopen
            sys.argv = [SCRIPT, "--from-entropy", "--threshold", "3", "--shares", "5",
                        "--entropy-file", "-", "--out", out]
            try:
                import io
                old_stdin = sys.stdin
                sys.stdin = io.StringIO("00112233445566778899aabbccddeeff\n")
                try:
                    mod.main()
                except SystemExit as e:
                    self.assertIn(e.code, (0, None), "mint aborted: %r" % (e.code,))
                finally:
                    sys.stdin = old_stdin
            finally:
                os.fdopen = real_fdopen
                sys.argv = old_argv
            self.assertIn("mode", captured, "the --out write path was never exercised")
            self.assertEqual(captured["mode"] & 0o077, 0,
                             "pre-existing --out was still group/world readable (mode %04o) "
                             "while the SLIP-39 shares were being written" % captured["mode"])

    def test_rejects_bad_entropy_length(self):
        r = self._run_entropy("abcd", "--threshold", "2", "--shares", "3")
        self.assertNotEqual(r.returncode, 0)

    def test_rejects_threshold_gt_shares(self):
        r = self._run("--threshold", "5", "--shares", "3")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
