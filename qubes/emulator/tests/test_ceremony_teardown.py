#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE.parent.parent / "scripts" / "ceremony-teardown.py"


class TeardownTests(unittest.TestCase):
    def run_teardown(self, leak=False):
        root = pathlib.Path(tempfile.mkdtemp())
        work = root / "ceremony.test"
        retained = root / "retained"
        work.mkdir(mode=0o700)
        retained.mkdir()
        canary = work / ".residue-canary"
        canary.write_bytes(b"c" * 32)
        (work / "private-key").write_text("secret", encoding="utf-8")
        if leak:
            (retained / "spool-copy").write_bytes(b"prefix" + canary.read_bytes())
        baseline = work / ".mount-baseline"
        baseline.write_text("/\n/dev\n/dev/shm\n", encoding="utf-8")
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_findmnt = fake_bin / "findmnt"
        fake_findmnt.write_text("#!/bin/sh\nprintf '/\\n/dev\\n/dev/shm\\n'\n", encoding="utf-8")
        fake_findmnt.chmod(0o755)
        report = root / "report.json"
        env = dict(os.environ)
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        result = subprocess.run(
            [str(SCRIPT), "--allow-nontmpfs-test", "--workdir", str(work), "--canary", str(canary),
             "--mount-baseline", str(baseline), "--scan-root", str(retained), "--report", str(report)],
            check=False, capture_output=True, text=True, env=env,
        )
        return root, work, report, result

    def test_removes_workdir_and_emits_passing_evidence(self):
        _, work, report, result = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(work.exists())
        self.assertEqual(json.loads(report.read_text())["status"], "pass")

    def test_canary_in_retained_artifact_fails(self):
        _, work, report, result = self.run_teardown(leak=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(work.exists())
        evidence = json.loads(report.read_text())
        self.assertEqual(evidence["status"], "fail")
        self.assertTrue(evidence["canary_hits"])

    def test_refuses_broad_or_non_tmpfs_target_in_production_mode(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root)
            canary = path / "canary"
            canary.write_bytes(b"x" * 32)
            baseline = path / "mounts"
            baseline.write_text("/\n")
            result = subprocess.run(
                [str(SCRIPT), "--workdir", str(path), "--canary", str(canary), "--mount-baseline", str(baseline)],
                check=False,
            )
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
