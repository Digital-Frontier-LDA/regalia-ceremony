#!/usr/bin/env python3
"""emulator_deps (#173): a missing dependency in a Python suite is a skip by hand and a failure under
REQUIRE_EMULATOR_DEPS=1, as CI runs, for a single test, a TestCase class, and skip_dep inside a test."""
import os as _hermetic_os  # no real card, even run by hand (#104): no pcscd, the emulator stand-ins first
_hermetic_os.environ.setdefault("PCSCLITE_CSOCK_NAME", "/nonexistent/regalia-no-pcscd.comm")
_hermetic_os.environ["PATH"] = _hermetic_os.path.join(_hermetic_os.path.dirname(_hermetic_os.path.abspath(__file__)), "..", "bin") + _hermetic_os.pathsep + _hermetic_os.environ.get("PATH", "")
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = textwrap.dedent('''
    import importlib.util, os, sys, unittest
    spec = importlib.util.spec_from_file_location("emulator_deps", sys.argv[1])
    deps = importlib.util.module_from_spec(spec); spec.loader.exec_module(deps)

    class One(unittest.TestCase):
        @deps.needs(False, "age is not installed")
        def test_needs(self):
            raise RuntimeError("ran without its dependency")

        @deps.needs(True, "never shown")
        def test_present(self):
            pass

        def test_inside(self):
            deps.skip_dep(self, "gpg is not installed")
            raise RuntimeError("ran past skip_dep")

    @deps.needs(False, "sops is not installed")
    class Whole(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            raise RuntimeError("setUpClass needs sops")

        def setUp(self):
            raise RuntimeError("setUp needs sops")

        def test_a(self):
            raise RuntimeError("ran without sops")

    r = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    print("RUN %d FAIL %d ERROR %d SKIP %d" % (r.testsRun, len(r.failures), len(r.errors), len(r.skipped)))
''')


class Deps(unittest.TestCase):
    def run_suite(self, require):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(SUITE)
        self.addCleanup(os.unlink, f.name)
        env = dict(os.environ)
        env.pop("REQUIRE_EMULATOR_DEPS", None)
        if require:
            env["REQUIRE_EMULATOR_DEPS"] = "1"
        return subprocess.run([sys.executable, "-I", f.name, os.path.join(HERE, "emulator_deps.py")],
                              capture_output=True, text=True, env=env).stdout

    def test_by_hand_a_missing_dependency_skips(self):
        out = self.run_suite(require=False)
        self.assertIn("RUN 4 FAIL 0 ERROR 0 SKIP 3", out)
        self.assertIn("age is not installed (REQUIRE_EMULATOR_DEPS=1 makes this a failure)", out)
        self.assertNotIn("ran without", out)

    def test_under_require_every_skip_is_a_failure_and_nothing_needing_it_runs(self):
        out = self.run_suite(require=True)
        self.assertIn("RUN 4 FAIL 3 ERROR 0 SKIP 0", out)
        for reason in ("age is not installed", "gpg is not installed", "sops is not installed"):
            self.assertIn(reason + ", and REQUIRE_EMULATOR_DEPS=1: this test must run here, not skip", out)
        for ran in ("ran without", "ran past skip_dep", "setUpClass needs sops", "setUp needs sops"):
            self.assertNotIn(ran, out)


if __name__ == "__main__":
    unittest.main()
