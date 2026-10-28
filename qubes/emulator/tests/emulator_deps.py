"""A missing dependency in a Python emulator suite: a skip by hand, a failure where REQUIRE_EMULATOR_DEPS=1 (CI), so a
test that never ran is never green (#173). The shell suites' skip_dep does the same (#166). Each test file loads this
by path, as it loads the script under test, so it is found under `python3 -I` too:

    _deps_spec = importlib.util.spec_from_file_location("emulator_deps", os.path.join(HERE, "emulator_deps.py"))
    deps = importlib.util.module_from_spec(_deps_spec)
    _deps_spec.loader.exec_module(deps)

    @deps.needs(shutil.which("age") is not None, "age is not installed")     # a test or a TestCase class
    ...
    deps.skip_dep(self, "shamir_mnemonic not installed")                      # inside a test
"""
import functools
import os
import unittest

HINT = " (REQUIRE_EMULATOR_DEPS=1 makes this a failure)"


def required():
    return os.environ.get("REQUIRE_EMULATOR_DEPS", "0") == "1"


def _failure(reason):
    return "%s, and REQUIRE_EMULATOR_DEPS=1: this test must run here, not skip" % reason


def needs(available, reason):
    """unittest.skipUnless(available, reason), except that under REQUIRE_EMULATOR_DEPS=1 a test it would skip fails."""
    if available:
        return lambda thing: thing
    if not required():
        return unittest.skip(reason + HINT)
    message = _failure(reason)

    def failing(thing):
        if isinstance(thing, type):                          # a TestCase: every test in it fails, from setUp
            def setUp(self):
                self.fail(message)
            thing.setUp = setUp
            for name in ("setUpClass", "tearDownClass"):     # never reach code that needs what is missing, its own or
                setattr(thing, name, classmethod(lambda cls: None))  # inherited (7e on #175)
            return thing

        @functools.wraps(thing)
        def test(self, *args, **kwargs):
            self.fail(message)
        return test
    return failing


def skip_dep(test, reason):
    """Inside a test: test.skipTest(reason), except that under REQUIRE_EMULATOR_DEPS=1 the test fails."""
    if required():
        test.fail(_failure(reason))
    test.skipTest(reason + HINT)
