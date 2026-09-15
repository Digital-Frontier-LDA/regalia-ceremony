#!/usr/bin/env python3
"""The cross-profile equivalence instrument (#36) must be able to fail.

run-vector.py is run for real in two profiles by CI (the salt-provisioned vault-tools image in
ceremony-emulator.yml, the offline Debian bundle in offline-ceremony-bundle.yml), each compared with
expected.json. Those runs can only show agreement. These tests pin the other half: compare-vector.py
names a field that differs, is missing or is unexpected; its negative-control mode refuses a run
that was not actually perturbed, or that differs somewhere other than where the perturbation
reaches; and expected.json is anchored to values published elsewhere in the repository, not only
to the run that wrote it.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EQUIVALENCE = os.path.join(HERE, "..", "equivalence")
QUBES = os.path.join(HERE, "..", "..")

spec = importlib.util.spec_from_file_location("compare_vector", os.path.join(EQUIVALENCE, "compare-vector.py"))
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def load(name):
    with open(os.path.join(EQUIVALENCE, name)) as fh:
        return json.load(fh)


class CompareVector(unittest.TestCase):
    def setUp(self):
        self.expected = load("expected.json")
        self.tmp = tempfile.mkdtemp()

    def run_compare(self, actual, *extra, expected=None):
        paths = []
        for name, doc in (("expected.json", expected or self.expected), ("actual.json", actual)):
            paths.append(os.path.join(self.tmp, name))
            with open(paths[-1], "w") as fh:
                json.dump(doc, fh)
        out = io.StringIO()
        import sys
        argv = sys.argv
        sys.argv = ["compare-vector.py", *paths, *extra]
        try:
            with contextlib.redirect_stdout(out):
                try:
                    code = compare.main()
                except SystemExit as exit_:
                    code = exit_.code
        finally:
            sys.argv = argv
        return code, out.getvalue()

    def profile(self, label="test-profile"):
        actual = copy.deepcopy({k: self.expected[k] for k in ("deterministic", "semantic")})
        actual["transcript"] = {"profile": label}
        return actual

    def test_a_matching_profile_passes(self):
        code, out = self.run_compare(self.profile())
        self.assertEqual(code, 0, out)

    def test_a_changed_deterministic_output_is_named_with_both_values(self):
        actual = self.profile()
        actual["deterministic"]["bip39.akash_address"] = "akash1different"
        code, out = self.run_compare(actual)
        self.assertEqual(code, 1)
        self.assertIn("DIFFERS   deterministic.bip39.akash_address", out)
        self.assertIn("akash1different", out)

    def test_a_failed_semantic_check_is_named(self):
        actual = self.profile()
        actual["semantic"]["ssss.fresh_split_recovers_from_shares_3_to_6"] = False
        code, out = self.run_compare(actual)
        self.assertEqual(code, 1)
        self.assertIn("semantic.ssss.fresh_split_recovers_from_shares_3_to_6", out)

    def test_missing_and_unexpected_fields_are_named(self):
        actual = self.profile()
        del actual["deterministic"]["age.recipient"]
        actual["deterministic"]["something.new"] = "x"
        code, out = self.run_compare(actual)
        self.assertEqual(code, 1)
        self.assertIn("MISSING   deterministic.age.recipient", out)
        self.assertIn("UNEXPECTED deterministic.something.new", out)

    def test_the_transcript_is_never_compared(self):
        actual = self.profile()
        actual["transcript"]["qrencode"] = "some other build"
        code, out = self.run_compare(actual)
        self.assertEqual(code, 0, out)

    def test_the_negative_control_refuses_an_unperturbed_run(self):
        code, out = self.run_compare(self.profile(), "--must-differ", "bip39.akash_address")
        self.assertEqual(code, 1)
        self.assertIn("cannot tell the profiles apart", out)

    def test_the_negative_control_refuses_a_difference_in_the_wrong_field(self):
        actual = self.profile()
        actual["deterministic"]["qr.ascii_level_h_sha256"] = "0" * 64
        code, out = self.run_compare(actual, "--must-differ", "bip39.akash_address")
        self.assertEqual(code, 1)
        self.assertIn("not on bip39.akash_address", out)

    def test_the_negative_control_accepts_the_perturbed_field(self):
        actual = self.profile()
        actual["deterministic"]["bip39.akash_address"] = "akash1perturbed"
        code, out = self.run_compare(actual, "--must-differ", "bip39.akash_address")
        self.assertEqual(code, 0, out)

    def test_an_expected_file_that_pins_nothing_is_refused(self):
        code, _ = self.run_compare(self.profile(), expected={"deterministic": {}, "semantic": {}})
        self.assertNotEqual(code, 0)
        hollow = copy.deepcopy(self.expected)
        hollow["semantic"]["age.fresh_encryption_decrypts"] = False
        code, _ = self.run_compare(self.profile(), expected=hollow)
        self.assertNotEqual(code, 0)


class TheVectorIsAnchoredOutsideItself(unittest.TestCase):
    """expected.json was written by a run of run-vector.py. These tie its addresses to values the
    repository already publishes for the same inputs, so a wrong expected file cannot agree with
    itself into CI."""

    def test_the_bip39_address_is_the_one_the_pico_drill_runbook_publishes(self):
        runbook = open(os.path.join(QUBES, "PICO-DRILL-RUNBOOK.md")).read()
        published = re.search(r"expected address: \*\*`(akash1[0-9a-z]+)`\*\*", runbook).group(1)
        self.assertEqual(load("expected.json")["deterministic"]["bip39.akash_address"], published)
        self.assertEqual(load("vector.json")["bip39_mnemonic"], "abandon " * 11 + "about")

    def test_the_spki_address_is_prove_ceremonys_cosmjs_canonical_value(self):
        prove = open(os.path.join(QUBES, "scripts", "prove-ceremony.sh")).read()
        canonical = re.search(r'CANON="(akash1[0-9a-z]+)"', prove).group(1)
        der = re.search(r"DER=([0-9a-f]+)", prove).group(1)
        self.assertEqual(load("expected.json")["deterministic"]["spki.akash_address"], canonical)
        self.assertEqual(load("vector.json")["secp256k1_spki_der_hex"], der)

    def test_the_pkcs12_and_slip39_paths_reach_the_same_address(self):
        deterministic = load("expected.json")["deterministic"]
        address = deterministic["bip39.akash_address"]
        self.assertEqual(deterministic["pkcs12.akash_address"], address)
        self.assertEqual(deterministic["slip39.recover_1234.akash_address"], address)

    def test_the_inputs_say_what_they_are(self):
        self.assertIn("TEST VECTOR, NEVER CUSTODY MATERIAL", load("vector.json")["_notice"])
        self.assertIn("TEST VECTOR, NEVER CUSTODY MATERIAL", load("expected.json")["_notice"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
