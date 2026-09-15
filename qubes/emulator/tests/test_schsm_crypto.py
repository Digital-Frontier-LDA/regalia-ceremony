#!/usr/bin/env python3
"""Adversarial crypto tests for the sc-hsm-tool DKEK key-wrap model.

It is only a throwaway emulator, but a key-wrap that is a two-time pad (deterministic
keystream + key reused for cipher and MAC) is the kind of thing a reviewer rightly flags,
and it would let an observer of two wrapped keys recover their XOR. These tests lock in:
round-trip, NOT-a-two-time-pad, authenticated (tamper-evident), and wrong-DKEK rejection.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

_path = os.path.join(os.path.dirname(__file__), "..", "bin", "sc-hsm-tool")
_loader = importlib.machinery.SourceFileLoader("schsm", _path)  # extension-less script
_spec = importlib.util.spec_from_loader("schsm", _loader)
schsm = importlib.util.module_from_spec(_spec)
_loader.exec_module(schsm)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class TestDkekWrap(unittest.TestCase):
    def setUp(self):
        self.dkek = bytes(range(32))

    def test_roundtrip(self):
        pt = b"funding-key-material-0123456789AB"
        self.assertEqual(schsm._unwrap(self.dkek, schsm._wrap(self.dkek, pt)), pt)

    def test_not_a_two_time_pad(self):
        # two equal-length plaintexts wrapped under the SAME DKEK must not share a keystream
        pt1 = b"A" * 32
        pt2 = b"B" * 32
        c1 = schsm._wrap(self.dkek, pt1)
        c2 = schsm._wrap(self.dkek, pt2)
        # locate ciphertext bodies (skip magic+nonce+len header, drop the 32-byte tag)
        body1 = c1[27:-32]
        body2 = c2[27:-32]
        self.assertEqual(len(body1), len(body2))
        # if it were a two-time pad, ct1^ct2 would equal pt1^pt2 — assert it does NOT
        self.assertNotEqual(xor(body1, body2), xor(pt1, pt2),
                            "wrap is a two-time pad: ct1^ct2 == pt1^pt2")

    def test_distinct_nonce_per_wrap(self):
        c1 = schsm._wrap(self.dkek, b"same-plaintext-xx")
        c2 = schsm._wrap(self.dkek, b"same-plaintext-xx")
        self.assertNotEqual(c1, c2, "same plaintext wrapped twice produced identical blobs (no nonce)")

    def test_tamper_is_detected(self):
        blob = bytearray(schsm._wrap(self.dkek, b"important-key"))
        blob[30] ^= 0x01            # flip a ciphertext byte
        with self.assertRaises(ValueError):
            schsm._unwrap(self.dkek, bytes(blob))

    def test_wrong_dkek_rejected(self):
        blob = schsm._wrap(self.dkek, b"important-key")
        with self.assertRaises(ValueError):
            schsm._unwrap(bytes([0xFF] * 32), blob)

    def test_cipher_key_differs_from_mac_key(self):
        # both subkeys derive from the DKEK+nonce but with different labels -> different keys
        nonce = b"\x00" * 16
        self.assertNotEqual(schsm._derive(self.dkek, nonce, b"enc"),
                            schsm._derive(self.dkek, nonce, b"mac"))


def _share_output(threshold, total, path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        schsm.create_dkek_share(path, threshold, total)
    return out.getvalue()


def _feed(created, positions, blank_lines=True):
    """The stdin OpenSC's --pwd-shares-total import reads: the prime, then for each share one
    blank line (its "Press <enter>"), the share ID and the share value."""
    prime = re.search(r"^Prime +: *([0-9a-f:]+)$", created, re.M).group(1)
    ids = re.findall(r"^Share ID +: *([0-9]+)$", created, re.M)
    values = re.findall(r"^Share value +: *([0-9a-f:]+)$", created, re.M)
    lines = [prime]
    for position in positions:
        lines += ([""] if blank_lines else []) + [ids[position - 1], values[position - 1]]
    return "\n".join(lines) + "\n"


def _import(path, stdin, shares_total):
    out, err = io.StringIO(), io.StringIO()
    code = None
    with mock.patch("sys.stdin", io.StringIO(stdin)), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            schsm.import_dkek_share(path, None, shares_total)
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


class _StateDirs(unittest.TestCase):
    def setUp(self):
        self._old_state = schsm.STATE
        self.orig = tempfile.mkdtemp()
        self.restore = tempfile.mkdtemp()
        schsm.STATE = self.orig
        self._env = mock.patch.dict(os.environ)
        self._env.start()
        os.environ.pop("EMU_SCHSM_PWD_LEADING_BYTE", None)

    def tearDown(self):
        self._env.stop()
        schsm.STATE = self._old_state
        shutil.rmtree(self.orig, ignore_errors=True)
        shutil.rmtree(self.restore, ignore_errors=True)


class TestDkekImportIdempotency(_StateDirs):
    """A re-run of --import-dkek-share on an already-imported share must never
    silently corrupt (XOR-cancel to zero) the active DKEK. Doing so would make every
    key previously wrapped under that DKEK permanently unrecoverable — with the tool
    still reporting 'DKEK complete and active'. This is set-once, real-money material."""

    def test_reimport_same_share_does_not_corrupt_active_dkek(self):
        share = os.path.join(self.orig, "d.pbe")
        wrapped = os.path.join(self.orig, "wrapped.bin")
        created = _share_output(2, 3, share)
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.initialize(1, "test-idempotency")
        code, out, err = _import(share, _feed(created, [1, 2]), 2)
        self.assertIsNone(code, err)
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.wrap_key(wrapped, "1")
            schsm.unwrap_key(wrapped, "1")  # sanity: the DKEK-backed backup unwraps

        # Operator is unsure the first import took, so they re-run the SAME share.
        # A loud refusal (SystemExit) is acceptable; a silent DKEK corruption is not.
        code, reimport_out, _ = _import(share, _feed(created, [1, 2]), 2)
        self.assertIsNotNone(code, "re-importing an already-imported share did not refuse")
        self.assertNotIn("DKEK complete and active", reimport_out,
                         "re-importing an already-imported share falsely reported success")

        # The previously-wrapped key MUST still unwrap — i.e. the active DKEK survived.
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.unwrap_key(wrapped, "1")


class TestDkekOfflineRestore(_StateDirs):
    """Disaster recovery on a FRESH machine/qube: the only surviving inputs are the
    backed-up DKEK-share blob and the custodians' password shares. Nothing from creation
    survives on the host. The restore must rebuild the password from the shares, decrypt
    the blob, activate the DKEK, and unwrap the funding-key backup. If it cannot, the HSM
    backup is not recoverable offline and the whole drill is a fiction."""

    def test_offline_restore_from_shares_unwraps_backup(self):
        share_blob = os.path.join(self.orig, "d.pbe")
        wrapped = os.path.join(self.orig, "funding-key.wrapped")

        # --- original machine: create the share, activate the DKEK, wrap the funding key ---
        created = _share_output(4, 6, share_blob)
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.initialize(1, "akash-funding")
        code, _, err = _import(share_blob, _feed(created, [1, 2, 3, 4]), 4)
        self.assertIsNone(code, err)
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.wrap_key(wrapped, "1")

        # --- fresh machine: only the blob and the printed shares survive ---
        restore_blob = os.path.join(self.restore, "d.pbe")
        shutil.copyfile(share_blob, restore_blob)
        schsm.STATE = self.restore
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.initialize(1, "akash-funding")
        # a DIFFERENT quorum from the one used at creation
        code, restore_out, err = _import(restore_blob, _feed(created, [3, 4, 5, 6]), 4)
        self.assertIsNone(code, err)
        self.assertIn("DKEK complete and active", restore_out,
                      "offline restore did not activate the DKEK from the password shares")
        unwrap_out = io.StringIO()
        with contextlib.redirect_stdout(unwrap_out):
            schsm.unwrap_key(wrapped, "1")          # must recover the backed-up bytes
        self.assertIn("HSM-KEYREF-1", unwrap_out.getvalue(),
                      "offline restore could not unwrap the funding-key backup")

    def test_import_refuses_when_no_password_recoverable(self):
        """The same fresh restore WITHOUT --pwd-shares-total. OpenSC then asks for a typed
        password, which no custodian has ever seen, so the import must fail loudly and never
        claim 'DKEK complete and active'. Also proves creation left nothing on the host that
        could open the share instead."""
        share_blob = os.path.join(self.orig, "d.pbe")
        created = _share_output(4, 6, share_blob)
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.initialize(1, "akash-funding")
        code, out, err = _import(share_blob, _feed(created, [1, 2, 3, 4]), None)
        self.assertEqual(code, 1)
        self.assertIn("Error decrypting DKEK share", err)
        self.assertNotIn("DKEK complete and active", out,
                         "claimed a successful import with no recovered DKEK material")


class TestOpenScPasswordShares(_StateDirs):
    """The password-share path as OpenSC 0.27.1 runs it (#464): its share format, its
    stdin protocol, its argument checks, and the leading-zero drop."""

    def _fresh_card(self):
        with contextlib.redirect_stdout(io.StringIO()):
            schsm.initialize(1, "akash-funding")

    def test_share_output_is_openscs_format(self):
        created = _share_output(4, 6, os.path.join(self.orig, "d.pbe"))
        self.assertEqual(len(re.findall(r"^Prime       : [0-9a-f]{2}(:[0-9a-f]{2}){7}$", created, re.M)), 6)
        self.assertEqual(re.findall(r"^Share ID    : ([0-9]+)$", created, re.M),
                         ["1", "2", "3", "4", "5", "6"])
        self.assertEqual(len(re.findall(r"^Share value : [0-9a-f:]+$", created, re.M)), 6)

    def test_nothing_is_stashed_at_creation(self):
        _share_output(4, 6, os.path.join(self.orig, "d.pbe"))
        self.assertEqual(os.listdir(self.orig), ["d.pbe"])

    def test_the_password_is_eight_bytes_below_two_to_the_63(self):
        os.environ["EMU_SCHSM_PWD_LEADING_BYTE"] = "random"
        with mock.patch.object(schsm.secrets, "token_bytes", return_value=b"\xff" * 8):
            self.assertEqual(schsm._share_password(), b"\x7f" + b"\xff" * 7)

    def test_fewer_shares_than_the_threshold_are_refused(self):
        share = os.path.join(self.orig, "d.pbe")
        created = _share_output(4, 6, share)
        self._fresh_card()
        code, out, err = _import(share, _feed(created, [1, 2, 3]), 3)
        self.assertEqual(code, 1)
        self.assertIn("Error decrypting DKEK share", err)
        self.assertNotIn("DKEK complete and active", out)

    def test_each_share_needs_its_enter_line(self):
        share = os.path.join(self.orig, "d.pbe")
        created = _share_output(4, 6, share)
        self._fresh_card()
        code, out, err = _import(share, _feed(created, [1, 2, 3, 4], blank_lines=False), 4)
        self.assertEqual(code, 1)
        self.assertIn("Input aborted", err)
        self.assertNotIn("DKEK complete and active", out)

    def test_a_leading_zero_password_is_refused_with_its_correct_shares(self):
        os.environ["EMU_SCHSM_PWD_LEADING_BYTE"] = "zero"
        share = os.path.join(self.orig, "d.pbe")
        created = _share_output(4, 6, share)
        self._fresh_card()
        code, out, err = _import(share, _feed(created, [1, 2, 3, 4]), 4)
        self.assertEqual(code, 1)
        self.assertIn("Error decrypting DKEK share", err)
        self.assertNotIn("DKEK complete and active", out)

    def test_the_first_byte_modes(self):
        # A zero draw is the 1-in-128 case: the default keeps rehearsals deterministic, "zero"
        # forces it, "random" passes the real tool's draw through.
        with mock.patch.object(schsm.secrets, "token_bytes", return_value=b"\x00" * 8):
            self.assertNotEqual(schsm._share_password()[0], 0)
            os.environ["EMU_SCHSM_PWD_LEADING_BYTE"] = "random"
            self.assertEqual(schsm._share_password()[0], 0)
        with mock.patch.object(schsm.secrets, "token_bytes", return_value=b"\x42" * 8):
            os.environ["EMU_SCHSM_PWD_LEADING_BYTE"] = "zero"
            self.assertEqual(schsm._share_password(), b"\x00" + b"\x42" * 7)

    def test_the_minimal_encoding_drops_leading_zero_bytes(self):
        self.assertEqual(schsm._minimal_bytes(int.from_bytes(bytes([0, 0, 5, 6]), "big")), bytes([5, 6]))
        self.assertEqual(schsm._minimal_bytes(0), b"")

    def test_reconstruction_recovers_the_secret_from_any_quorum(self):
        value = int.from_bytes(bytes(range(1, 9)), "big")
        prime, shares = schsm._split(value, 4, 6)
        self.assertTrue(prime > value and prime.bit_length() == 64 and schsm._probable_prime(prime))
        for quorum in ([0, 1, 2, 3], [2, 3, 4, 5], [0, 2, 3, 5]):
            self.assertEqual(schsm._reconstruct(prime, [shares[i] for i in quorum]), value)
        self.assertNotEqual(schsm._reconstruct(prime, shares[:3]), value)

    def test_create_refuses_what_opensc_refuses(self):
        path = os.path.join(self.orig, "x.pbe")
        for threshold, total, message in ((4, None, "Must specify both"),
                                          (None, 6, "Must specify both"),
                                          (2, 2, "--pwd-shares-total must be 3 or larger"),
                                          (1, 3, "--pwd-shares-threshold must 2 or larger"),
                                          (5, 4, "--pwd-shares-threshold must be smaller or equal")):
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit):
                schsm.create_dkek_share(path, threshold, total)
            self.assertIn(message, err.getvalue(), (threshold, total))
            self.assertFalse(os.path.exists(path), (threshold, total))

    def test_reconstruction_refuses_what_cannot_be_interpolated(self):
        _, shares = schsm._split(0x1234, 2, 3)
        self.assertIsNone(schsm._reconstruct(0, shares[:2]))
        self.assertIsNone(schsm._reconstruct(1, shares[:2]))
        self.assertIsNone(schsm._reconstruct(2**61 - 1, [shares[0], shares[0]]))

    def test_malformed_share_input_is_refused_not_crashed(self):
        share = os.path.join(self.orig, "d.pbe")
        created = _share_output(4, 6, share)
        self._fresh_card()
        feed = _feed(created, [1, 2, 3, 4]).split("\n")
        feed[0] = "not-a-prime"
        feed[3] = "zz:zz"  # the first share value
        code, out, err = _import(share, "\n".join(feed), 4)
        self.assertEqual(code, 1)
        self.assertNotIn("DKEK complete and active", out)

    def test_a_share_id_reads_as_openssl_reads_it(self):
        self.assertEqual(schsm._share_id_in("3\n"), 3)
        self.assertEqual(schsm._share_id_in("10 trailing"), 16)  # BN_hex2bn: hex, leading digits
        self.assertEqual(schsm._share_id_in("\n"), 0)

    def test_password_wins_over_shares_as_in_opensc(self):
        # OpenSC's import consults --password before --pwd-shares-total. A password-share file
        # given a --password is opened with that password, and the shares are never read.
        share = os.path.join(self.orig, "d.pbe")
        created = _share_output(4, 6, share)
        self._fresh_card()
        with mock.patch("sys.stdin", io.StringIO(_feed(created, [1, 2, 3, 4]))), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            schsm.import_dkek_share(share, "not-the-password", 4)
        self.assertIn("Error decrypting DKEK share", err.getvalue())
        self.assertNotIn("DKEK complete and active", out.getvalue())

    def test_create_with_no_password_and_no_share_flags_is_not_modelled(self):
        path = os.path.join(self.orig, "x.pbe")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            schsm.create_dkek_share(path, None, None)
        self.assertIn("prompts for a typed password", str(raised.exception.code))
        self.assertFalse(os.path.exists(path))

    def test_an_unknown_first_byte_mode_is_refused(self):
        os.environ["EMU_SCHSM_PWD_LEADING_BYTE"] = "sometimes"
        with self.assertRaises(SystemExit):
            schsm._share_password()


if __name__ == "__main__":
    unittest.main(verbosity=2)
