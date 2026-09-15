#!/usr/bin/env python3
"""Unit tests for the SLE4442 chip model (no pcscd needed — runs anywhere).

Drives the pseudo-APDU handler directly and asserts datasheet behaviour:
read, PSC gate on writes, wrong-PSC error-counter decrement + lockout, correct-PSC
counter restore, write-once protection bits, change-PSC, reset clears auth.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "sle4442_vpicc", os.path.join(os.path.dirname(__file__), "..", "bin", "sle4442-vpicc.py")
)
sle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sle)


def h(s):
    return bytes.fromhex(s.replace(" ", ""))


class TestSLE4442(unittest.TestCase):
    def setUp(self):
        self.card = sle.SLE4442(psc=b"\x12\x34\x56")

    def test_select_card_type(self):
        self.assertEqual(self.card.apdu(h("FF A4 00 00 01 06")), sle.SW_OK)
        # wrong card type rejected
        self.assertEqual(self.card.apdu(h("FF A4 00 00 01 05")), sle.SW_WRONG_P1P2)

    def test_read_main_memory(self):
        r = self.card.apdu(h("FF B0 00 00 06"))
        self.assertEqual(r[-2:], sle.SW_OK)
        self.assertEqual(r[:-2], h("A2 13 10 91 FF FF"))

    def test_read_security_memory_hides_psc(self):
        r = self.card.apdu(h("FF B1 00 00 04"))
        self.assertEqual(r, bytes([0x07, 0xFF, 0xFF, 0xFF]) + sle.SW_OK)

    def test_write_requires_auth(self):
        self.assertEqual(self.card.apdu(h("FF D0 00 20 01 AB")), sle.SW_NO_AUTH)

    def test_verify_then_write(self):
        self.assertEqual(self.card.apdu(h("FF 20 00 00 03 12 34 56")), sle.SW_OK)
        self.assertEqual(self.card.apdu(h("FF D0 00 20 03 DE AD BE")), sle.SW_OK)
        r = self.card.apdu(h("FF B0 00 20 03"))
        self.assertEqual(r, h("DE AD BE") + sle.SW_OK)

    def test_wrong_psc_decrements_counter(self):
        r = self.card.apdu(h("FF 20 00 00 03 00 00 00"))
        self.assertEqual(r[0], 0x63)
        self.assertEqual(r[1] & 0x0F, 2)  # 2 attempts left
        sec = self.card.apdu(h("FF B1 00 00 04"))
        self.assertEqual(sec[0], 0x03)  # 0b011 = two bits remaining

    def test_correct_psc_restores_counter(self):
        self.card.apdu(h("FF 20 00 00 03 00 00 00"))  # one wrong
        self.card.apdu(h("FF 20 00 00 03 12 34 56"))  # correct
        sec = self.card.apdu(h("FF B1 00 00 04"))
        self.assertEqual(sec[0], 0x07)  # restored to 3 attempts

    def test_lockout_after_three_wrong(self):
        for _ in range(3):
            self.card.apdu(h("FF 20 00 00 03 00 00 00"))
        self.assertEqual(self.card.apdu(h("FF 20 00 00 03 12 34 56")), sle.SW_LOCKED)
        # locked card cannot authenticate even with the right PSC
        self.assertEqual(self.card.apdu(h("FF D0 00 20 01 AB")), sle.SW_NO_AUTH)

    def test_protection_is_write_once(self):
        self.card.apdu(h("FF 20 00 00 03 12 34 56"))
        self.card.apdu(h("FF D0 00 00 01 7E"))   # write byte 0
        self.card.apdu(h("FF D1 00 00 01 00"))   # lock byte 0
        prot = self.card.apdu(h("FF B2 00 00 04"))
        self.assertEqual(prot[0] & 0x01, 0)      # bit 0 cleared = locked
        # a locked byte can no longer be written
        self.assertEqual(self.card.apdu(h("FF D0 00 00 01 99")), sle.SW_NO_AUTH)
        r = self.card.apdu(h("FF B0 00 00 01"))
        self.assertEqual(r[:-2], h("7E"))        # still the pre-lock value

    def test_change_psc(self):
        self.card.apdu(h("FF 20 00 00 03 12 34 56"))
        self.assertEqual(self.card.apdu(h("FF D2 00 00 03 AA BB CC")), sle.SW_OK)
        # old PSC now fails, new one works
        self.assertEqual(self.card.apdu(h("FF 20 00 00 03 12 34 56"))[0], 0x63)
        self.assertEqual(self.card.apdu(h("FF 20 00 00 03 AA BB CC")), sle.SW_OK)

    def test_reset_clears_auth(self):
        self.card.apdu(h("FF 20 00 00 03 12 34 56"))
        self.card.power_on_reset()
        self.assertEqual(self.card.apdu(h("FF D0 00 20 01 AB")), sle.SW_NO_AUTH)

    def test_write_honors_lc_not_trailing_bytes(self):
        # Lc=2 but 4 data bytes follow — a real card writes exactly Lc; we must too.
        self.card.apdu(h("FF 20 00 00 03 12 34 56"))
        self.card.apdu(h("FF D0 00 20 02 AA BB CC DD"))
        r = self.card.apdu(h("FF B0 00 20 04"))
        self.assertEqual(r, h("AA BB 00 00") + sle.SW_OK,
                         "wrote trailing bytes beyond Lc")

    def test_write_rejects_data_shorter_than_lc(self):
        self.card.apdu(h("FF 20 00 00 03 12 34 56"))
        self.assertEqual(self.card.apdu(h("FF D0 00 20 04 AA BB")), sle.SW_WRONG_LEN)

    def test_write_is_atomic_when_a_byte_is_locked(self):
        # locking byte 5, then writing bytes 4..6 must NOT partially write byte 4
        self.card.apdu(h("FF 20 00 00 03 12 34 56"))
        self.card.apdu(h("FF D0 00 04 01 7E"))   # set byte 4 to a known value
        self.card.apdu(h("FF D1 00 05 01 00"))   # lock byte 5
        before = self.card.apdu(h("FF B0 00 04 03"))[:-2]
        rv = self.card.apdu(h("FF D0 00 04 03 11 22 33"))   # 4 ok, 5 locked, 6 ok
        after = self.card.apdu(h("FF B0 00 04 03"))[:-2]
        self.assertEqual(rv, sle.SW_NO_AUTH)
        self.assertEqual(before, after, "a locked-byte write left a partial modification")

    def test_state_persists_across_instances(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        try:
            c1 = sle.SLE4442(psc=b"\x12\x34\x56", state_path=path)
            c1.apdu(h("FF 20 00 00 03 12 34 56"))
            c1.apdu(h("FF D0 00 40 04 CA FE BA BE"))
            c2 = sle.SLE4442(psc=b"\x12\x34\x56", state_path=path)  # reload
            r = c2.apdu(h("FF B0 00 40 04"))
            self.assertEqual(r, h("CA FE BA BE") + sle.SW_OK)
        finally:
            os.unlink(path)


class TestSecretLeak(unittest.TestCase):
    """Adversarial: secrets must NEVER reach the log. The card moves the PSC and whatever
    share/seed bytes you store; the per-APDU log line must redact all of them."""

    PSC_HEX = "a1b2c3"
    SHARE_HEX = "deadbeefcafe"   # stand-in for a stored Shamir share

    def test_log_never_contains_psc_on_verify(self):
        line = sle.log_line(h("FF 20 00 00 03 " + self.PSC_HEX), sle.SW_OK)
        self.assertNotIn(self.PSC_HEX, line.lower())
        self.assertIn("redacted", line)

    def test_log_never_contains_written_share(self):
        line = sle.log_line(h("FF D0 00 20 06 " + self.SHARE_HEX), sle.SW_OK)
        self.assertNotIn(self.SHARE_HEX, line.lower())
        self.assertIn("redacted", line)

    def test_log_never_contains_read_back_share(self):
        # a memory READ response carries the stored secret bytes + SW
        resp = h(self.SHARE_HEX) + sle.SW_OK
        line = sle.log_line(h("FF B0 00 20 06"), resp)
        self.assertNotIn(self.SHARE_HEX, line.lower())
        self.assertIn("9000", line.replace(" ", ""))   # status word still logged

    def test_log_never_contains_changed_psc(self):
        line = sle.log_line(h("FF D2 00 00 03 " + self.PSC_HEX), sle.SW_OK)
        self.assertNotIn(self.PSC_HEX, line.lower())

    def test_log_keeps_nonsecret_commands_readable(self):
        # SELECT / read-security / read-protection carry no secret — keep them legible
        self.assertIn("ffa4000001", sle.log_line(h("FF A4 00 00 01 06"), sle.SW_OK).lower().replace(" ", ""))
        sec = bytes([0x07, 0xFF, 0xFF, 0xFF]) + sle.SW_OK
        self.assertIn("07ffffff", sle.log_line(h("FF B1 00 00 04"), sec).lower().replace(" ", ""))

    def test_real_session_log_has_no_secret(self):
        # drive the actual logging sink used by _session and assert nothing leaks
        captured = []
        card = sle.SLE4442(psc=h(self.PSC_HEX))
        for apdu in ("FF A4 00 00 01 06", "FF 20 00 00 03 " + self.PSC_HEX,
                     "FF D0 00 20 06 " + self.SHARE_HEX, "FF B0 00 20 06"):
            captured.append(sle.log_line(h(apdu), card.apdu(h(apdu))))
        blob = " ".join(captured).lower()
        self.assertNotIn(self.PSC_HEX, blob)
        self.assertNotIn(self.SHARE_HEX, blob)

    def test_state_file_is_not_world_readable(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        try:
            c = sle.SLE4442(psc=h(self.PSC_HEX), state_path=path)
            c.apdu(h("FF 20 00 00 03 " + self.PSC_HEX))
            c.apdu(h("FF D0 00 20 06 " + self.SHARE_HEX))   # triggers a _save()
            mode = os.stat(path).st_mode & 0o077
            self.assertEqual(mode, 0, f"state file holding the share+PSC is group/world accessible (mode {oct(os.stat(path).st_mode & 0o777)})")
        finally:
            os.unlink(path)


def _load_manager_module():
    """Load bin/sle4442-manager with a faked smartcard layer (pyscard is absent on the native
    test host). Shared by the manager-level test classes below."""
    import types

    def to_bytes(s):
        s = s.replace(" ", "")
        return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]

    def to_hex_string(data):
        return " ".join(f"{b:02X}" for b in data)

    sc = types.ModuleType("smartcard")
    sc_system = types.ModuleType("smartcard.System")
    sc_util = types.ModuleType("smartcard.util")
    sc_system.readers = lambda: []
    sc_util.toBytes = to_bytes
    sc_util.toHexString = to_hex_string
    sc.System = sc_system
    sc.util = sc_util

    saved = {k: sys.modules.get(k) for k in ("smartcard", "smartcard.System", "smartcard.util")}
    sys.modules["smartcard"] = sc
    sys.modules["smartcard.System"] = sc_system
    sys.modules["smartcard.util"] = sc_util
    try:
        from importlib.machinery import SourceFileLoader

        loader = SourceFileLoader(
            "sle4442_manager",
            os.path.join(os.path.dirname(__file__), "..", "bin", "sle4442-manager"),
        )
        spec = importlib.util.spec_from_loader("sle4442_manager", loader)
        mgr = importlib.util.module_from_spec(spec)
        loader.exec_module(mgr)
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mgr


class TestManagerSecretOffArgv(unittest.TestCase):
    """The real secret payload (the share via --text / --hex) must get the SAME off-argv
    protection the far-less-sensitive PSC already has: resolvable from an env var or a file,
    and a warning (which never echoes the value) when it is passed directly on argv where
    `ps` / `/proc/<pid>/cmdline` / shell history can capture it."""

    SHARE_TEXT = "share-7-DO-NOT-LEAK-abandon ability able"
    SHARE_HEX = "deadbeefcafe"

    def _args(self, **kw):
        import argparse

        ns = argparse.Namespace(text=None, text_file=None, hex=None, hex_file=None)
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_text_resolves_from_env(self):
        mgr = _load_manager_module()
        os.environ["SLE4442_TEXT"] = self.SHARE_TEXT
        try:
            self.assertEqual(mgr.resolve_secret(self._args(), "text"), self.SHARE_TEXT)
        finally:
            os.environ.pop("SLE4442_TEXT", None)

    def test_hex_resolves_from_env(self):
        mgr = _load_manager_module()
        os.environ["SLE4442_HEX"] = self.SHARE_HEX
        try:
            self.assertEqual(mgr.resolve_secret(self._args(), "hex"), self.SHARE_HEX)
        finally:
            os.environ.pop("SLE4442_HEX", None)

    def test_text_resolves_from_file(self):
        mgr = _load_manager_module()
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(self.SHARE_TEXT + "\n")   # editors append a trailing newline
            path = tf.name
        try:
            self.assertEqual(mgr.resolve_secret(self._args(text_file=path), "text"), self.SHARE_TEXT)
        finally:
            os.unlink(path)

    def test_hex_resolves_from_file(self):
        mgr = _load_manager_module()
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(self.SHARE_HEX + "\n")
            path = tf.name
        try:
            self.assertEqual(mgr.resolve_secret(self._args(hex_file=path), "hex"), self.SHARE_HEX)
        finally:
            os.unlink(path)

    def test_argv_secret_warns_without_echoing_it(self):
        import contextlib
        import io

        mgr = _load_manager_module()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            val = mgr.resolve_secret(self._args(text=self.SHARE_TEXT), "text")
        msg = err.getvalue()
        self.assertEqual(val, self.SHARE_TEXT)          # still usable
        self.assertIn("WARNING", msg)                   # but the operator is warned
        self.assertNotIn(self.SHARE_TEXT, msg)          # and the warning never leaks the share
        self.assertNotIn(self.SHARE_TEXT[:12], msg)

    def test_env_preferred_over_argv(self):
        mgr = _load_manager_module()
        os.environ["SLE4442_TEXT"] = self.SHARE_TEXT
        try:
            self.assertEqual(
                mgr.resolve_secret(self._args(text="ignored-argv-value"), "text"), self.SHARE_TEXT
            )
        finally:
            os.environ.pop("SLE4442_TEXT", None)


class TestManagerStoreNoLeak(unittest.TestCase):
    """Adversarial: `sle4442-manager store` must NOT echo the stored secret payload (a
    Shamir share) back to stdout. It writes the share to the card and verify-reads it, but
    the only thing it prints must be non-secret status (byte count + address) — otherwise a
    tee/script log or screenshot of the ceremony leaks the whole share."""

    SHARE = "share-3-TOPSECRET-seed-do-not-leak"   # stand-in for a Shamir share text
    PSC_HEX = "FFFFFF"
    ADDR = 0x20

    def _load_manager(self):
        """Load bin/sle4442-manager with a faked smartcard layer (pyscard is absent on the
        native test host), wiring conn.transmit() straight into the real SLE4442 model."""
        import types

        def to_bytes(s):
            s = s.replace(" ", "")
            return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]

        def to_hex_string(data):
            return " ".join(f"{b:02X}" for b in data)

        sc = types.ModuleType("smartcard")
        sc_system = types.ModuleType("smartcard.System")
        sc_util = types.ModuleType("smartcard.util")
        sc_system.readers = lambda: []
        sc_util.toBytes = to_bytes
        sc_util.toHexString = to_hex_string
        sc.System = sc_system
        sc.util = sc_util

        saved = {k: sys.modules.get(k) for k in ("smartcard", "smartcard.System", "smartcard.util")}
        sys.modules["smartcard"] = sc
        sys.modules["smartcard.System"] = sc_system
        sys.modules["smartcard.util"] = sc_util
        try:
            from importlib.machinery import SourceFileLoader

            loader = SourceFileLoader(
                "sle4442_manager",
                os.path.join(os.path.dirname(__file__), "..", "bin", "sle4442-manager"),
            )
            spec = importlib.util.spec_from_loader("sle4442_manager", loader)
            mgr = importlib.util.module_from_spec(spec)
            loader.exec_module(mgr)
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        return mgr

    def _fake_conn(self, card):
        class FakeConn:
            def transmit(self, apdu_ints):
                resp = card.apdu(bytes(apdu_ints))
                return list(resp[:-2]), resp[-2], resp[-1]

            def disconnect(self):
                pass

        return FakeConn()

    def test_store_does_not_print_secret_payload(self):
        import contextlib
        import io

        mgr = self._load_manager()
        card = sle.SLE4442(psc=h(self.PSC_HEX))
        conn = self._fake_conn(card)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mgr.cmd_store(conn, self.PSC_HEX, self.ADDR, self.SHARE)
        out = buf.getvalue()

        # sanity: the store actually round-tripped to the card
        self.assertIn(str(len(self.SHARE.encode())), out)
        # the secret share text must NEVER appear on stdout
        self.assertNotIn(self.SHARE, out, "store leaked the full Shamir share to stdout")
        # not even a repr/quoted form of any meaningful run of the share
        self.assertNotIn(self.SHARE[:12], out, "store leaked (part of) the share to stdout")


class TestManagerWriteVerifiesReadBack(unittest.TestCase):
    """A `write` that stores a Shamir-share backup must READ IT BACK and fail loudly on any
    mismatch — never report success on the strength of the UPDATE status word alone. A
    faulty/weak EEPROM cell (or a hostile card) can ACK UPDATE MAIN MEMORY with SW=90 00 yet
    persist zeros/garbage; without a verify-read the operator believes the backup share is
    safely stored when the card is blank. This mirrors the guarantee `store` already gives."""

    SHARE_HEX = "deadbeefcafe"
    PSC_HEX = "FFFFFF"
    ADDR = 0x20

    def _load_manager(self):
        return _load_manager_module()

    def _healthy_conn(self, card):
        class FakeConn:
            def transmit(self, apdu_ints):
                resp = card.apdu(bytes(apdu_ints))
                return list(resp[:-2]), resp[-2], resp[-1]

            def disconnect(self):
                pass

        return FakeConn()

    def _dropping_conn(self, card):
        """A faulty/hostile card: ACKs UPDATE MAIN MEMORY (FF D0) with 90 00 but never
        persists the bytes. Every other APDU (SELECT / VERIFY / READ) is honoured, so a
        subsequent read-back returns the card's real (blank) contents."""

        class DroppingConn:
            def transmit(self, apdu_ints):
                apdu = bytes(apdu_ints)
                if apdu[:2] == b"\xFF\xD0":  # UPDATE MAIN MEMORY — ACK but drop the write
                    return [], 0x90, 0x00
                resp = card.apdu(apdu)
                return list(resp[:-2]), resp[-2], resp[-1]

            def disconnect(self):
                pass

        return DroppingConn()

    def test_write_fails_when_card_does_not_persist(self):
        import contextlib
        import io

        mgr = self._load_manager()
        card = sle.SLE4442(psc=h(self.PSC_HEX))
        conn = self._dropping_conn(card)

        buf = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(buf):
            mgr.cmd_write(conn, self.PSC_HEX, self.ADDR, self.SHARE_HEX)
        # must NOT have printed a bogus success line
        self.assertNotIn("wrote", buf.getvalue().lower())
        # and the failure message must not leak the share bytes
        self.assertNotIn(self.SHARE_HEX, str(ctx.exception).lower())

    def test_write_succeeds_and_verifies_on_healthy_card(self):
        import contextlib
        import io

        mgr = self._load_manager()
        card = sle.SLE4442(psc=h(self.PSC_HEX))
        conn = self._healthy_conn(card)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mgr.cmd_write(conn, self.PSC_HEX, self.ADDR, self.SHARE_HEX)
        out = buf.getvalue()
        # round-tripped: the bytes really are on the card
        self.assertEqual(bytes(card.main[self.ADDR:self.ADDR + 6]), bytes.fromhex(self.SHARE_HEX))
        # reports success by byte count/address, never the secret payload itself
        self.assertIn("6", out)
        self.assertNotIn(self.SHARE_HEX, out.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
