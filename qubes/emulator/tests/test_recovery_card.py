#!/usr/bin/env python3
"""The printed break-glass recovery card must match the custody that was ACTUALLY performed.

Option B (the chosen custody, ceremony.sh step_hsm_funding is SKIPPED) backs the FUNDING
seed up as SLIP-39 word-shares with NO HSM. The card therefore must tell a break-glass
operator to recover the funding seed with `bip39-slip39-backup.py --recover` from 4 SLIP-39
shares — NOT to rebuild a Nitrokey HSM from a `.pbe` DKEK + `sc-hsm-tool --unwrap-key`,
because under Option B those artifacts were never created. It also must not hand the operator
raw `shamir recover` (which emits hex entropy, not the BIP39 wallet mnemonic a wallet needs).

These tests pin the card's text (build_lines) to the documented recovery runbook
(recovery/RECOVERY-TECHNICAL.md lines 46-49).
"""
import importlib.machinery
import importlib.util
import os
import re
import unittest

_SCRIPTS = os.environ.get("CEREMONY_SCRIPTS") or os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
_path = os.path.join(_SCRIPTS, "make-recovery-card.py")
_loader = importlib.machinery.SourceFileLoader("make_recovery_card", _path)
_spec = importlib.util.spec_from_loader("make_recovery_card", _loader)
mrc = importlib.util.module_from_spec(_spec)
_loader.exec_module(mrc)


def card_text(**kw):
    return "\n".join(text for (text, _f, _s, _g) in mrc.build_lines("2026-06-30", **kw))


class TestRecoveryCardOptionB(unittest.TestCase):
    def test_funding_seed_recovered_from_slip39_no_hsm(self):
        t = card_text()
        # the funding seed recovery is the central NO-HSM guarantee of the chosen custody
        self.assertIn("bip39-slip39-backup.py --recover", t,
                      "card must instruct the documented funding-seed recovery tool")
        self.assertIn("funding", t.lower(),
                      "card must name the funding seed as recoverable")

    def test_no_dead_hsm_artifacts_by_default(self):
        # under Option B no .pbe DKEK / wrapped key / HSM exist — pointing at them strands funds
        t = card_text().lower()
        for dead in ("sc-hsm-tool --unwrap-key", ".pbe", "nitrokey hsm", "import dkek", "unwrap-key"):
            self.assertNotIn(dead.lower(), t,
                             "default (Option B) card must not reference the never-created HSM/DKEK path: %r" % dead)

    def test_no_raw_shamir_recover_step(self):
        # raw `shamir recover` emits hex entropy, not the BIP39 mnemonic a wallet needs
        self.assertNotIn("shamir recover", card_text(),
                         "card must not hand the operator raw `shamir recover` for a wallet seed")

    def test_funding_and_derivation_shares_are_distinguished(self):
        t = card_text().lower()
        self.assertIn("funding", t)
        self.assertIn("derivation", t)

    def test_hsm_path_only_when_that_path_was_performed(self):
        # the optional HSM signer path may only appear when it was actually used (flag set)
        t = card_text(hsm_funding=True).lower()
        self.assertIn("sc-hsm-tool --unwrap-key", t,
                      "with the HSM path performed, the card should describe the HSM unwrap")

    def test_hsm_card_has_no_seed_recovery_steps(self):
        # Born-in-HSM custody (RECOVERY-TECHNICAL.md 3B): the funding key has NO SLIP-39
        # word-shares and NO plaintext mnemonic. A card that still tells the operator to
        # recover from `funding-shares.txt` (step 2) or to verify a `funding.mnemonic` file
        # (step 6) hands them two IMPOSSIBLE steps and contradicts the inserted HSM block.
        t = card_text(hsm_funding=True)
        self.assertNotIn("funding-shares.txt", t,
                         "HSM card must not point at non-existent funding SLIP-39 shares")
        self.assertNotIn("mnemonic-file funding.mnemonic", t,
                         "HSM card must not verify a never-created funding.mnemonic file")
        # the funding-key restore (money path) must be the DKEK/unwrap flow
        self.assertIn("funding-wrapped.bin", t,
                      "HSM card step 2 must restore the funding key from the DKEK-wrapped blob")
        # and the address verify must use the exported public key, per RECOVERY-TECHNICAL.md 3B
        self.assertIn("derive-akash-address.py --der funding-pub.der", t,
                      "HSM card step 6 must verify via the exported funding pubkey (.der)")


class TestRecoveryCardSopsDecrypt(unittest.TestCase):
    """The vault-decrypt step must be a command that actually works when typed literally.

    SOPS_AGE_KEY_FILE is a FILESYSTEM PATH; the recovered breakglass key (from
    `ssss-combine -t 4`) is a VALUE (AGE-SECRET-KEY-1...). Passing the value to the
    *_FILE env var makes SOPS try to open a file literally named 'AGE-SECRET-KEY-1...'
    which does not exist -> decrypt fails. The key VALUE must go through SOPS_AGE_KEY.
    """

    def test_card_sops_decrypt_uses_key_value_env_not_file_path(self):
        t = card_text()
        self.assertNotIn("SOPS_AGE_KEY_FILE=<key>", t,
                         "card must not pass the recovered age key VALUE to the FILE-path env var")
        self.assertIn("SOPS_AGE_KEY=<key>", t,
                      "card must pass the recovered age key value via SOPS_AGE_KEY")


class TestRecoveryRunbookSopsDecrypt(unittest.TestCase):
    """The RECOVERY-TECHNICAL.md runbook step 6 has the same must-run-as-written contract."""

    def _md(self):
        # recovery/ is a sibling of scripts/ (repo and baked image); resolve via CEREMONY_SCRIPTS.
        recovery = os.environ.get("CEREMONY_RECOVERY") or os.path.join(_SCRIPTS, "..", "recovery")
        with open(os.path.join(recovery, "RECOVERY-TECHNICAL.md")) as f:
            return f.read()

    def test_runbook_sops_decrypt_uses_key_value_env_not_file_path(self):
        t = self._md()
        self.assertNotIn("SOPS_AGE_KEY_FILE=<that key>", t,
                         "runbook must not pass the recovered age key VALUE to the FILE-path env var")
        self.assertIn("SOPS_AGE_KEY=<that key>", t,
                      "runbook must pass the recovered age key value via SOPS_AGE_KEY")


class TestRecoveryAddressAnchorLocation(unittest.TestCase):
    """The funding-address integrity anchor must be quoted to ONE consistent location.

    QUORUM-CONFIRMED DEFECT: the recovery card prints NO akash address — its own step 6 and
    ceremony.sh option c both record the funding address on the SEALED custodian-contact sheet
    (the seal registry). Yet the layperson sheet (RECOVERY-START-HERE.txt) and the technical
    runbook (RECOVERY-TECHNICAL.md) told the recoverer to compare the rebuilt wallet to "the
    address printed on the recovery card". A recoverer who inspects the card finds no address
    and may SKIP the only STOP-check that catches wrong shares / wrong passphrase / a tampered
    backup before moving real money. All four sources must agree the anchor lives on the sealed
    sheet, never on the (address-less) card.
    """

    def _recovery(self):
        return os.environ.get("CEREMONY_RECOVERY") or os.path.join(_SCRIPTS, "..", "recovery")

    def _read(self, name):
        with open(os.path.join(self._recovery(), name)) as f:
            return f.read()

    @staticmethod
    def _norm(s):
        return " ".join(s.split())

    def test_card_prints_no_funding_address(self):
        # the premise of the defect: the card is address-less, so no doc may send the
        # recoverer to it for the anchor. (build_lines takes no address; step 6 -> sealed sheet.)
        for kw in ({}, {"hsm_funding": True}):
            t = card_text(**kw)
            self.assertNotIn("akash1", t.lower(),
                             "recovery card must not print a funding address (it has no --funding-addr): %r" % kw)

    def test_layperson_sheet_anchors_the_address_to_the_sealed_sheet_not_the_card(self):
        norm = self._norm(self._read("RECOVERY-START-HERE.txt"))
        idx = norm.lower().find("matches the address")
        self.assertNotEqual(idx, -1, "RECOVERY-START-HERE.txt lost its integrity-anchor check")
        window = norm[idx:idx + 140].lower()
        self.assertNotIn("recovery card", window,
                         "layperson sheet sends the recoverer to the card for the funding address, "
                         "but the card prints none — the STOP-check gets skipped")
        self.assertIn("custodian-contact sheet", window,
                      "layperson sheet must anchor the address to the sealed custodian-contact sheet")

    def test_runbook_anchor_never_points_at_the_addressless_card(self):
        norm = self._norm(self._read("RECOVERY-TECHNICAL.md"))
        sites = re.findall(r"matches the address recorded on ([^.:]+)", norm)
        # both anchor comparisons exist (Section 3B pubkey form + Section 4 mnemonic form)
        self.assertGreaterEqual(len(sites), 2,
                                "runbook must keep both address-match STOP-checks (Section 3B + Section 4)")
        for loc in sites:
            self.assertNotIn("recovery card", loc.lower(),
                             "runbook anchor comparison points at the address-less recovery card "
                             "instead of the sealed custodian-contact sheet: %r" % loc)
            self.assertIn("sheet", loc.lower(),
                          "runbook anchor comparison must name the sealed custodian-contact sheet: %r" % loc)


class TestRecoveryCardLayoutFits(unittest.TestCase):
    """No recovery instruction may be drawn below the card cut-line.

    The card's %%BoundingBox is the cut rectangle. PostScript viewers/printers clip
    anything below it, so a text baseline below the bounding-box bottom is silently
    lost when the card is cut. This is real money, set-once: a break-glass operator
    who is handed a card missing steps 6-8 (verify addr / move funds / rotate) or the
    'AFTER: shut down' line can strand or expose the funds. emit() must fit the content
    or fail loudly — never emit a card with clipped recovery steps.
    """

    _TEXT_DRAW = re.compile(r"^([\d.]+)\s+([\d.]+)\s+moveto\s+\(.*\)\s+show$")

    def _bbox_bottom_and_baselines(self, ps):
        bbox_bottom = None
        baselines = []
        for line in ps.splitlines():
            if line.startswith("%%BoundingBox:"):
                # %%BoundingBox: x0 y0 x1 y1
                bbox_bottom = float(line.split()[2])
            mm = self._TEXT_DRAW.match(line)
            if mm:
                baselines.append(float(mm.group(2)))
        return bbox_bottom, baselines

    def test_default_card_keeps_all_text_inside_bounding_box(self):
        ps = mrc.emit(120.0, 180.0, "letter", "2026-06-30")
        bbox_bottom, baselines = self._bbox_bottom_and_baselines(ps)
        self.assertTrue(baselines, "expected some text on the card")
        self.assertGreaterEqual(
            min(baselines), bbox_bottom,
            "default card draws a recovery line below the cut-line (would be clipped)")

    def test_default_card_with_all_footers_fits(self):
        # the real ceremony sets --case-id/--seal-serial (and optionally --hsm-funding);
        # this is the densest legitimate card and must still fit at the default height.
        ps = mrc.emit(120.0, 180.0, "letter", "2026-06-30",
                      case_id="DF-BG-01", seal_serial="HOLO-9988", hsm_funding=True)
        bbox_bottom, baselines = self._bbox_bottom_and_baselines(ps)
        self.assertGreaterEqual(
            min(baselines), bbox_bottom,
            "densest default card overflows the cut-line (would be clipped)")

    def test_shrunk_card_fails_loudly_instead_of_clipping(self):
        # operator-settable --height-mm 150: content no longer fits. It must refuse,
        # not silently print a card whose last recovery lines fall below the cut-line.
        with self.assertRaises(SystemExit) as ctx:
            mrc.emit(120.0, 150.0, "letter", "2026-06-30")
        self.assertIn("height-mm", str(ctx.exception).lower(),
                      "the failure must tell the operator to raise --height-mm")


class TestRecoveryCardLayoutFitsHorizontally(unittest.TestCase):
    """No recovery instruction may run past the RIGHT (vertical) cut-line either.

    emit() guards the VERTICAL fit (nothing below the cut-line) but Courier is
    monospace and the text is left-anchored at `bx + margin`; a line wider than
    the card runs past the right dashed cut-guide and is physically sliced off
    when the operator cuts the card. `--width-mm` is an advertised operator knob,
    so a narrower keep-case (e.g. 95mm) silently amputates the tail of recovery
    commands — the funding.mnemonic filename / the `-o` output path — the exact
    'card handed over missing recovery steps' data-loss the vertical guard prevents.
    """

    _SETFONT = re.compile(r"^/\S+\s+findfont\s+([\d.]+)\s+scalefont\s+setfont$")
    _MOVETO_SHOW = re.compile(r"^([\d.]+)\s+([\d.]+)\s+moveto\s+\((.*)\)\s+show$")

    def _bbox_right_and_extents(self, ps):
        """Return (bbox_right, [rightmost x of each drawn glyph run]).

        Courier advance width is 0.6*size per char (600/1000 em). We recover the
        original character count from build_lines rather than the PostScript-escaped
        text so `\\(`, `\\)` and `\\\\` do not distort the width.
        """
        bbox_right = None
        cur_size = None
        extents = []
        for line in ps.splitlines():
            if line.startswith("%%BoundingBox:"):
                bbox_right = float(line.split()[3])
                continue
            fm = self._SETFONT.match(line)
            if fm:
                cur_size = float(fm.group(1))
                continue
            sm = self._MOVETO_SHOW.match(line)
            if sm:
                x = float(sm.group(1))
                # un-escape esc(): \\ -> \, \( -> (, \) -> )
                shown = re.sub(r"\\(.)", r"\1", sm.group(3))
                extents.append(x + len(shown) * 0.6 * cur_size)
        return bbox_right, extents

    def test_default_card_keeps_all_text_left_of_right_cut(self):
        ps = mrc.emit(120.0, 180.0, "letter", "2026-06-30",
                      case_id="DF-BG-01", seal_serial="HOLO-9988", hsm_funding=True)
        bbox_right, extents = self._bbox_right_and_extents(ps)
        self.assertTrue(extents, "expected some text on the card")
        self.assertLessEqual(
            max(extents), bbox_right,
            "default card draws a recovery line past the right cut-line (would be clipped)")

    def test_narrow_card_fails_loudly_instead_of_clipping_horizontally(self):
        # operator-settable --width-mm 95 (a plausible narrower keep-case). Vertical
        # room is ample (tall height) so ONLY the horizontal overflow is exercised: it
        # must refuse, not silently emit a card whose commands run past the right cut.
        with self.assertRaises(SystemExit) as ctx:
            mrc.emit(95.0, 300.0, "letter", "2026-06-30")
        self.assertIn("width-mm", str(ctx.exception).lower(),
                      "the failure must tell the operator to raise --width-mm")

    def test_narrow_hsm_card_fails_loudly_instead_of_clipping_horizontally(self):
        # the born-in-HSM path's `pkcs11-tool --read-object ... -o funding-pub.der`
        # is the widest line; a narrow card must refuse rather than slice off the path.
        with self.assertRaises(SystemExit) as ctx:
            mrc.emit(95.0, 300.0, "letter", "2026-06-30", hsm_funding=True)
        self.assertIn("width-mm", str(ctx.exception).lower(),
                      "the failure must tell the operator to raise --width-mm")


if __name__ == "__main__":
    unittest.main(verbosity=2)
