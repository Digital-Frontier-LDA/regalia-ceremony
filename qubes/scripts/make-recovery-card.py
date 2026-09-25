#!/usr/bin/env python3
"""Generate a print-ready BREAK-GLASS RECOVERY instruction card (PostScript).

The card carries the *procedure* for reconstructing the custodial wallet from the
Shamir shares + M-DISC — NO secrets. It prints with a dashed cut-guide + corner
crop marks sized to fit inside a standard DVD keep-case, so you print it, cut along
the line, and slip it in beside the M-DISC.

  make-recovery-card.py -o recovery-card.ps            # default 120x180mm card on Letter
  make-recovery-card.py --paper a4 --date 2026-06-29
  # then print on the ceremony's USB printer:
  lp -d <queue> recovery-card.ps

PostScript only (no deps); prints on any CUPS queue.
"""
import argparse
import datetime
import sys
import textwrap

PAPER = {"letter": (612.0, 792.0), "a4": (595.28, 841.89)}
MM = 2.834645669

def esc(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

# (text, font, size, gap_before_pt). Empty text = blank line. Lines are wrapped
# to fit the card width; keep them short so the card stays one cuttable sheet.
def build_lines(date: str, case_id: str = "", seal_serial: str = "", hsm_funding: bool = False):
    D = date or "____-__-__"
    body = [
        ("BREAK-GLASS RECOVERY", "Courier-Bold", 11, 0),
        ("Akash custodial wallet - Digital Frontier", "Courier", 7.5, 2),
    ]
    if case_id or seal_serial:
        body.append((("Case %s   Seal holo#: %s" % (case_id or "____", seal_serial or "________")),
                     "Courier-Bold", 8, 2))
        body.append(("Verify this serial matches the sticker on the case;", "Courier", 7, 0))
        body.append(("mismatch or broken seal => assume compromise, ROTATE.", "Courier", 7, 0))
    body += [
        ("", "Courier", 7.5, 0),
        ("IF THE OWNER IS INCAPACITATED: open the disc file", "Courier-Bold", 8, 2),
        ("RECOVERY-START-HERE.txt (plain English). Custodian", "Courier-Bold", 8, 0),
        ("list + executor = the SEALED sheet in this case.", "Courier-Bold", 8, 0),
        ("", "Courier", 7.5, 0),
        ("IN THIS CASE", "Courier-Bold", 8.5, 2),
        ("- 1x M-DISC: full recovery docs + toolkit + ciphertext.", "Courier", 7.5, 0),
        ("- This card; a sealed custodian-contact sheet.", "Courier", 7.5, 0),
        ("- Tamper seal: if broken, assume compromise, ROTATE.", "Courier", 7.5, 0),
        ("SCHEME 4-of-6: you need 4 of the 6 cases.", "Courier-Bold", 8, 2),
        ("Technical steps below + full RECOVERY-TECHNICAL.md on disc.", "Courier", 7, 0),
        ("", "Courier", 7.5, 0),
        ("OFFLINE / AIR-GAPPED ONLY (Qubes vault qube,", "Courier-Bold", 8, 2),
        ("netvm=none). NEVER on a networked machine.", "Courier-Bold", 8, 0),
        ("", "Courier", 7.5, 0),
        ("1. Gather >=4 of the 6 sealed cases' shares.", "Courier", 7.5, 1),
        ("   Metal plate? expand prefixes to words first:", "Courier", 7, 0),
        ("     metal-stamp-worksheet.py --verify", "Courier", 7, 0),]
    if hsm_funding:
        # Born-in-HSM funding custody (RECOVERY-TECHNICAL.md 3B). The funding key was born
        # NON-EXPORTABLE inside the Nitrokey HSM 2: it has NO SLIP-39 word-shares and NO
        # plaintext seed. Its only backup is the DKEK-wrapped blob + 4-of-6 DKEK password
        # shares, so step 2 must REPLACE the seed recovery with the DKEK/unwrap restore
        # (the seed path here would strand the operator on non-existent artifacts).
        body += [
            ("2. Funding KEY - the money - reborn in a FRESH HSM:", "Courier", 7.5, 1),
            ("     sc-hsm-tool --initialize --dkek-shares 1 \\", "Courier", 7, 0),
            ("       --label akash-funding   (blank spare HSM)", "Courier", 7, 0),
            ("     sc-hsm-tool --import-dkek-share dkek.pbe \\", "Courier", 7, 0),
            ("       --pwd-shares-total 4  (prompts prime/id/value)", "Courier", 7, 0),
            ("     sc-hsm-tool --unwrap-key funding-wrapped.bin \\", "Courier", 7, 0),
            ("       --key-reference 1   (key stays in HSM)", "Courier", 7, 0),
            ("     pkcs11-tool --read-object --type pubkey -o funding-pub.der", "Courier", 7, 0),]
    else:
        body += [
            ("2. Funding seed - the money - NO HSM needed:", "Courier", 7.5, 1),
            ("     bip39-slip39-backup.py --recover \\", "Courier", 7.5, 0),
            ("       --in funding-shares.txt   (4 SLIP-39)", "Courier", 7.5, 0),
            ("     -> funding BIP39 mnemonic; import to a wallet.", "Courier", 7.5, 0),]
    body += [
        ("3. Derivation root seed (its OWN 4 SLIP-39 shares):", "Courier", 7.5, 1),
        ("     bip39-slip39-backup.py --recover \\", "Courier", 7.5, 0),
        ("       --in derivation-shares.txt", "Courier", 7.5, 0),]
    body += [
        ("4. Breakglass age key (only to decrypt the vault):", "Courier", 7.5, 1),
        ("     ssss-combine -t 4   (paste 4 ssss shares)", "Courier", 7.5, 0),
        ("     -> AGE-SECRET-KEY-1... (recovery key)", "Courier", 7.5, 0),
        ("5. Decrypt vault with the recovered age key:", "Courier", 7.5, 1),
        ("     SOPS_AGE_KEY=<key> sops decrypt \\", "Courier", 7.5, 0),
        ("       example-service:infra/ansible/vault.sops.yaml", "Courier", 7.5, 0),
        ("6. Verify recovered addr == funding addr on sealed sheet:", "Courier", 7.5, 1),]
    if hsm_funding:
        # No funding.mnemonic exists in the born-in-HSM path; verify from the exported
        # public key instead (RECOVERY-TECHNICAL.md 3B, pubkey form).
        body += [
            ("     derive-akash-address.py --der funding-pub.der", "Courier", 7, 0),
            ("     (offline; mismatch => wrong DKEK/shares, STOP.)", "Courier", 7, 0),]
    else:
        body += [
            ("     derive-akash-address.py --mnemonic-file funding.mnemonic", "Courier", 7, 0),
            ("     (offline; mismatch => wrong shares/pass, STOP.)", "Courier", 7, 0),]
    body += [
        ("7. MOVE funds to the safe destination (sealed sheet).", "Courier", 7.5, 1),
        ("8. ROTATE all shares/keys - they were exposed.", "Courier", 7.5, 1),
        ("", "Courier", 7.5, 0),
        ("AFTER: shut down (wipes RAM); log the open + re-seal.", "Courier", 7.5, 1),
        ("Full runbook: RECOVERY-TECHNICAL.md on this disc.", "Courier", 7.5, 1),
        ("Generated %s. No secrets are printed on this card." % D, "Courier-Oblique", 6.5, 3),
    ]
    return body

def emit(width_mm, height_mm, paper, date, case_id="", seal_serial="", hsm_funding=False):
    pw, ph = PAPER[paper]
    cw, ch = width_mm * MM, height_mm * MM
    bx, by = (pw - cw) / 2.0, (ph - ch) / 2.0      # card box origin (centered)
    margin = 6 * MM
    tick = 5 * MM
    out = []
    a = out.append
    a("%!PS-Adobe-3.0")
    a("%%%%BoundingBox: %d %d %d %d" % (int(bx), int(by), int(bx + cw + 0.5), int(by + ch + 0.5)))
    a("%%Pages: 1")
    a("%%EndComments")
    a("%%Page: 1 1")
    # cut guide (dashed) + corner crop ticks
    a("0.5 setlinewidth [3 3] 0 setdash")
    a("newpath %.2f %.2f %.2f %.2f rectstroke" % (bx, by, cw, ch))
    a("[] 0 setdash 0.4 setlinewidth")
    for (cx, cy, dx, dy) in [
        (bx, by, -1, 0), (bx, by, 0, -1),
        (bx + cw, by, 1, 0), (bx + cw, by, 0, -1),
        (bx, by + ch, -1, 0), (bx, by + ch, 0, 1),
        (bx + cw, by + ch, 1, 0), (bx + cw, by + ch, 0, 1),
    ]:
        a("newpath %.2f %.2f moveto %.2f %.2f rlineto stroke" % (cx, cy, dx * tick, dy * tick))
    # text, top-down. Pre-place every line so we can refuse (rather than silently
    # clip) when the recovery instructions do not fit inside the card cut-line: the
    # %%BoundingBox bottom is `by`, and anything drawn below it is dropped by the
    # printer/viewer. A break-glass card missing its final steps can strand funds.
    descender = 2.0  # pt of headroom below the last baseline for glyph descenders
    y = by + ch - margin
    placements = []
    for text, font, size, gap in build_lines(date, case_id, seal_serial, hsm_funding):
        y -= gap
        y -= size * 1.25
        placements.append((text, font, size, y))
    drawn = [py for (text, _f, _s, py) in placements if text]
    last_baseline = min(drawn) if drawn else y
    if last_baseline - descender < by:
        top = by + ch - margin
        needed_mm = ((top - last_baseline) + margin + descender) / MM
        sys.exit(
            "make-recovery-card: recovery text does not fit the card and would be clipped "
            "below the cut-line (last line at %.1fpt, card bottom at %.1fpt). "
            "Increase --height-mm to >= %.0f (currently %.0f) or shorten the content; "
            "refusing to print a card with silently dropped recovery steps."
            % (last_baseline, by, needed_mm + 1, height_mm))
    # Horizontal fit: the text is left-anchored at `bx + margin` and Courier is
    # monospace (advance = 0.6*size per char), so a line wider than the card runs
    # past the RIGHT dashed cut-guide (stroked at the card box edge) and is sliced
    # off when the operator cuts the card. Mirror the vertical refusal — never emit
    # a card whose recovery commands (e.g. the funding.mnemonic filename or the `-o`
    # output path) extend past the cut rectangle and are silently amputated.
    avail = cw - 2 * margin
    widest = 0.0
    for text, _font, size, _py in placements:
        if not text:
            continue
        w = len(text) * 0.6 * size
        if w > widest:
            widest = w
    if widest > avail:
        needed_mm = (widest + 2 * margin) / MM
        sys.exit(
            "make-recovery-card: a recovery line is wider than the card and would be clipped "
            "past the right cut-line (widest line %.1fpt, available %.1fpt inside the margins). "
            "Increase --width-mm to >= %.0f (currently %.0f) or shorten the content; "
            "refusing to print a card with silently amputated recovery steps."
            % (widest, avail, needed_mm + 1, width_mm))
    for text, font, size, py in placements:
        if text:
            a("/%s findfont %.1f scalefont setfont" % (font, size))
            a("%.2f %.2f moveto (%s) show" % (bx + margin, py, esc(text)))
    a("showpage")
    return "\n".join(out) + "\n"

def main():
    ap = argparse.ArgumentParser(description="Generate a DVD-case-sized break-glass recovery card (PostScript).")
    ap.add_argument("-o", "--out", default="recovery-card.ps")
    ap.add_argument("--paper", choices=list(PAPER), default="letter")
    ap.add_argument("--width-mm", type=float, default=120.0, help="cut-card width (default 120mm, fits a DVD case)")
    ap.add_argument("--height-mm", type=float, default=180.0, help="cut-card height (default 180mm)")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--case-id", default="", help="case id printed on the card (e.g. DF-BG-01)")
    ap.add_argument("--seal-serial", default="", help="holographic sticker serial for this case")
    ap.add_argument("--hsm-funding", action="store_true",
                    help="ONLY if the optional Nitrokey HSM funding-signer path (step_hsm_funding) "
                         "was actually performed. Default (Option B) recovers the funding seed from "
                         "its SLIP-39 shares with no HSM.")
    a = ap.parse_args()
    ps = emit(a.width_mm, a.height_mm, a.paper, a.date, a.case_id, a.seal_serial, a.hsm_funding)
    with open(a.out, "w") as f:
        f.write(ps)
    print("wrote %s  (%gx%gmm cut card on %s)" % (a.out, a.width_mm, a.height_mm, a.paper))
    print("print it:  lp -d <queue> %s   (then cut along the dashed line)" % a.out)

if __name__ == "__main__":
    main()
