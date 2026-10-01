#!/usr/bin/env python3
"""pin-card-form.py — print a BLANK paper PIN card: the day-to-day PINs are written on it BY HAND.

  pin-card-form.py -o pin-card.ps                      # HSM A, B, C (10 digits) + YubiKey A, B, C (8)
  pin-card-form.py -o pin-card.ps --hsms a,b --yubikeys a --hsm-digits 10 --yubikey-digits 8 --paper a4

WHAT IT IS (owner, 2026-09-29; ADR-0002 D16): step 0 generates the day-to-day PINs and shows each
once; they are copied onto this card by hand, then typed back. The card is what carries each site's
HSM user PIN to that site's one-time TPM sealing (regalia-kms deploy/seal-hsm-pin.sh) and holds the
YubiKey PIN until it is memorised. The recovery credentials (SO-PINs, PUK, management key) are NEVER
written here: they exist only in the encrypted tier-0 payload.

The printer only ever sees this blank form: device names, empty digit boxes and the rules. The PINs,
and the serial numbers too, are written by hand (ADR-0002 D12).

PostScript only (no deps); prints on any CUPS queue.
"""
import argparse
import sys

PAPER = {"letter": (612.0, 792.0), "a4": (595.28, 841.89)}

RULES = [
    "RULES FOR THIS CARD",
    "- Write each PIN in pen, one digit per box, from the ceremony screen; the wizard then asks you to",
    "  type it back from THIS card. Never photograph, scan or type it into an online computer.",
    "- Seal it in a tamper-evident envelope right after the ceremony. Keep it APART from the tokens:",
    "  a token together with its PIN is usable. Never carry it in the same bag as a token in transit.",
    "- A broken seal means: assume the PINs are known and rotate them.",
    "- It is NOT the backup: every PIN is also in the encrypted recovery payload, which the Shamir",
    "  shares open. Losing this card costs a recovery step, not the keys.",
    "- Each site's HSM PIN is typed ONCE into that server's TPM (seal-hsm-pin.sh). Once every site is",
    "  sealed and the YubiKey PIN is memorised, the card may be destroyed (shredded, then burned).",
    "- Never write the SO-PINs, the PUK or the management key here.",
]


def esc(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def emit(hsms, yubikeys, hsm_digits, yk_digits, paper):
    W, H = PAPER[paper]
    m = 42.0
    out = ["%!PS-Adobe-3.0", "%%%%BoundingBox: 0 0 %d %d" % (W, H),
           "%%%%DocumentMedia: %s %d %d 0 () ()" % (paper, round(W), round(H)),
           "%%Pages: 1", "%%EndComments",
           "%%BeginSetup", "<< /PageSize [%.2f %.2f] >> setpagedevice" % (W, H), "%%EndSetup",
           "%%Page: 1 1", "0.8 setlinewidth"]

    def text(x, y, s, font="Helvetica", size=10):
        out.append("/%s findfont %g scalefont setfont %.1f %.1f moveto (%s) show" % (font, size, x, y, esc(s)))

    def box(x, y, w, h):
        out.append("%.1f %.1f %.1f %.1f rectstroke" % (x, y, w, h))

    def line(x1, y, x2):
        out.append("%.1f %.1f moveto %.1f %.1f lineto stroke" % (x1, y, x2, y))

    y = H - m - 6
    text(m, y, "PIN CARD - WRITE BY HAND, IN PEN", "Helvetica-Bold", 15)
    y -= 18
    text(m, y, "Day-to-day PINs only. This printed page held no PIN when printed.", "Helvetica", 9)
    y -= 16
    text(m, y, "Date:", "Helvetica-Bold", 9)
    line(m + 32, y - 2, m + 180)
    text(m + 200, y, "Written by (initials):", "Helvetica-Bold", 9)
    line(m + 305, y - 2, W - m)
    y -= 26

    rows = [("HSM %s - user PIN" % h.upper(), hsm_digits) for h in hsms] + \
           [("YubiKey %s - PIV PIN" % y.upper(), yk_digits) for y in yubikeys]
    cell = 20.0
    for label, digits in rows:
        text(m, y, label, "Helvetica-Bold", 10.5)
        text(m + 190, y, "Serial:", "Helvetica-Bold", 9)
        line(m + 225, y - 2, W - m)
        y -= 28
        for i in range(digits):
            box(m + i * (cell + 4), y, cell, 24)
        text(m + digits * (cell + 4) + 10, y + 8, "Typed back and matched: [  ]", "Helvetica", 9)
        y -= 22

    # The breakglass recipient's fingerprint: every later PIN escrow checks the repository's copy of
    # the public recipient against this handwritten value (CEREMONY-PLAN, "The PIN card").
    text(m, y, "Breakglass recipient - first 16 hex of sha256 (step 3 shows it):", "Helvetica-Bold", 10.5)
    y -= 28
    for i in range(16):
        box(m + i * (cell + 4), y, cell, 24)
    y -= 22

    # The escrow MAC key (step 0 shows it once): every later PIN escrow is authenticated with it, and
    # the escrow tool asks for it (CEREMONY-PLAN, "The PIN card"). Secret. This card is its only
    # human-readable copy; the encrypted tier-0 payload holds it too, for recovery from k shares.
    text(m, y, "ESCROW MAC KEY - 32 hex, two rows of 16 (step 0 shows it once):", "Helvetica-Bold", 10.5)
    for _ in range(2):
        y -= 28
        for i in range(16):
            box(m + i * (cell + 4), y, cell, 24)
    y -= 22

    lh = 11.0
    ib_h = lh * len(RULES) + 12
    if y < m + ib_h + 8:
        raise ValueError("%d rows do not fit above the rules on %s paper" % (len(rows), paper))
    box(m, m, W - 2 * m, ib_h)
    yy = m + ib_h - 14
    for ln in RULES:
        text(m + 8, yy, ln, "Helvetica-Bold" if ln.isupper() else "Helvetica", 8.5)
        yy -= lh
    out += ["showpage", "%%EOF"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--hsms", default="a,b,c", help="HSM letters, comma separated (default a,b,c)")
    ap.add_argument("--yubikeys", default="a,b,c", help="YubiKey letters, comma separated (default a,b,c)")
    ap.add_argument("--hsm-digits", type=int, default=10, help="HSM user PIN length (default 10)")
    ap.add_argument("--yubikey-digits", type=int, default=8, help="YubiKey PIN length (default 8)")
    ap.add_argument("--paper", choices=list(PAPER), default="letter")
    a = ap.parse_args()
    hsms = [h for h in a.hsms.split(",") if h]
    yubikeys = [y for y in a.yubikeys.split(",") if y]
    for name, lst in (("--hsms", hsms), ("--yubikeys", yubikeys)):
        if not lst or any(len(x) != 1 or not x.isalpha() for x in lst) or len(lst) > 3:
            sys.exit("pin-card-form: %s is 1-3 single letters, e.g. a,b,c" % name)
    if not 6 <= a.hsm_digits <= 16 or not 6 <= a.yubikey_digits <= 8:
        sys.exit("pin-card-form: HSM PINs are 6-16 digits, a YubiKey PIN 6-8")
    try:
        page = emit(hsms, yubikeys, a.hsm_digits, a.yubikey_digits, a.paper)
    except ValueError as exc:
        sys.exit("pin-card-form: %s; nothing written" % exc)
    with open(a.out, "w") as fh:
        fh.write(page)


if __name__ == "__main__":
    main()
