#!/usr/bin/env python3
"""share-form.py — print a BLANK form that a Shamir share is written onto BY HAND.

  share-form.py --label "Wallet seed — SLIP-0039 share 3 of 6 (need 4)" --kind words --count 33 -o form.ps
  share-form.py --label "Breakglass age key — share 1 of 6 (need 4)" --kind chars --count 148 -o form.ps

WHY BLANK: the owner's rule (ADR-0002 D12, 2026-09-29) is that a printer never sees a Shamir
share: it keeps pages in memory, and a share is a quarter of the way to the secret. The printer
prints this empty form — title, numbered boxes, the case fields, the instructions — and the share
is copied into it by hand from the ceremony screen, then typed back to prove the copy.

THE PAGE (owner, 2026-09-29): a label saying what the sheet is; handwrite fields for the case ID,
seal serial, date, share number and initials (written at the ceremony, so the printer never sees
even those); the boxes for the share; and, at the foot of every page, instructions for whoever
holds the sheet later and for a recovery. The instructions are never dropped: a share too long to
fit above them is refused, and nothing is written.

The form carries NO secret: only the label, the number of boxes and fixed text. --count is the
share's length (its word count, or its character count), which is not secret either: every share
of a given kind has the same length.

PostScript only (no deps); prints on any CUPS queue.
"""
import argparse
import sys

PAPER = {"letter": (612.0, 792.0), "a4": (595.28, 841.89)}


def esc(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def ascii_only(s):
    # the standard PostScript fonts are Latin-1; keep the label printable as typed
    return s.replace("—", "-").replace("–", "-").encode("latin-1", "replace").decode("latin-1")


# The instruction block printed at the foot of every form. It is for whoever holds or finds the
# sheet later, not for the ceremony: what it is, what to do, and how a recovery goes.
# The holder's rule (owner, 2026-09-29): when, and ONLY when, to hand the share over. Remote
# requests are never enough, and an in-person request by the principal is checked against duress.
HOLDER = [
    "IF YOU HOLD THIS SHEET",
    "- This is ONE of {n} shares. Alone it reveals nothing; any {k} of them together rebuild the secret.",
    "- Keep it sealed in its case. Never open, copy, photograph, scan or type it anywhere.",
    "- If the seal is broken, or the sheet or case is lost, tell the executor at once.",
    "WHEN TO ACT - ONLY IN ONE OF THESE TWO CASES:",
    "1. You are shown the ORIGINAL official death certificate, or a legal certificate of incapacity, of the",
    "   principal named above, AND the executor asks you for this share IN PERSON.",
    "2. The principal named above asks you IN PERSON - never by phone, message, e-mail or video call.",
    "   Ask a question only the two of you know the answer to (agreed face to face, never written down).",
    "   If the answer is wrong, or they give the agreed DISTRESS answer, or seem forced, rushed or",
    "   watched: hand NOTHING over, say you need time, leave, and contact the police.",
    "In every other case, keep the case sealed. Nobody can authorize its release remotely.",
]
RECOVER = [
    "TO RECOVER (executor and operator)",
    "- Gather any {k} of the {n} cases. Check each seal serial against the seal registry before opening.",
    "- Follow the recovery card in this case and the recovery kit on its disc.",
    "- Type the shares ONLY into an offline (air-gapped) computer, never an online one.",
    "- Afterwards, move what the secret protects and make NEW shares: an opened share is spent.",
]


def emit(label, kind, count, paper, k=4, n=6):
    W, H = PAPER[paper]
    m = 42.0
    # The page size is declared, not assumed: without it a renderer uses its default (Letter), and
    # an A4 form lost its title off the top (rendered, 2026-09-29).
    out = ["%!PS-Adobe-3.0", "%%%%BoundingBox: 0 0 %d %d" % (W, H),
           "%%%%DocumentMedia: %s %d %d 0 () ()" % (paper, round(W), round(H)),
           "%%Pages: 1", "%%EndComments",
           "%%BeginSetup", "<< /PageSize [%.2f %.2f] >> setpagedevice" % (W, H), "%%EndSetup",
           "%%Page: 1 1", "0.8 setlinewidth"]

    def text(x, y, s, font="Helvetica", size=10):
        out.append("/%s findfont %g scalefont setfont %.1f %.1f moveto (%s) show"
                   % (font, size, x, y, esc(ascii_only(s))))

    def box(x, y, w, h):
        out.append("%.1f %.1f %.1f %.1f rectstroke" % (x, y, w, h))

    # ---- label: what the sheet is --------------------------------------------------------------
    y = H - m - 6
    text(m, y, "SHAMIR SHARE - WRITE BY HAND, IN PEN", "Helvetica-Bold", 15)
    y -= 20
    text(m, y, label, "Helvetica-Bold", 11)
    y -= 14
    text(m, y, "Share scheme: any %d of %d. This printed page held no secret when printed." % (k, n), "Helvetica", 8.5)
    y -= 10

    # ---- handwrite fields: filled in by hand at the ceremony, so the printer never sees them ------
    # The principal's name is hand-written too: the printer never sees whose share this is.
    fields = [("Principal (full name)",), ("Case ID", "Seal serial"), ("Date sealed", "Share number"),
              ("Written by (initials)", "Witness (initials)")]
    fh, fw = 22.0, (W - 2 * m) / 2
    top = y - 4
    box(m, top - fh * len(fields) - 6, W - 2 * m, fh * len(fields) + 6)
    for r, pair in enumerate(fields):
        if len(pair) == 1:                       # one field across the whole width
            x, yy = m + 6, top - (r + 1) * fh + 4
            text(x, yy + 2, pair[0] + ":", "Helvetica-Bold", 8.5)
            out.append("%.1f %.1f moveto %.1f %.1f lineto stroke" % (x + 105, yy, W - m - 12, yy))
            continue
        for c, name in enumerate(pair):
            x, yy = m + 6 + c * fw, top - (r + 1) * fh + 4
            text(x, yy + 2, name + ":", "Helvetica-Bold", 8.5)
            out.append("%.1f %.1f moveto %.1f %.1f lineto stroke" % (x + 105, yy, x + fw - 12, yy))
    y = top - fh * len(fields) - 6 - 16
    text(m, y, "Copied from the ceremony screen, then typed back and matched:  [   ] yes", "Helvetica-Bold", 8.5)
    y -= 12

    # ---- the instruction block sits at the foot of the page and is ALWAYS printed ---------------
    lines = [ln.format(k=k, n=n) for ln in HOLDER] + [""] + [ln.format(k=k, n=n) for ln in RECOVER]
    lh = 11.0
    ib_h = lh * len(lines) + 12
    ib_top = m + ib_h

    # ---- the boxes for the share ---------------------------------------------------------------
    if kind == "words":
        cols, box_h = 3, 24.0
        rows = -(-count // cols)
        col_w = (W - 2 * m) / cols
        need_bottom = y - rows * box_h
        if need_bottom < ib_top + 8:
            raise ValueError("%d words do not fit above the instructions on %s paper" % (count, paper))
        for i in range(count):
            r, c = i // cols, i % cols           # numbered left-to-right, like the screen shows them
            x, top = m + c * col_w, y - r * box_h
            text(x, top - 15, "%2d" % (i + 1), "Helvetica-Bold", 9)
            box(x + 20, top - 20, col_w - 30, 19)
    else:
        group, cell = 4, 14.5                     # groups of 4 characters
        gw = group * cell + 10
        per_row = max(1, int((W - 2 * m - 24 + 10) // gw))   # as many groups as fit this paper width
        groups = -(-count // group)
        rows = -(-groups // per_row)
        need_bottom = y - rows * 30
        if need_bottom < ib_top + 8:
            raise ValueError("%d characters do not fit above the instructions on %s paper" % (count, paper))
        for g in range(groups):
            r, c = g // per_row, g % per_row
            x, top = m + 24 + c * gw, y - r * 30
            if c == 0:
                text(m, top - 15, "%3d" % (g * group + 1), "Helvetica-Bold", 8)
            for j in range(min(group, count - g * group)):
                box(x + j * cell, top - 22, cell - 1.5, 20)

    box(m, m, W - 2 * m, ib_h)
    yy = ib_top - 14
    for ln in lines:
        if ln:
            bold = ln.isupper() or ln.startswith(("TO RECOVER", "WHEN TO ACT", "In every other case"))
            text(m + 8, yy, ln, "Helvetica-Bold" if bold else "Helvetica", 8.5)
        yy -= lh
    out += ["showpage", "%%EOF"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True)
    ap.add_argument("--kind", choices=("words", "chars"), required=True)
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--paper", choices=list(PAPER), default="letter")
    ap.add_argument("--threshold", type=int, default=4, help="shares needed (printed in the instructions)")
    ap.add_argument("--total", type=int, default=6, help="shares made (printed in the instructions)")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    if not 1 <= a.count <= (60 if a.kind == "words" else 400):
        sys.exit("share-form: --count out of range for --kind %s" % a.kind)
    if not 2 <= a.threshold <= a.total <= 16:
        sys.exit("share-form: need 2 <= --threshold <= --total <= 16")
    try:
        page = emit(a.label, a.kind, a.count, a.paper, a.threshold, a.total)
    except ValueError as exc:
        sys.exit("share-form: %s — nothing written" % exc)
    with open(a.out, "w") as fh:
        fh.write(page)


if __name__ == "__main__":
    main()
