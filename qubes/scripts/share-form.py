#!/usr/bin/env python3
"""share-form.py — print a BLANK form that a Shamir share is written onto BY HAND.

  share-form.py --label "Wallet seed — SLIP-0039 share 3 of 6 (need 4)" --kind words --count 33 -o form.ps
  share-form.py --label "Breakglass age key — share 1 of 6 (need 4)" --kind chars --count 148 -o form.ps

WHY BLANK: the owner's rule (ADR-0002 D12, 2026-09-29) is that a printer never sees a Shamir
share: it keeps pages in memory, and a share is a quarter of the way to the secret. The printer
prints this empty form — title, numbered boxes, the case fields, the instructions — and the share
is copied into it by hand from the ceremony screen, then typed back to prove the copy.

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


def emit(label, kind, count, paper):
    W, H = PAPER[paper]
    m = 42.0
    out = ["%!PS-Adobe-3.0", "%%%%BoundingBox: 0 0 %d %d" % (W, H), "%%Pages: 1", "%%EndComments",
           "%%Page: 1 1", "0.8 setlinewidth"]

    def text(x, y, s, font="Helvetica", size=10):
        out.append("/%s findfont %g scalefont setfont %.1f %.1f moveto (%s) show"
                   % (font, size, x, y, esc(ascii_only(s))))

    y = H - m - 6
    text(m, y, "SHAMIR SHARE - WRITE BY HAND, IN PEN", "Helvetica-Bold", 15)
    y -= 20
    text(m, y, label, "Helvetica-Bold", 11)
    y -= 22
    for field in ("Case ID: ______________    Seal serial: ______________    Date: ____-__-__",
                  "Written by: ______________________    Checked (re-typed OK): [   ]"):
        text(m, y, field, "Helvetica", 9.5)
        y -= 16
    y -= 8

    if kind == "words":
        cols, box_h = 3, 24.0
        rows = -(-count // cols)
        col_w = (W - 2 * m) / cols
        for i in range(count):
            r, c = i // cols, i % cols           # numbered left-to-right, like the screen shows them
            x, top = m + c * col_w, y - r * box_h
            text(x, top - 15, "%2d" % (i + 1), "Helvetica-Bold", 9)
            out.append("%.1f %.1f %.1f %.1f rectstroke" % (x + 20, top - 20, col_w - 30, 19))
        y -= rows * box_h + 12
    else:
        group, cell = 4, 14.5                     # groups of 4 characters
        gw = group * cell + 10
        per_row = max(1, int((W - 2 * m - 24 + 10) // gw))   # as many groups as fit this paper width
        groups = -(-count // group)
        rows = -(-groups // per_row)
        for g in range(groups):
            r, c = g // per_row, g % per_row
            x, top = m + 24 + c * gw, y - r * 30
            if c == 0:
                text(m, top - 15, "%3d" % (g * group + 1), "Helvetica-Bold", 8)
            n = min(group, count - g * group)
            for k in range(n):
                out.append("%.1f %.1f %.1f %.1f rectstroke" % (x + k * cell, top - 22, cell - 1.5, 20))
        y -= rows * 30 + 12

    notes = [
        "Copy the share from the ceremony screen exactly: every %s, in order." % ("word" if kind == "words" else "character"),
        "The wizard then asks you to type it back from THIS sheet; it must match before you seal it.",
        "Never photograph, scan or type this sheet anywhere else. Store it sealed, flat, away from the others.",
        "One share alone reveals nothing; any %s of these sheets together rebuild the secret." % "the threshold",
    ]
    for s in notes:
        if y < m + 10:
            break
        text(m, y, s, "Helvetica", 8.5)
        y -= 12
    out += ["showpage", "%%EOF"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True)
    ap.add_argument("--kind", choices=("words", "chars"), required=True)
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--paper", choices=list(PAPER), default="letter")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    if not 1 <= a.count <= (60 if a.kind == "words" else 400):
        sys.exit("share-form: --count out of range for --kind %s" % a.kind)
    with open(a.out, "w") as fh:
        fh.write(emit(a.label, a.kind, a.count, a.paper))


if __name__ == "__main__":
    main()
