#!/usr/bin/env python3
"""case-label.py — the label stuck on the OUTSIDE of a sealed share case: when, and only when, to
release it, readable without breaking the seal.

  case-label.py -o case-label.ps [--paper letter|a4]

WHY OUTSIDE (owner, 2026-09-29): the release rules also sit on the share form inside the case, but a
holder must be able to check them, and refuse, WITHOUT opening it: opening breaks the seal.

WHAT IT MUST NOT SAY: what is inside (no "wallet", "crypto", "key", amounts, names or places). It
reads like any sealed legal document, so the label does not tell a burglar or a curious relative
what is valuable. The distress answer itself is NEVER written anywhere: the label describes only
what to do when it is given. The owner and each holder agree the check question and the distress
answer in person and keep them in memory.

The case ID and seal serial are written by hand. PostScript only (no deps); prints on any CUPS queue.
"""
import argparse

PAPER = {"letter": (612.0, 792.0), "a4": (595.28, 841.89)}
MM = 72 / 25.4

# The label is the size of a DVD keep-case's front (about 135 x 190 mm, portrait), with a 0.5 inch
# safety border (owner, 2026-09-29): all text stays at least 12.7 mm inside the cut line.
CASE_W_MM, CASE_H_MM, BORDER_IN = 135.0, 190.0, 0.5

# (text, font, size, space before). Paragraphs are word-wrapped to the inner width.
BLOCKS = [
    ("SEALED DOCUMENT", "Helvetica-Bold", 20, 0),
    ("DO NOT OPEN", "Helvetica-Bold", 20, 2),
    ("Release this package ONLY in one of these two ways:", "Helvetica-Bold", 12, 16),
    ("1. To the OWNER, in person. Ask your agreed check question first. If the owner gives the "
     "agreed DISTRESS answer, or seems forced, rushed or watched: hand NOTHING over. Say you need "
     "time to fetch it. Leave safely, and contact the police afterwards.", "Helvetica", 11, 10),
    ("2. To the EXECUTOR named to you, in person, with the ORIGINAL official death certificate of "
     "the owner, or the ORIGINAL court decision of the owner's incapacity.", "Helvetica", 11, 10),
    ("NEVER on a phone call, message, e-mail or video call. NEVER to anyone else, including the "
     "owner's technical staff on their own.", "Helvetica-Bold", 11, 12),
    ("If this seal is broken, or the package is lost, tell the owner or the executor at once.",
     "Helvetica", 10.5, 12),
    ("The check question and the distress answer are never written down, anywhere.",
     "Helvetica-Oblique", 10.5, 10),
]


def esc(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def wrap(text, size, width_pt):
    # Helvetica averages well under 0.56 em per character; 0.56 keeps every line inside the width.
    per_line = max(10, int(width_pt / (size * 0.56)))
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > per_line:
            lines.append(cur); cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines


def emit(paper):
    W, H = PAPER[paper]
    w, h = CASE_W_MM * MM, CASE_H_MM * MM
    x0, y0 = (W - w) / 2, (H - h) / 2
    b = BORDER_IN * 72
    inner_left, inner_right, inner_top, inner_bottom = x0 + b, x0 + w - b, y0 + h - b, y0 + b
    out = ["%!PS-Adobe-3.0", "%%%%BoundingBox: 0 0 %d %d" % (W, H),
           "%%%%DocumentMedia: %s %d %d 0 () ()" % (paper, round(W), round(H)),
           "%%Pages: 1", "%%EndComments",
           "%%BeginSetup", "<< /PageSize [%.2f %.2f] >> setpagedevice" % (W, H), "%%EndSetup",
           "%%Page: 1 1", "0.6 setlinewidth",
           "[4 3] 0 setdash %.1f %.1f %.1f %.1f rectstroke [] 0 setdash" % (x0, y0, w, h)]
    y = inner_top
    for text, font, size, gap in BLOCKS:
        y -= gap
        for line in wrap(text, size, inner_right - inner_left):
            y -= size
            out.append("/%s findfont %g scalefont setfont %.1f %.1f moveto (%s) show" % (font, size, inner_left, y, esc(line)))
            y -= size * 0.3
    # Handwritten fields at the foot of the inner area.
    fy = inner_bottom + 34
    for label in ("Case ID:", "Seal serial:"):
        out.append("/Helvetica-Bold findfont 11 scalefont setfont %.1f %.1f moveto (%s) show" % (inner_left, fy, label))
        out.append("%.1f %.1f moveto %.1f %.1f lineto stroke" % (inner_left + 80, fy - 2, inner_right, fy - 2))
        fy -= 26
    if y < inner_bottom + 60:
        raise SystemExit("case-label: the text runs into the handwritten fields or the 0.5 inch border")
    out.append("/Helvetica findfont 7 scalefont setfont %.1f %.1f moveto (cut along the dashed line: the size of a DVD case front; stick it on the OUTSIDE of the sealed case) show"
               % (x0, y0 - 12))
    out += ["showpage", "%%EOF"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--paper", choices=list(PAPER), default="letter")
    a = ap.parse_args()
    with open(a.out, "w") as fh:
        fh.write(emit(a.paper))


if __name__ == "__main__":
    main()
