#!/usr/bin/env python3
"""pin-card-form.py — print a BLANK paper PIN card: the day-to-day PINs are written on it BY HAND.

  pin-card-form.py -o pin-card.ps                      # HSM A, B, C (10 digits) + YubiKey A, B, C (8)
  pin-card-form.py -o pin-card.ps --hsms a,b --yubikeys a --hsm-digits 10 --yubikey-digits 8 --paper a4

WHAT IT IS (owner, 2026-09-29; ADR-0002 D16): step 0 generates the day-to-day PINs and shows each
once; they are copied onto this card by hand, then typed back. The card is what carries each site's
HSM user PIN to that site's one-time TPM sealing (regalia-kms deploy/seal-hsm-pin.sh) and holds the
YubiKey PIN until it is memorised. The recovery credentials (SO-PINs, PUK, management key) are NEVER
written here: they exist only in the encrypted tier-0 payload.

PAGE 2, THE KMS HOST CARD (--hosts, default a,b,c): a row per KMS host for its TPM lockout
authorization, which step 0 also generates and shows once. It is typed at that host's console when
its TPM is commissioned (regalia-kms deploy/baremetal/tpm-lockout.sh --set).

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
    "- Each site's HSM PIN is typed ONCE into that server's TPM (seal-hsm-pin.sh). KEEP the card after",
    "  that, sealed. It is how a KMS server is BROUGHT BACK when its TPM no longer releases the PIN",
    "  (a rebuild, a TPM reset or lockout, a replaced board): the PIN is sealed again from this card.",
    "  And the next PIN escrow asks for every PIN and the escrow MAC key from it.",
    "- Never write the SO-PINs, the PUK or the management key here.",
]


# Page 2. What step 0 generates for each KMS host's TPM: 20 characters from capitals and digits with
# no 0, 1, I, L or O (ceremony.sh gen_secret paper:20).
HOST_AUTH_CHARS = 20
HOST_RULES = [
    "RULES FOR THIS PAGE",
    "- One row per KMS host. Each value is typed ONCE at that host's console, when its TPM is",
    "  commissioned (regalia-kms tpm-lockout.sh --set). Whoever holds it can change that TPM's lockout",
    "  settings or clear its failed-try counter.",
    "- Copy it EXACTLY and never guess at the host: after ONE wrong attempt the TPM refuses the right",
    "  value too until its lockout-recovery time has passed (24 hours under the KMS policy).",
    "- It never contains 0, 1, I, L or O: a character that looks like one of those is a copying error.",
    "- Type it at the host WITHOUT spaces, whatever grouping you used here to copy it.",
    "- KEEP this page, sealed in its tamper-evident envelope, apart from the servers. It is what clears",
    "  a server's TPM lockout when that server has to be brought back, and every later PIN escrow asks",
    "  for all of these values again. It is NOT the backup (each value is also in the encrypted",
    "  recovery payload), but without it a PIN change cannot be escrowed.",
    "- A broken seal means: assume the values are known. Record it as an incident.",
]


def esc(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def emit(hsms, yubikeys, hsm_digits, yk_digits, paper, hosts=()):
    W, H = PAPER[paper]
    m = 42.0
    out = ["%!PS-Adobe-3.0", "%%%%BoundingBox: 0 0 %d %d" % (W, H),
           "%%%%DocumentMedia: %s %d %d 0 () ()" % (paper, round(W), round(H)),
           "%%%%Pages: %d" % (2 if hosts else 1), "%%EndComments",
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
    out.append("showpage")

    # Page 2, the KMS HOST CARD: each KMS host's TPM lockout authorization (step 0 shows each once).
    # A page of its own: the values are not PINs, they go to a host's console once, and the rule that
    # matters most for them (never guess at the host) belongs beside them.
    if hosts:
        out += ["%%Page: 2 2", "0.8 setlinewidth"]
        y = H - m - 6
        text(m, y, "KMS HOST CARD - WRITE BY HAND, IN PEN", "Helvetica-Bold", 15)
        y -= 18
        text(m, y, "TPM lockout authorizations only. This printed page held no secret when printed.", "Helvetica", 9)
        y -= 16
        text(m, y, "Date:", "Helvetica-Bold", 9)
        line(m + 32, y - 2, m + 180)
        text(m + 200, y, "Written by (initials):", "Helvetica-Bold", 9)
        line(m + 305, y - 2, W - m)
        y -= 26
        for host in hosts:
            text(m, y, "KMS host %s - TPM lockout authorization" % host.upper(), "Helvetica-Bold", 10.5)
            text(m + 262, y, "Server serial:", "Helvetica-Bold", 9)
            line(m + 325, y - 2, W - m)
            y -= 28
            for i in range(HOST_AUTH_CHARS):
                box(m + i * (cell + 4), y, cell, 24)
            y -= 14
            text(m, y, "%d characters, capitals and digits. Typed back and matched: [  ]" % HOST_AUTH_CHARS, "Helvetica", 9)
            y -= 22
        ib_h = lh * len(HOST_RULES) + 12
        if y < m + ib_h + 8:
            raise ValueError("%d host rows do not fit above the rules on %s paper" % (len(hosts), paper))
        box(m, m, W - 2 * m, ib_h)
        yy = m + ib_h - 14
        for ln in HOST_RULES:
            text(m + 8, yy, ln, "Helvetica-Bold" if ln.isupper() else "Helvetica", 8.5)
            yy -= lh
        out.append("showpage")
    out.append("%%EOF")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--hsms", default="a,b,c", help="HSM letters, comma separated (default a,b,c)")
    ap.add_argument("--yubikeys", default="a,b,c", help="YubiKey letters, comma separated (default a,b,c)")
    ap.add_argument("--hosts", default="a,b,c", help="KMS host letters for page 2, the TPM lockout "
                    "authorizations (default a,b,c; empty for no second page)")
    ap.add_argument("--hsm-digits", type=int, default=10, help="HSM user PIN length (default 10)")
    ap.add_argument("--yubikey-digits", type=int, default=8, help="YubiKey PIN length (default 8)")
    ap.add_argument("--paper", choices=list(PAPER), default="letter")
    a = ap.parse_args()
    hsms = [h for h in a.hsms.split(",") if h]
    yubikeys = [y for y in a.yubikeys.split(",") if y]
    for name, lst in (("--hsms", hsms), ("--yubikeys", yubikeys)):
        if not lst or any(len(x) != 1 or not x.isalpha() for x in lst) or len(lst) > 3:
            sys.exit("pin-card-form: %s is 1-3 single letters, e.g. a,b,c" % name)
    hosts = [h for h in a.hosts.split(",") if h]
    if any(len(x) != 1 or not x.isalpha() for x in hosts) or len(hosts) > 3:
        sys.exit("pin-card-form: --hosts is up to 3 single letters, e.g. a,b,c")
    if not 6 <= a.hsm_digits <= 16 or not 6 <= a.yubikey_digits <= 8:
        sys.exit("pin-card-form: HSM PINs are 6-16 digits, a YubiKey PIN 6-8")
    try:
        page = emit(hsms, yubikeys, a.hsm_digits, a.yubikey_digits, a.paper, hosts)
    except ValueError as exc:
        sys.exit("pin-card-form: %s; nothing written" % exc)
    with open(a.out, "w") as fh:
        fh.write(page)


if __name__ == "__main__":
    main()
