#!/usr/bin/env python3
"""Parse and cryptographically verify a SmartCard-HSM C.DevAut certificate, OFFLINE.

WHY THIS EXISTS. The device identity lives in C.DevAut in read-only EF 2F02 as a Card
Verifiable Certificate (BSI TR-03110) — NOT X.509, so openssl cannot parse it, and
sc-hsm-tool never prints it. Until now the only consumer was hsm-devaut-id.js, which pulls
the CHR/CAR out with a tag-SUBSTRING search (hex.indexOf("5F20")): a search that can match
inside a value field on a different cert layout and silently read the wrong bytes — precisely
the failure the identity check exists to catch. And the genuineness arm of the Nitrokey gate
(RUNBOOK-NITROKEY-GATE.md §2.3) was a STRING check: "CAR names a CardContact Device Issuer
CA". A name is not a signature. This script does the real TR-03110 parse (via pycvc) and
verifies the certificate's signature chain against a trust anchor, so "something above the
device vouches for it" is proven cryptographically, not read off a label.

Why a library consumer and not pycvc's own cvc-print CLI: cvc-print prints "Certificate
VALID/NOT VALID" but ALWAYS EXITS 0 — it discards the verification result. A fail-closed
ceremony control branches on the exit code, so this script wraps the cvc library API with
the house contract:

  0 = every requested check passed
  1 = verification FAILED or a required property is absent (cannot-evaluate = FAIL, not skip)
  2 = operator/input error (missing file, bad flags, pycvc not installed)

  cvc-devaut-verify.py --cert devaut.bin [--trust-dir DIR]
  cvc-devaut-verify.py --hex devaut.hex --require-external-car --expect-chr DENK0400001
                       [--expect-car CAR] [--expect-sha256 HEX]

--cert reads the raw EF 2F02 blob; --hex reads the DEVAUT_HEX line captured from
hsm-devaut-id.js. --trust-dir points at a directory of CVC certificates NAMED BY THEIR CHR
(the cvc-print convention), holding the issuer chain — e.g. the CardContact Device Issuer
CA — and turns the string check into chain verification. Without it the signature is not
verifiable; that is reported loudly (CVC_CHAIN=unverified) but is not by itself a failure,
because the structural checks and pins below still stand. Combine with --trust-dir at the
gate.

pycvc is GPL-3.0 and comes from the hash-pinned qubes/requirements.txt — it is an
installed dependency, not vendored, so this script also runs anywhere `pip install
--require-hashes -r qubes/requirements.txt` has been run.
"""
import argparse
import binascii
import hashlib
import os
import sys

try:
    from cvc.certificates import CVC
    from cvc.oid import oid2scheme
except ImportError:  # reported as an operator error (rc=2) in main(), not a traceback
    CVC = None
    oid2scheme = None

PROG = "cvc-devaut-verify"


def err(msg):
    print(f"{PROG} ERROR: {msg}", file=sys.stderr)


def fail(msg):
    print(f"{PROG} FAILED: {msg}", file=sys.stderr)
    return 1


def fmt_bcd_date(v):
    """TR-03110 dates are BCD 'yymmdd'. pycvc emits one byte per digit (6 bytes); a packed
    on-card encoding is 3 bytes, two nibbles per digit. Accept both, refuse anything else."""
    if len(v) == 6:
        digits = list(v)
    elif len(v) == 3:
        digits = []
        for b in v:
            digits += [(b >> 4) & 0xF, b & 0xF]
    else:
        raise ValueError(f"date field is {len(v)} bytes, expected 3 or 6")
    if any(d > 9 for d in digits):
        raise ValueError("date field is not BCD")
    return "20%d%d-%d%d-%d%d" % tuple(digits)


ELEMENT_NAMES = {
    0x67: "authenticated REQUEST (self-signed; no validity period)",
    0x7F21: "CV Certificate",
}


def top_level_elements(blob):
    """Walk the top-level BER-TLV elements of EF 2F02 and return [(tag, value_length)].

    EF 2F02 is NOT one certificate. On a SmartCard-HSM it holds the device certificate followed
    by its issuer's, and on a self-provisioned Pico it holds a 0x67 request followed by a 0x7F21
    certificate (measured 2026-08-06: 497 + 443 = 940 bytes). Reporting the real structure is
    what lets an operator tell "self-signed, nothing above it" apart from "a genuine chain",
    which a digest alone cannot express. Parsing stops at the first malformed element rather
    than guessing — a partial answer here is still an answer, and the caller sees the count."""
    out = []
    off = 0
    n = len(blob)
    try:
        while off < n:
            tag = blob[off]
            off += 1
            if tag & 0x1F == 0x1F:              # multi-byte tag
                tag = (tag << 8) | blob[off]
                off += 1
            length = blob[off]
            off += 1
            if length & 0x80:
                nbytes = length & 0x7F
                length = int.from_bytes(blob[off:off + nbytes], "big")
                off += nbytes
            if length < 0 or off + length > n:
                break
            out.append((tag, length))
            off += length
    except IndexError:
        pass
    return out


def verify_chain(blob, cert_dir):
    """Walk leaf -> issuer -> ... -> self-signed root, verifying each signature, the way
    cvc-print does but with a boolean result. Every certificate in the directory is named by
    its CHR; a missing issuer file is a FAILURE (the chain cannot be evaluated), never a skip."""
    cert_dir_b = os.fsencode(cert_dir)
    cur = blob
    seen = set()
    car = chr_ = b"?"
    while True:
        # Any exception in the walk is a verification FAILURE, reported as one. An issuer file
        # whose public point is not on the curve raised ValueError("Invalid EC key") out of
        # pycvc/cryptography and ended the script in a traceback (measured 2026-09-17 with a
        # corrupted anchor). The exit code happened to be 1, but by accident, and with no
        # CVC_CHAIN line for a caller to read.
        try:
            c = CVC().decode(cur)
            car, chr_ = bytes(c.car()), bytes(c.chr())
            verified = c.verify(cert_dir=cert_dir_b)
        except Exception:
            return False, car, chr_
        if not verified:
            return False, car, chr_
        if car == chr_:
            return True, car, chr_  # reached a self-signed root that verified against itself
        if car in seen:
            return False, car, chr_  # cycle — a constructed chain, not a PKI
        seen.add(car)
        try:
            with open(os.path.join(cert_dir, car.decode("ascii")), "rb") as f:
                cur = f.read()
        except (OSError, UnicodeDecodeError):
            return False, car, chr_


def main():
    ap = argparse.ArgumentParser(
        description="Parse and verify a SmartCard-HSM C.DevAut CVC certificate (offline).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--cert", help="raw EF 2F02 blob (binary)")
    src.add_argument("--hex", dest="hexfile",
                     help="file with the blob as hex (e.g. a captured DEVAUT_HEX line)")
    ap.add_argument("--trust-dir",
                    help="directory of issuer CVC certificates named by CHR; enables "
                         "signature-chain verification to the trust anchor")
    ap.add_argument("--require-external-car", action="store_true",
                    help="fail if CHR == CAR (self-signed — the measured Pico behaviour)")
    ap.add_argument("--expect-chr", help="fail unless the CHR equals this value")
    ap.add_argument("--expect-car", help="fail unless the CAR equals this value")
    ap.add_argument("--expect-sha256", help="fail unless the blob's SHA-256 equals this hex")
    a = ap.parse_args()

    if CVC is None:
        err("pycvc is not importable — install the hash-pinned deps: "
            "pip install --require-hashes -r qubes/requirements.txt")
        return 2

    try:
        if a.cert:
            with open(a.cert, "rb") as f:
                blob = f.read()
        else:
            with open(a.hexfile, "r", encoding="ascii") as f:
                blob = binascii.unhexlify("".join(f.read().split()))
    except (OSError, binascii.Error, UnicodeDecodeError) as e:
        err(f"cannot read the certificate input: {e}")
        return 2
    if not blob:
        err("certificate input is empty")
        return 2
    if a.trust_dir and not os.path.isdir(a.trust_dir):
        err(f"--trust-dir '{a.trust_dir}' is not a directory")
        return 2

    sha = hashlib.sha256(blob).hexdigest()

    # ---- parse: a real TR-03110 decode, not a tag-substring search ---------------------
    try:
        c = CVC().decode(blob)
        car = bytes(c.car()).decode("ascii")
        chr_ = bytes(c.chr()).decode("ascii")
    except Exception as e:
        tags = ", ".join(f"0x{t:X}" for t, _ in top_level_elements(blob)) or "none"
        return fail(f"not a parseable CVC certificate ({type(e).__name__}: {e}); "
                    f"top-level tags present: {tags} — cannot-evaluate is a FAILURE")

    try:
        scheme = oid2scheme(bytes(c.pubkey().oid()))
    except Exception:
        try:
            scheme = "unknown:" + bytes(c.pubkey().oid()).hex()
        except Exception:
            scheme = "unreadable"

    # THE DATES ARE OPTIONAL, and assuming otherwise is how this script spent its first day
    # reporting a perfectly good certificate as unparseable. A TR-03110 *authenticated request*
    # (outer tag 0x67) has no Certificate Effective/Expiration Date — a CA fills those in when it
    # issues the certificate — and that is exactly the shape a self-signed device writes into
    # EF 2F02. MEASURED on the staging Pico 2026-08-06: EF 2F02 is a 0x67 request CONCATENATED
    # with a 0x7F21 certificate; pycvc reads the request first, c.valid() raises AttributeError,
    # and the old blanket `except` around the whole parse reported "not a parseable CVC".
    since = expires = "n/a"
    dated = True
    try:
        since = fmt_bcd_date(bytes(c.valid()))
        expires = fmt_bcd_date(bytes(c.expires()))
    except Exception:
        dated = False

    elements = top_level_elements(blob)

    print(f"CVC_CAR={car}")
    print(f"CVC_CHR={chr_}")
    print(f"CVC_SCHEME={scheme}")
    print(f"CVC_SINCE={since}")
    print(f"CVC_EXPIRES={expires}")
    print(f"CVC_DATED={'yes' if dated else 'no'}")
    print(f"CVC_ELEMENTS={len(elements)}")
    for i, (tag, _) in enumerate(elements, 1):
        print(f"CVC_ELEMENT_{i}=0x{tag:X} {ELEMENT_NAMES.get(tag, 'unrecognised')}")
    print(f"CVC_SHA256={sha}")

    if not dated:
        # Loud, but not fatal on its own: an undated self-signed request is the MEASURED staging
        # posture, not a fault. What makes it untrustworthy is CHR == CAR, which
        # --require-external-car below turns into a hard failure when the caller demands it.
        print(f"{PROG} NOTE: this element carries NO VALIDITY PERIOD — it is a certificate "
              f"REQUEST (tag 0x67), not an issued certificate. Nothing has dated or vouched for "
              f"it. Expected on a self-provisioned Pico; NOT expected on a Nitrokey HSM 2.",
              file=sys.stderr)

    # ---- structural + pin checks --------------------------------------------------------
    if a.require_external_car and chr_ == car:
        return fail(f"C.DevAut is SELF-SIGNED (CHR == CAR == '{chr_}') — nothing above the "
                    f"device vouches for it. Measured Pico behaviour; on a device sold as a "
                    f"Nitrokey you are not holding what you think you are holding.")
    if a.expect_chr is not None and chr_ != a.expect_chr:
        return fail(f"CHR MISMATCH — expected '{a.expect_chr}', certificate carries '{chr_}'")
    if a.expect_car is not None and car != a.expect_car:
        return fail(f"CAR MISMATCH — expected '{a.expect_car}', certificate carries '{car}'")
    if a.expect_sha256 is not None and sha != a.expect_sha256.lower():
        return fail("DIGEST MISMATCH — this is not the certificate that was pinned")

    # ---- signature chain ----------------------------------------------------------------
    if a.trust_dir:
        ok, last_car, last_chr = verify_chain(blob, a.trust_dir)
        if not ok:
            print("CVC_CHAIN=failed")
            return fail(f"signature chain does NOT verify "
                        f"(issuer '{last_car.decode('ascii', 'replace')}' for holder "
                        f"'{last_chr.decode('ascii', 'replace')}') — a missing anchor "
                        f"file is a failure, not a skip")
        print("CVC_CHAIN=verified")
    else:
        print("CVC_CHAIN=unverified")
        print(f"{PROG} NOTE: CHAIN UNVERIFIED — no --trust-dir given, so the signature was "
              f"not checked; 'CAR names a CA' remains a STRING claim until a trust anchor "
              f"(e.g. the CardContact Device Issuer CA cert, named by its CHR) is provided.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
