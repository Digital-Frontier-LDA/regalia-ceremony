#!/usr/bin/env python3
"""Verify a SmartCard-HSM KEY ATTESTATION offline: the device signed this public key at generation.

WHY THIS EXISTS. `AssertKEKGeneratedOnToken` reads CKA_LOCAL on the public half, and on a genuine
SmartCard-HSM that attribute is useless: MEASURED on a Nitrokey HSM 2 (DENK0404144, fw 4.1,
2026-09-17), a key generated ON the card reads CKA_LOCAL=false on its public half, and a key
DKEK-imported from a host reads `local` on its private half (#447). The card does record
provenance, just not there. GENERATE ASYMMETRIC KEY PAIR returns an authenticated CV request
(tag 0x67): an inner request carrying the new public key, and an OUTER signature made with the
device key PrK.DevAut. OpenSC stores it in EF CExx next to the key. A DKEK import (UNWRAP KEY)
produces no such object, so a verifying attestation means "generated on THIS device".

This script checks that outer signature against the device public key from C.DevAut (EF 2F02,
first element) and, optionally, that the attested point is the key the token exposes.

**THE DEVICE CERTIFICATE MUST BE VALIDATED, OR THIS PROVES NOTHING.** The attestation is only
evidence because the key that signed it is a CardContact-certified device key. Given an attacker's
certificate and an attestation forged under its matching private key, every signature check below
passes — the chain to the trust anchor is the only thing that makes the device key a device key.
So this refuses to report success unless one of two things is true:

  --trust-dir DIR   the C.DevAut blob is validated to an anchor in DIR first (cvc-devaut-verify.py
                    does the TR-03110 parse and chain walk; this script shells out to it)
  --devaut-already-verified
                    an explicit assertion by the caller that the SAME bytes were validated earlier
                    in the pipeline. It is printed in the output, so a reader of a transcript can
                    see which arm was used.

Neither is not a third option: with no assurance about C.DevAut the script exits 2 rather than
printing a verification a reader would take for one.

  hsm-key-attestation-verify.py --devaut ef2f02.bin --attestation ce01.bin \
      --trust-dir ../trust-anchors/smartcard-hsm [--expect-point HEX]

Exit: 0 verified; 1 verification failed or the point differs; 2 operator/input error.
"""
import argparse
import os
import subprocess
import sys
import tempfile

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
except ImportError:
    ec = None

PROG = "hsm-key-attestation-verify"


def tlv(b, i=0):
    t = b[i]
    i += 1
    if t & 0x1F == 0x1F:
        while b[i] & 0x80:
            t = (t << 8) | b[i]
            i += 1
        t = (t << 8) | b[i]
        i += 1
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > len(b):
        raise ValueError("truncated TLV")
    return t, b[i:i + n], i + n


def children(b):
    out, i = [], 0
    while i < len(b):
        t, v, j = tlv(b, i)
        out.append((t, v, b[i:j]))
        i = j
    return out


def field(elems, tag):
    for t, v, _ in elems:
        if t == tag:
            return v
    raise ValueError(f"tag 0x{tag:X} absent")


def public_point(cert_or_request_body):
    """0x7F21 { 0x7F4E { ... 0x7F49 { ... 0x86 point } } }"""
    body = field(children(cert_or_request_body), 0x7F4E)
    pk = field(children(body), 0x7F49)
    return field(children(pk), 0x86)


def main():
    ap = argparse.ArgumentParser(description="Verify a SmartCard-HSM key attestation offline.")
    ap.add_argument("--devaut", required=True, help="EF 2F02 blob (C.DevAut first)")
    ap.add_argument("--attestation", required=True, help="EF CExx blob (authenticated request, tag 0x67)")
    ap.add_argument("--expect-point", help="uncompressed EC point (hex) the token exposes for the key")
    ap.add_argument("--trust-dir",
                    help="directory of issuer CVC certificates named by CHR; the C.DevAut blob is "
                         "validated to an anchor here before the attestation is checked")
    ap.add_argument("--devaut-already-verified", action="store_true",
                    help="assert that these exact C.DevAut bytes were validated earlier in the "
                         "pipeline; recorded in the output so a transcript shows which arm ran")
    a = ap.parse_args()
    if not a.trust_dir and not a.devaut_already_verified:
        print(f"{PROG} ERROR: refusing to report an attestation without assurance about C.DevAut. "
              f"Pass --trust-dir DIR to validate it here, or --devaut-already-verified if the same "
              f"bytes were validated earlier. An attestation verified under an unvalidated device "
              f"certificate proves nothing: an attacker's certificate and a matching forged "
              f"attestation would pass every check below.", file=sys.stderr)
        return 2
    if ec is None:
        print(f"{PROG} ERROR: the `cryptography` package is required", file=sys.stderr)
        return 2
    try:
        devaut = open(a.devaut, "rb").read()
        att = open(a.attestation, "rb").read()
    except OSError as e:
        print(f"{PROG} ERROR: {e}", file=sys.stderr)
        return 2

    if a.trust_dir:
        # Delegate to the TR-03110 parser and chain walker rather than reimplementing it: one
        # implementation of "does this chain to the anchor", used by both tools.
        verifier = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvc-devaut-verify.py")
        if not os.path.isfile(verifier):
            print(f"{PROG} ERROR: cvc-devaut-verify.py not found next to this script; cannot "
                  f"validate C.DevAut", file=sys.stderr)
            return 2
        # ONE READ, ONE SET OF BYTES. Passing a.devaut to the child would make it open the path a
        # second time, and a local process that can replace that path between the two opens gets a
        # trusted certificate validated while the attestation below is checked against the bytes
        # already cached here (TOCTOU, CWE-367). The child validates exactly what this process read.
        with tempfile.NamedTemporaryFile(suffix=".devaut", delete=False) as cached:
            cached.write(devaut)
            cached_path = cached.name
        try:
            chain = subprocess.run([sys.executable, verifier, "--cert", cached_path,
                                    "--trust-dir", a.trust_dir, "--require-external-car"],
                                   capture_output=True, text=True)
        finally:
            os.unlink(cached_path)
        if chain.returncode != 0:
            print("DEVAUT_CHAIN=failed")
            print(f"{PROG} FAILED: C.DevAut does not validate to an anchor in {a.trust_dir}; the "
                  f"attestation below would prove nothing.\n{chain.stderr.strip()}", file=sys.stderr)
            return 1
        print("DEVAUT_CHAIN=verified")
    else:
        print("DEVAUT_CHAIN=asserted-by-caller")
    try:
        t, dev_body, _ = tlv(devaut)
        if t != 0x7F21:
            raise ValueError(f"EF 2F02 does not start with a CV certificate (tag 0x{t:X})")
        dev_point = public_point(dev_body)
        dev_chr = field(children(field(children(dev_body), 0x7F4E)), 0x5F20)
        t, body, _ = tlv(att)
        if t != 0x67:
            raise ValueError(f"not an authenticated request (tag 0x{t:X}, want 0x67)")
        parts = children(body)
        if [p[0] for p in parts[:3]] != [0x7F21, 0x42, 0x5F37]:
            raise ValueError("authenticated request layout is not 7F21 | 42 | 5F37")
        inner_raw, car_raw, outer_sig = parts[0][2], parts[1][2], parts[2][1]
        car = parts[1][1]
        key_point = public_point(parts[0][1])
    except (ValueError, IndexError) as e:
        print(f"{PROG} FAILED: unparseable input ({e}) — cannot-evaluate is a failure", file=sys.stderr)
        return 1

    print(f"ATTEST_CAR={car.decode('ascii', 'replace')}")
    print(f"DEVAUT_CHR={dev_chr.decode('ascii', 'replace')}")
    print(f"ATTESTED_POINT={key_point.hex()}")
    rc = 0
    if car != dev_chr:
        print(f"{PROG} FAILED: the attestation names signer '{car.decode('ascii', 'replace')}', "
              f"not this device", file=sys.stderr)
        rc = 1
    half = len(outer_sig) // 2
    try:
        # SmartCard-HSM device keys are brainpoolP256r1; signatures are plain r||s over the
        # inner request followed by the CAR TLV (TR-03110 authenticated request).
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP256R1(), dev_point)
        sig = encode_dss_signature(int.from_bytes(outer_sig[:half], "big"),
                                   int.from_bytes(outer_sig[half:], "big"))
        pub.verify(sig, inner_raw + car_raw, ec.ECDSA(hashes.SHA256()))
        print("ATTEST_SIGNATURE=verified")
    except (InvalidSignature, ValueError):
        print("ATTEST_SIGNATURE=failed")
        print(f"{PROG} FAILED: the outer signature does not verify under the device key", file=sys.stderr)
        rc = 1
    if a.expect_point is not None:
        if key_point.hex() == a.expect_point.lower():
            print("ATTESTED_POINT_MATCHES=yes")
        else:
            print("ATTESTED_POINT_MATCHES=no")
            print(f"{PROG} FAILED: the attested key is not the key the token exposes", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
