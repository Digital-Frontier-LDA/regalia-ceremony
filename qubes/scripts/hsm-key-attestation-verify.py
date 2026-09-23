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
first element) and, optionally, that the attested key is the key the token exposes.

**BOTH KEY TYPES THE CARD GENERATES ARE ATTESTED, SO BOTH ARE COMPARED.** The inner request's public
key (0x7F49) is TR-03110's: an EC key carries its domain parameters (0x81 prime .. 0x85 order) and
the point in 0x86; an RSA key carries the modulus in 0x81 and the public exponent in 0x82. This
script used to read only 0x86, so an RSA key — the envelope KEK, ADR-0002 D1's main key type —
could not be commissioned at all: the attestation was "unparseable" and commission-card refused
before asking. MEASURED on DENK0404144 (fw 4.1, 2026-09-23): an RSA-2048 key generated on the card
leaves an EF CExx whose 0x7F49 is {06 id-TA-RSA-v1-5-SHA-256, 81 modulus, 82 exponent}, signed by
PrK.DevAut exactly like the EC one.

  --expect-spki FILE  the token's DER SubjectPublicKeyInfo — exactly what `pkcs11-tool --read-object
                      --type pubkey` writes, and exactly what regalia-kms hashes into its pin. The
                      attested key must BE that key: for EC the same point on the same curve (the
                      attested generator must be the SPKI curve's generator — a point alone names no
                      curve); for RSA the same modulus AND the same exponent. Verdict line
                      ATTESTED_KEY_MATCHES=yes|no. A type mismatch (an RSA attestation and an EC SPKI,
                      or the reverse), an SPKI of a type the card cannot attest, or an SPKI that does
                      not parse is `no` — never an error a caller could mistake for "not checked".
  --expect-point HEX  the older EC-only comparison (ATTESTED_POINT_MATCHES=yes|no), kept so existing
                      callers keep their meaning. An RSA attestation never matches a point.

**A MISSING DEPENDENCY IS NOT A CHAIN FAILURE.** The chain walk needs pycvc; run under an
interpreter without it (the system python3 on the bench, 2026-09-23), the child exits 2 with "pycvc
is not importable" — and this script used to report that as "C.DevAut does not validate to an
anchor", a genuine-card verdict about an environment problem, with the real cause on a later line
commission-card never showed. The dependencies are now checked HERE, first, and a missing one is its
own named failure (DEPENDENCY_MISSING=<name>, exit 2) on the first line. Anything else that stops
the child from evaluating (exit 2) is DEVAUT_CHAIN=not-evaluated, also exit 2. Only a chain the
child evaluated and rejected is DEVAUT_CHAIN=failed. All three are failures; they differ in what the
operator must fix.

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
      --trust-dir ../trust-anchors/smartcard-hsm [--expect-spki kek.der] [--expect-point HEX]

Exit: 0 verified; 1 verification failed or the key differs; 2 operator/input error or a missing
dependency (nothing about the card was established).
"""
import argparse
import hashlib
import importlib
import os
import subprocess
import sys
import tempfile

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
    from cryptography.exceptions import UnsupportedAlgorithm
except ImportError:
    ec = None

    class UnsupportedAlgorithm(Exception):  # never raised: the dependency check exits first
        pass

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


# TR-03110 terminal-authentication OIDs, as the 0x06 inside 0x7F49 carries them (DER content octets):
# id-TA 0.4.0.127.0.7.2.2.2, then .1 for RSA and .2 for ECDSA, then the hash/padding variant. The
# variant does not change where the key lives, so the ARC decides the layout and the variant is only
# reported.
ID_TA_RSA = bytes.fromhex("04007F000702020201")
ID_TA_ECDSA = bytes.fromhex("04007F000702020202")


def optional(elems, tag):
    for t, v, _ in elems:
        if t == tag:
            return v
    return None


def attested_key(request_body):
    """The public key inside the inner request, by the algorithm its OID names.

    Returns {"type": "ec", "point": bytes, "generator": bytes|None} or {"type": "rsa", "n": int,
    "e": int}. The OID decides, not which tags happen to be present: 0x81 is the PRIME in an EC key
    and the MODULUS in an RSA key, so guessing the type from the tags would read one as the other.
    An OID of neither arc is unparseable — never silently treated as either."""
    body = field(children(request_body), 0x7F4E)
    pk = children(field(children(body), 0x7F49))
    oid = field(pk, 0x06)
    if oid.startswith(ID_TA_RSA) and len(oid) == len(ID_TA_RSA) + 1:
        n, e = field(pk, 0x81), field(pk, 0x82)
        if not n or not e:
            raise ValueError("RSA key with an empty modulus or exponent")
        return {"type": "rsa", "oid": oid, "n": int.from_bytes(n, "big"), "e": int.from_bytes(e, "big")}
    if oid.startswith(ID_TA_ECDSA) and len(oid) == len(ID_TA_ECDSA) + 1:
        return {"type": "ec", "oid": oid, "point": field(pk, 0x86), "generator": optional(pk, 0x84)}
    raise ValueError(f"public key OID {oid.hex()} is neither id-TA-RSA nor id-TA-ECDSA")


def compare_to_spki(key, der):
    """(matches, reason). Every way of not matching is (False, why) — including an SPKI that does not
    parse and a type mismatch — so the verdict line is always printed and always binary."""
    try:
        tok = load_der_public_key(der)
    except (ValueError, TypeError) as e:
        return False, f"the expected SubjectPublicKeyInfo does not parse ({e})"
    except UnsupportedAlgorithm as e:
        # A well-formed SPKI naming an algorithm `cryptography` does not know is still a named
        # non-match, never a traceback without a verdict line (review of regalia-ceremony#40).
        return False, f"the expected SubjectPublicKeyInfo names a key algorithm this cannot compare ({e})"
    if isinstance(tok, rsa.RSAPublicKey):
        if key["type"] != "rsa":
            return False, "the attestation is of an EC key but the token's key is RSA"
        pn = tok.public_numbers()
        if pn.n != key["n"]:
            return False, "the attested RSA modulus is not the token key's modulus"
        if pn.e != key["e"]:
            return False, "the attested RSA public exponent is not the token key's exponent"
        return True, f"RSA-{pn.n.bit_length()}: modulus and exponent match"
    if isinstance(tok, ec.EllipticCurvePublicKey):
        if key["type"] != "ec":
            return False, "the attestation is of an RSA key but the token's key is EC"
        if tok.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint) != key["point"]:
            return False, "the attested EC point is not the token key's point"
        # THE CURVE, NOT JUST THE POINT. Coordinates are only numbers; the same bytes can be a point
        # on two curves of one field size. The request carries its domain parameters, and its
        # generator must be the SPKI curve's generator (1·G, computed rather than tabulated). An
        # attestation without them names no curve and does not match — refused, not assumed.
        if key["generator"] is None:
            return False, "the attestation carries no domain parameters, so its curve cannot be confirmed"
        gen = ec.derive_private_key(1, tok.curve).public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        if gen != key["generator"]:
            return False, f"the attested key is on a different curve than the token key ({tok.curve.name})"
        return True, f"EC {tok.curve.name}: point and curve match"
    return False, (f"the token's key is {type(tok).__name__}; a SmartCard-HSM attests only RSA and EC "
                   f"keys, so nothing can match it")


def missing_dependencies(need_pycvc):
    """Names of the modules this run needs and cannot import. pycvc is imported the way the chain
    walker imports it — in THIS interpreter, which is the one the walker is run under (sys.executable),
    with this environment — so the answer is the child's answer, obtained before the child can give
    a misleading one."""
    missing = [] if ec is not None else ["cryptography"]
    if need_pycvc:
        try:
            importlib.import_module("cvc.certificates")
            importlib.import_module("cvc.oid")
        except ImportError:
            missing.append("pycvc")
    return missing


def main():
    ap = argparse.ArgumentParser(description="Verify a SmartCard-HSM key attestation offline.")
    ap.add_argument("--devaut", required=True, help="EF 2F02 blob (C.DevAut first)")
    ap.add_argument("--attestation", required=True, help="EF CExx blob (authenticated request, tag 0x67)")
    ap.add_argument("--expect-point", help="uncompressed EC point (hex) the token exposes for the key")
    ap.add_argument("--expect-spki",
                    help="DER SubjectPublicKeyInfo the token exposes for the key (pkcs11-tool "
                         "--read-object --type pubkey); compared for RSA and EC alike")
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
    missing = missing_dependencies(bool(a.trust_dir))
    if missing:
        # FIRST, AND NAMED AS WHAT IT IS. Nothing about the card has been looked at; a reader of a
        # transcript must not be able to take this for "not a genuine card".
        print(f"{PROG} ERROR: MISSING DEPENDENCY — {', '.join(missing)} not importable by "
              f"{sys.executable}. Nothing about the card was evaluated: this is the interpreter, not "
              f"a chain or signature failure. Run under the ceremony venv (tools/ceremony-python.sh "
              f"finds it) or install the hash-pinned deps: pip install --require-hashes -r "
              f"qubes/requirements.txt", file=sys.stderr, flush=True)
        for name in missing:
            print(f"DEPENDENCY_MISSING={name}")
        return 2
    try:
        devaut = open(a.devaut, "rb").read()
        att = open(a.attestation, "rb").read()
        spki = open(a.expect_spki, "rb").read() if a.expect_spki is not None else None
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
        if chain.returncode == 2:
            # The child's own contract: 2 is "could not evaluate" (input or environment), not a
            # verdict about the card. Reported as such, and still a failure.
            print("DEVAUT_CHAIN=not-evaluated")
            print(f"{PROG} ERROR: the C.DevAut chain could NOT BE EVALUATED (not a verdict on the "
                  f"card):\n{chain.stderr.strip()}", file=sys.stderr)
            return 2
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
        key = attested_key(parts[0][1])
    except (ValueError, IndexError) as e:
        print(f"{PROG} FAILED: unparseable input ({e}) — cannot-evaluate is a failure", file=sys.stderr)
        return 1

    print(f"ATTEST_CAR={car.decode('ascii', 'replace')}")
    print(f"DEVAUT_CHR={dev_chr.decode('ascii', 'replace')}")
    print(f"ATTESTED_KEY_TYPE={key['type']}")
    if key["type"] == "ec":
        print(f"ATTESTED_POINT={key['point'].hex()}")
    else:
        print(f"ATTESTED_RSA_BITS={key['n'].bit_length()}")
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
    if a.expect_spki is not None:
        matches, why = compare_to_spki(key, spki)
        print(f"EXPECTED_SPKI_SHA256=sha256:{hashlib.sha256(spki).hexdigest()}")
        if matches:
            print("ATTESTED_KEY_MATCHES=yes")
        else:
            print("ATTESTED_KEY_MATCHES=no")
            print(f"{PROG} FAILED: the attested key is not the key the token exposes — {why}", file=sys.stderr)
            rc = 1
    if a.expect_point is not None:
        if key["type"] == "ec" and key["point"].hex() == a.expect_point.lower():
            print("ATTESTED_POINT_MATCHES=yes")
        else:
            print("ATTESTED_POINT_MATCHES=no")
            print(f"{PROG} FAILED: the attested key is not the key the token exposes", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
