#!/usr/bin/env python3
"""Verify a YubiKey PIV ATTESTATION offline: this key was generated in this slot of a genuine YubiKey.

WHY THIS EXISTS. The ceremony's YubiKey evidence is `ykman piv keys info`: slot, algorithm,
`Origin: GENERATED`, PIN and touch policy. All of it is the DEVICE SAYING SO. A counterfeit or
emulated token can print the same lines. ADR-0002 D1 does not accept that for a Nitrokey, where
genuineness is proven once at commissioning from C.DevAut and the key attestation. This is the
YubiKey counterpart.

A YubiKey signs, with the attestation key in slot f9 (shared across a batch; see below), a certificate for any key that was
GENERATED in a slot (an imported key cannot be attested). The f9 certificate is issued by Yubico,
so the chain is:

    slot attestation  <- f9 "YubiKey PIV Attestation"  <- Yubico PIV Attestation {A,B,B2} 1
                      <- Yubico Attestation Intermediate {A,B} 1  <- Yubico Attestation Root 1
    (firmware <= 5.7.3: f9 is issued directly by "Yubico PIV Root CA Serial 263751")

**THE f9 KEY IS NOT PER DEVICE, SO THE SERIAL IS REQUIRED.** Measured 2026-09-24 on two 5.7.4
cards (36345471 and 36344616): both carry the IDENTICAL f9 certificate (serial 95DC17993B2DB7FC,
same key). The attestation key is shared across a production batch. A verified chain therefore proves
"a genuine YubiKey generated this key", not which one. The device is identified by the serial Yubico
signs into each attestation, so --serial is mandatory: without it, a key attested by any other
genuine card of the batch would pass.

The attestation certificate also carries Yubico's extensions: the device serial (1.3.6.1.4.1.41482.3.7),
the key's PIN and touch policy (…3.8) and the firmware version (…3.3). Those are signed values, not
self-reports.

    yubikey-attestation-verify.py --attestation att.pem --f9 f9.pem --serial N \
        [--pin-policy once|always|never] [--touch-policy never|always|cached] \
        [--expect-spki spki.der | --expect-sha256 sha256:HEX]

    ykman --device N piv keys attest 9a att.pem ; ykman --device N piv certificates export f9 f9.pem
    (--serial is required; the rest are checked when given)

TRUST. The two Yubico roots are PINNED by SHA-256 below and the vendored copies must match the pins,
so replacing a vendored file does not change what is trusted. Intermediates come from the vendored
file (Yubico publishes them at developers.yubico.com/PKI). Every link's signature, issuer name and
validity period is checked, and every issuer above f9 must be a CA.

OUTPUT. Verdict lines, KEY=value, in the style of hsm-key-attestation-verify.py:
YUBICO_CHAIN=verified|failed, ATTESTED_SERIAL, SERIAL_MATCHES, ATTESTED_PIN_POLICY,
ATTESTED_TOUCH_POLICY, POLICY_MATCHES, ATTESTED_KEY_SHA256, ATTESTED_KEY_MATCHES, ATTESTED_FIRMWARE.
Exit 0 only when the chain verifies and EVERY expectation given matches; 1 otherwise; 2 on a usage or
dependency problem, with DEPENDENCY_MISSING=<name> on the first line.
"""
import argparse
import datetime
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor", "yubico-attestation")
# SHA-256 of each root's DER. Pinned here, NOT read from the vendored file: the file is checked against these.
PINNED_ROOTS = {
    "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8": "Yubico Attestation Root 1",
    "63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546": "Yubico PIV Root CA Serial 263751",
}
OID_FIRMWARE = "1.3.6.1.4.1.41482.3.3"
OID_SERIAL = "1.3.6.1.4.1.41482.3.7"
OID_POLICY = "1.3.6.1.4.1.41482.3.8"
PIN_POLICY = {1: "never", 2: "once", 3: "always"}
TOUCH_POLICY = {1: "never", 2: "always", 3: "cached"}
MAX_DEPTH = 6

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:  # the ceremony venv has it; a bare python3 may not
    print("DEPENDENCY_MISSING=cryptography")
    sys.exit(2)


def load_all(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificates(f.read())


def der_sha256(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def trusted_roots():
    roots = []
    for name in ("yubico-attestation-root-1.pem", "yubico-piv-root-ca-263751.pem"):
        for cert in load_all(os.path.join(VENDOR, name)):
            if der_sha256(cert) not in PINNED_ROOTS:
                raise ValueError(f"vendored root {name} does not match its pinned SHA-256")
            roots.append(cert)
    return roots


def valid_now(cert, now):
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def verify_chain(attestation, f9, intermediates, roots, now):
    """Return (ok, description). attestation <- f9 <- … <- a pinned root, every link checked."""
    try:
        attestation.verify_directly_issued_by(f9)
    except Exception as err:  # InvalidSignature, ValueError (name mismatch), TypeError (key type)
        return False, f"the attestation is not signed by the f9 certificate ({type(err).__name__})"
    for cert, what in ((attestation, "attestation"), (f9, "f9")):
        if not valid_now(cert, now):
            return False, f"the {what} certificate is outside its validity period"
    pinned = {der_sha256(r): r for r in roots}
    current, path = f9, []
    for _ in range(MAX_DEPTH):
        if der_sha256(current) in pinned:
            return True, " <- ".join(["attestation", "f9"] + path)
        issuers = [c for c in intermediates + roots if c.subject == current.issuer]
        link = None
        for candidate in issuers:
            try:
                current.verify_directly_issued_by(candidate)
            except Exception:
                continue
            link = candidate
            break
        if link is None:
            return False, f"no trusted issuer verifies {current.subject.rfc4514_string()!r}"
        if not is_ca(link):
            return False, f"{link.subject.rfc4514_string()!r} is not a CA"
        if not valid_now(link, now):
            return False, f"{link.subject.rfc4514_string()!r} is outside its validity period"
        path.append(link.subject.rfc4514_string())
        current = link
    return False, "the chain is longer than any Yubico hierarchy"


def extension_bytes(cert, oid):
    try:
        return cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value.value
    except x509.ExtensionNotFound:
        return None


def der_integer(raw):
    if not raw or raw[0] != 0x02 or len(raw) < 3 or raw[1] != len(raw) - 2:
        return None
    return int.from_bytes(raw[2:], "big")


def attested_facts(attestation_pem, f9_pem, trust=None, now=None):
    """The chain verdict and the signed facts, for a caller that decides for itself (ceremony-manifest's
    `record`). `trust` is (intermediates, roots) and defaults to the vendored intermediates plus the
    PINNED Yubico roots. Anything else is a simulation's business, and the caller must say so.
    Raises ValueError on input that is not exactly one PEM certificate each."""
    certs = x509.load_pem_x509_certificates(attestation_pem)
    f9s = x509.load_pem_x509_certificates(f9_pem)
    if len(certs) != 1 or len(f9s) != 1:
        raise ValueError("expected exactly one attestation certificate and one f9 certificate")
    attestation, f9 = certs[0], f9s[0]
    intermediates, roots = trust if trust is not None else (
        load_all(os.path.join(VENDOR, "yubico-intermediates.pem")), trusted_roots())
    chained, how = verify_chain(attestation, f9, intermediates, roots,
                                now or datetime.datetime.now(datetime.timezone.utc))
    policy = extension_bytes(attestation, OID_POLICY)
    firmware = extension_bytes(attestation, OID_FIRMWARE)
    spki = attestation.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "chain": chained, "how": how,
        "serial": der_integer(extension_bytes(attestation, OID_SERIAL)),
        "pin_policy": PIN_POLICY.get(policy[0]) if policy and len(policy) >= 2 else None,
        "touch_policy": TOUCH_POLICY.get(policy[1]) if policy and len(policy) >= 2 else None,
        "firmware": ".".join(str(b) for b in firmware) if firmware and len(firmware) == 3 else None,
        "spki": spki,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--attestation", required=True, help="PEM from `ykman piv keys attest <slot>`")
    ap.add_argument("--f9", required=True, help="PEM from `ykman piv certificates export f9`")
    ap.add_argument("--serial", type=int, required=True, help="the device serial the key must be attested on")
    ap.add_argument("--pin-policy", choices=sorted(set(PIN_POLICY.values())))
    ap.add_argument("--touch-policy", choices=sorted(set(TOUCH_POLICY.values())))
    expect = ap.add_mutually_exclusive_group()
    expect.add_argument("--expect-spki", help="DER SubjectPublicKeyInfo the slot exports")
    expect.add_argument("--expect-sha256", help="sha256:HEX of that SPKI (a manifest public_key_sha256)")
    args = ap.parse_args(argv)

    try:
        attestation, = load_all(args.attestation)
        f9, = load_all(args.f9)
        intermediates = load_all(os.path.join(VENDOR, "yubico-intermediates.pem"))
        roots = trusted_roots()
    except (OSError, ValueError) as err:
        print(f"YUBICO_CHAIN=not-evaluated reason={err}")
        return 2

    ok = True
    chained, how = verify_chain(attestation, f9, intermediates, roots, datetime.datetime.now(datetime.timezone.utc))
    print(f"YUBICO_CHAIN={'verified' if chained else 'failed'} {how}")
    ok &= chained

    serial = der_integer(extension_bytes(attestation, OID_SERIAL))
    print(f"ATTESTED_SERIAL={serial if serial is not None else 'absent'}")
    match = serial == args.serial
    print(f"SERIAL_MATCHES={'yes' if match else 'no'}")
    ok &= match

    policy = extension_bytes(attestation, OID_POLICY)
    pin = PIN_POLICY.get(policy[0]) if policy and len(policy) >= 2 else None
    touch = TOUCH_POLICY.get(policy[1]) if policy and len(policy) >= 2 else None
    print(f"ATTESTED_PIN_POLICY={pin or 'absent'}")
    print(f"ATTESTED_TOUCH_POLICY={touch or 'absent'}")
    if args.pin_policy or args.touch_policy:
        match = (not args.pin_policy or pin == args.pin_policy) and (not args.touch_policy or touch == args.touch_policy)
        print(f"POLICY_MATCHES={'yes' if match else 'no'}")
        ok &= match

    firmware = extension_bytes(attestation, OID_FIRMWARE)
    print(f"ATTESTED_FIRMWARE={'.'.join(str(b) for b in firmware) if firmware and len(firmware) == 3 else 'absent'}")

    spki = attestation.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = "sha256:" + hashlib.sha256(spki).hexdigest()
    print(f"ATTESTED_KEY_SHA256={digest}")
    if args.expect_spki or args.expect_sha256:
        if args.expect_spki:
            with open(args.expect_spki, "rb") as f:
                match = f.read() == spki
        else:
            match = args.expect_sha256.lower() == digest
        print(f"ATTESTED_KEY_MATCHES={'yes' if match else 'no'}")
        ok &= match
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
