#!/usr/bin/env python3
"""hsm-signing-cert.py — the certificate and the record of a signing key generated ON a SmartCard-HSM
(regalia#554, regalia-kms#57). Called by hsm-signing-key.sh; standard library only, run with `python3 -I`.

    hsm-signing-cert.py tbs      --public-key PUB.der --subject CN --days N --serial-hex HEX --out TBS.der
    hsm-signing-cert.py assemble --tbs TBS.der --signature SIG.bin --out CERT.pem
    hsm-signing-cert.py check    --certificate CERT.pem --public-key PUB.der
    hsm-signing-cert.py key-type --public-key PUB.der              (prints rsa:2048 or ec:prime256v1)
    hsm-signing-cert.py evidence --device-serial S --object-id ID --key-reference R --label L --public-key PUB.der
                                 --certificate CERT.pem --blob BLOB --devaut DEVAUT.bin --attestation ATTEST.bin
                                 --out EVIDENCE.json

WHY A CERTIFICATE. The tools that sign a boot image take an X.509 certificate beside a key held in a
token (systemd-measure --certificate, sbsign --cert), and the Secure Boot certificate is what each KMS
host enrols. The key never leaves the card, so the certificate is built here as bytes to be signed
(`tbs`), the CARD signs them (pkcs11-tool --sign --mechanism SHA256-RSA-PKCS), and the signature is
put in place (`assemble`). A certificate that verifies under its own public key is then also a
signature the card made: `check` is the proof that the key at that object signs.

TWO KEY TYPES. RSA-2048 (sha256WithRSAEncryption; the card signs with SHA256-RSA-PKCS), for the boot
image's keys (regalia#554); and ECDSA P-256 (ecdsa-with-SHA256; the card signs with ECDSA-SHA256 and
pkcs11-tool --signature-format openssl gives the DER ECDSA-Sig-Value X.509 carries), for the membership
root (regalia-kms#156, option C). The type is read from the public key, and the signature algorithm is
the one that type implies, never chosen separately.

The certificate is self-signed, version 3, with basicConstraints
CA:FALSE (critical) and keyUsage digitalSignature (critical). Nothing in it is a trust decision: the
hosts trust the key because the root-signed measurement document and the enrolled Secure Boot
certificate name it, not because of what the certificate says.

NO VERDICT IN THE RECORD. `evidence` writes what was observed: the device serial, the object id and
key reference, the public key, the certificate, the SHA-256 of the wrapped blob, and the card's own
evidence that it generated the key: its device certificate C.DevAut (EF 2F02) and the authenticated
request the generation left in EF CE<key reference>, both as read. Whether they agree is recomputed by
whoever reads them (`check`; hsm-key-attestation-verify.py for the device's).
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys

SCHEMA = "regalia.hsm-signing-key/v2"     # v2: the key type, and the card's device certificate and key attestation
SHA256_WITH_RSA = bytes.fromhex("06092a864886f70d01010b0500")      # AlgorithmIdentifier body: OID + NULL
RSA_ENCRYPTION_OID = bytes.fromhex("06092a864886f70d0101010500")
ECDSA_WITH_SHA256 = bytes.fromhex("06082a8648ce3d040302")          # AlgorithmIdentifier body: OID, NO parameters (RFC 5758)
EC_P256 = bytes.fromhex("06072a8648ce3d0201" "06082a8648ce3d030107")  # id-ecPublicKey, prime256v1


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


# ---- DER, as little of it as a certificate needs ----

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def read_tlv(data, offset=0):
    """(tag, body, end) of the TLV at `offset`; refuses anything malformed."""
    require(offset + 2 <= len(data), "truncated DER")
    tag, first = data[offset], data[offset + 1]
    offset += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        require(1 <= count <= 4 and offset + count <= len(data), "bad DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    require(offset + length <= len(data), "DER length beyond the data")
    return tag, data[offset:offset + length], offset + length


def utc(when):
    # UTCTime up to 2049, GeneralizedTime after (RFC 5280 4.1.2.5)
    if when.year < 2050:
        return tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def name(common_name):
    require(re.fullmatch(r"[A-Za-z0-9 ,._()-]{1,64}", common_name) is not None, "--subject must be a short plain name")
    attribute = seq(tlv(0x06, bytes.fromhex("550403")), tlv(0x0C, common_name.encode("ascii")))   # CN, UTF8String
    return seq(tlv(0x31, attribute))


def rsa_public_key(spki):
    """The modulus size of an RSA SubjectPublicKeyInfo; refuses anything else."""
    tag, body, end = read_tlv(spki)
    require(tag == 0x30 and end == len(spki), "the public key is not one DER SubjectPublicKeyInfo")
    tag, algorithm, offset = read_tlv(body)
    require(tag == 0x30 and algorithm == RSA_ENCRYPTION_OID, "the public key is not RSA (rsaEncryption)")
    tag, bits, _ = read_tlv(body, offset)
    require(tag == 0x03 and bits[:1] == b"\0", "the public key's bit string is malformed")
    tag, key, _ = read_tlv(bits[1:])
    require(tag == 0x30, "the RSA key is not a SEQUENCE")
    tag_n, modulus, offset = read_tlv(key)
    require(tag_n == 0x02, "the RSA key has no modulus")
    return int.from_bytes(modulus, "big").bit_length()       # in bits: 2041 is not 2048


def key_type(spki):
    """"rsa:2048" or "ec:prime256v1" for the two keys this tool certifies; refuses any other."""
    tag, body, end = read_tlv(spki)
    require(tag == 0x30 and end == len(spki), "the public key is not one DER SubjectPublicKeyInfo")
    tag, algorithm, offset = read_tlv(body)
    require(tag == 0x30, "the public key has no algorithm")
    if algorithm == EC_P256:
        tag, bits, end = read_tlv(body, offset)
        require(tag == 0x03 and end == len(body) and bits[:2] == b"\0\x04" and len(bits) == 66,
                "the P-256 public key is not one uncompressed point")
        return "ec:prime256v1"
    require(rsa_public_key(spki) == 2048, "the key is not RSA-2048 (nor ECDSA P-256)")
    return "rsa:2048"


def signature_algorithm(spki):
    return SHA256_WITH_RSA if key_type(spki) == "rsa:2048" else ECDSA_WITH_SHA256


def ecdsa_signature(signature):
    """A DER ECDSA-Sig-Value of two positive INTEGERs no longer than a P-256 scalar; refuses anything else
    (a raw r||s from a tool that was not asked for --signature-format openssl, for instance)."""
    tag, body, end = read_tlv(signature)
    require(tag == 0x30 and end == len(signature), "the ECDSA signature is not one DER SEQUENCE")
    tag_r, r, offset = read_tlv(body)
    tag_s, s, offset = read_tlv(body, offset)
    require(tag_r == 0x02 and tag_s == 0x02 and offset == len(body), "the ECDSA signature is not two INTEGERs")
    for v in (r, s):
        require(1 <= len(v) <= 33 and v[0] < 0x80 and int.from_bytes(v, "big") > 0, "the ECDSA signature's integers are out of range")
    return signature


def tbs_certificate(spki, common_name, days, serial, now=None):
    algorithm = signature_algorithm(spki)
    require(1 <= days <= 7300, "--days must be 1 to 7300")
    require(re.fullmatch(r"[0-9a-f]{16,40}", serial) is not None and serial[0] in "1234567", "--serial-hex must be 16 to 40 hex, positive")
    now = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
    subject = name(common_name)
    extensions = seq(
        seq(tlv(0x06, bytes.fromhex("551d13")), tlv(0x01, b"\xff"), tlv(0x04, seq())),                        # basicConstraints, critical, CA:FALSE
        seq(tlv(0x06, bytes.fromhex("551d0f")), tlv(0x01, b"\xff"), tlv(0x04, tlv(0x03, bytes([0x07, 0x80])))))  # keyUsage, critical, digitalSignature
    return seq(
        tlv(0xA0, tlv(0x02, b"\x02")),                     # version 3
        tlv(0x02, bytes.fromhex(serial)),
        seq(algorithm),
        subject,                                           # issuer: self
        seq(utc(now), utc(now + datetime.timedelta(days=days))),
        subject,
        spki,
        tlv(0xA3, extensions))


def certificate(tbs, signature):
    tag, body, _ = read_tlv(tbs)
    require(tag == 0x30, "the TBSCertificate is not a SEQUENCE")
    offset = 0
    for _ in range(6):                                        # version, serial, algorithm, issuer, validity, subject
        _, _, offset = read_tlv(body, offset)
    _, _, end = read_tlv(body, offset)
    spki = body[offset:end]
    algorithm = signature_algorithm(spki)
    if algorithm == SHA256_WITH_RSA:
        require(len(signature) == 256, "the signature is not an RSA-2048 signature (%d bytes)" % len(signature))
    else:
        ecdsa_signature(signature)
    return seq(tbs, seq(algorithm), tlv(0x03, b"\0" + signature))


def pem(der):
    body = base64.b64encode(der).decode("ascii")
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END CERTIFICATE-----\n"


def unpem(text):
    m = re.fullmatch(r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?", text)
    require(m is not None, "not one PEM certificate")
    return base64.b64decode(m.group(1), validate=False)


def certificate_parts(der):
    """(tbs, its public key SPKI, signature) of a certificate this tool writes."""
    tag, body, end = read_tlv(der)
    require(tag == 0x30 and end == len(der), "not one DER certificate")
    tag, _, tbs_end = read_tlv(body)
    require(tag == 0x30, "the certificate's first field is not a TBSCertificate")
    tbs = body[:tbs_end]
    tag, algorithm, offset = read_tlv(body, tbs_end)
    require(tag == 0x30 and algorithm in (SHA256_WITH_RSA, ECDSA_WITH_SHA256),
            "the certificate is not signed with sha256WithRSAEncryption or ecdsa-with-SHA256")
    tag, bits, end = read_tlv(body, offset)
    require(tag == 0x03 and bits[:1] == b"\0" and end == len(body), "the certificate's signature is malformed")
    fields = []
    _, tbs_body, _ = read_tlv(tbs)
    offset = 0
    while offset < len(tbs_body):
        tag, _, nxt = read_tlv(tbs_body, offset)
        fields.append(tbs_body[offset:nxt])
        offset = nxt
    # version, serial, signature algorithm, issuer, validity, subject, public key, extensions: by tag, and the
    # inner algorithm must be the outer one. A structure that merely has eight parts is not a certificate.
    require([f[0] for f in fields] == [0xA0, 0x02, 0x30, 0x30, 0x30, 0x30, 0x30, 0xA3], "the certificate's fields are not the ones this tool writes")
    require(fields[2] == seq(algorithm), "the certificate names another signature algorithm inside than outside")
    require(fields[3] == fields[5], "the certificate is not self-signed (issuer and subject differ)")
    require(signature_algorithm(fields[6]) == algorithm, "the certificate's signature algorithm is not its key's")
    if algorithm == ECDSA_WITH_SHA256:
        ecdsa_signature(bits[1:])
    return tbs, fields[6], bits[1:]


def verifies(spki, data, signature):
    """RSASSA-PKCS1-v1_5 / SHA-256, or ECDSA / SHA-256 over a DER signature, checked by openssl (this file
    implements no cryptography)."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as work:
        paths = {}
        for n, content in (("pub.der", spki), ("data", data), ("sig", signature)):
            paths[n] = os.path.join(work, n)
            with open(paths[n], "wb") as f:
                f.write(content)
        pub = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", paths["pub.der"], "-out", os.path.join(work, "pub.pem")],
                             capture_output=True)
        require(pub.returncode == 0, "openssl cannot read the public key")
        done = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(work, "pub.pem"), "-signature", paths["sig"], paths["data"]],
                              capture_output=True)
    return done.returncode == 0


def blob_kcv(blob):
    """The DKEK key check value a sc-hsm-tool --wrap-key blob names: SEQUENCE { OCTET STRING { KCV(8) || … }, … }.

    Measured 2026-10-03 on DENK0404380: the eight bytes equal sc-hsm-tool's "DKEK key check value" of the card
    that wrapped it, and a card of another DKEK refuses the blob with "Data object not found".
    """
    tag, body, end = read_tlv(blob)
    require(tag == 0x30 and end == len(blob), "the blob is not one DER SEQUENCE")
    tag, key_blob, _ = read_tlv(body)
    require(tag == 0x04 and len(key_blob) > 8, "the blob does not start with a key blob")
    return key_blob[:8].hex().upper()


def _read(path, limit=1 << 20):
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    require(len(data) <= limit, "%s is too large" % path)
    return data


def _write(path, data, mode="wb"):
    # O_EXCL: an output that already exists is refused, never overwritten
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, mode) as f:
        f.write(data)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("tbs")
    c.add_argument("--public-key", required=True)
    c.add_argument("--subject", required=True)
    c.add_argument("--days", type=int, required=True)
    c.add_argument("--serial-hex", required=True)
    c.add_argument("--out", required=True)
    c = sub.add_parser("assemble")
    c.add_argument("--tbs", required=True)
    c.add_argument("--signature", required=True)
    c.add_argument("--out", required=True)
    c = sub.add_parser("unhex")
    c.add_argument("--out", required=True)
    c = sub.add_parser("key-type")
    c.add_argument("--public-key", required=True)
    c = sub.add_parser("check")
    c.add_argument("--certificate", required=True)
    c.add_argument("--public-key", required=True)
    c = sub.add_parser("blob-kcv")
    c.add_argument("--blob", required=True)
    c = sub.add_parser("evidence")
    for a in ("--device-serial", "--object-id", "--key-reference", "--label", "--public-key", "--certificate", "--blob",
              "--dkek-kcv", "--devaut", "--attestation", "--out"):
        c.add_argument(a, required=True)
    a = p.parse_args(argv)
    try:
        if a.command == "tbs":
            _write(a.out, tbs_certificate(_read(a.public_key), a.subject, a.days, a.serial_hex))
        elif a.command == "assemble":
            _write(a.out, pem(certificate(_read(a.tbs), _read(a.signature))), "w")
        elif a.command == "unhex":
            text = sys.stdin.read(1 << 22).strip()
            require(re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", text) is not None, "not hex")
            _write(a.out, bytes.fromhex(text))
        elif a.command == "key-type":
            print(key_type(_read(a.public_key)))
        elif a.command == "check":
            tbs, spki, signature = certificate_parts(unpem(_read(a.certificate).decode("ascii")))
            require(spki == _read(a.public_key), "the certificate is for another public key than the card's")
            require(verifies(spki, tbs, signature), "the certificate's signature does not verify under its own key")
            print("CERTIFICATE-VERIFIES %s" % hashlib.sha256(spki).hexdigest())
        elif a.command == "blob-kcv":
            print(blob_kcv(_read(a.blob)))
        else:
            require(re.fullmatch(r"[A-Za-z0-9]{4,32}", a.device_serial) is not None, "--device-serial is not a serial")
            require(re.fullmatch(r"[0-9a-f]{2,4}", a.object_id) is not None, "--object-id is not a hex id")
            require(re.fullmatch(r"[1-9][0-9]{0,2}", a.key_reference) is not None, "--key-reference is not a key reference")
            spki, text = _read(a.public_key), _read(a.certificate).decode("ascii")
            _, cert_key, _ = certificate_parts(unpem(text))
            require(cert_key == spki, "the certificate is for another public key than the card's")
            devaut, attestation = _read(a.devaut), _read(a.attestation)
            require(devaut and attestation, "the device certificate and the attestation must not be empty")
            blob = _read(a.blob)
            require(blob_kcv(blob) == a.dkek_kcv, "the blob was wrapped under DKEK %s, not %s" % (blob_kcv(blob), a.dkek_kcv))
            record = {"evidence": SCHEMA, "device_serial": a.device_serial, "object_id": a.object_id, "key_type": key_type(spki),
                      "devaut_b64": base64.b64encode(devaut).decode("ascii"), "devaut_sha256": hashlib.sha256(devaut).hexdigest(),
                      "attestation_b64": base64.b64encode(attestation).decode("ascii"),
                      "attestation_sha256": hashlib.sha256(attestation).hexdigest(),
                      "key_reference": int(a.key_reference), "label": a.label,
                      "public_key_der_b64": base64.b64encode(spki).decode("ascii"),
                      "public_key_sha256": hashlib.sha256(spki).hexdigest(), "certificate_pem": text,
                      "dkek_kcv": a.dkek_kcv, "wrapped_blob_sha256": hashlib.sha256(blob).hexdigest()}
            _write(a.out, json.dumps(record, indent=2, sort_keys=True) + "\n", "w")
        return 0
    except (Refused, OSError, ValueError) as refusal:
        print("hsm-signing-cert: REFUSED: %s" % refusal, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
