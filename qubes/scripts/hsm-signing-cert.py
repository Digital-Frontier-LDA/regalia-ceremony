#!/usr/bin/env python3
"""hsm-signing-cert.py — the certificate and the record of a signing key generated ON a SmartCard-HSM
(regalia#554, regalia-kms#57). Called by hsm-signing-key.sh; standard library only, run with `python3 -I`.

    hsm-signing-cert.py tbs      --public-key PUB.der --subject CN --days N --serial-hex HEX --out TBS.der
    hsm-signing-cert.py assemble --tbs TBS.der --signature SIG.bin --out CERT.pem
    hsm-signing-cert.py check    --certificate CERT.pem --public-key PUB.der
    hsm-signing-cert.py evidence --device-serial S --object-id ID --key-reference R --label L --public-key PUB.der
                                 --certificate CERT.pem --blob BLOB --out EVIDENCE.json

WHY A CERTIFICATE. The tools that sign a boot image take an X.509 certificate beside a key held in a
token (systemd-measure --certificate, sbsign --cert), and the Secure Boot certificate is what each KMS
host enrols. The key never leaves the card, so the certificate is built here as bytes to be signed
(`tbs`), the CARD signs them (pkcs11-tool --sign --mechanism SHA256-RSA-PKCS), and the signature is
put in place (`assemble`). A certificate that verifies under its own public key is then also a
signature the card made: `check` is the proof that the key at that object signs.

The certificate is self-signed, RSA-2048, sha256WithRSAEncryption, version 3, with basicConstraints
CA:FALSE (critical) and keyUsage digitalSignature (critical). Nothing in it is a trust decision: the
hosts trust the key because the root-signed measurement document and the enrolled Secure Boot
certificate name it, not because of what the certificate says.

NO VERDICT IN THE RECORD. `evidence` writes what was observed: the device serial, the object id and
key reference, the public key, the certificate, the SHA-256 of the wrapped blob. Whether they agree is
recomputed by whoever reads them (`check`).
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys

SCHEMA = "regalia.hsm-signing-key/v1"
SHA256_WITH_RSA = bytes.fromhex("06092a864886f70d01010b0500")      # AlgorithmIdentifier body: OID + NULL
RSA_ENCRYPTION_OID = bytes.fromhex("06092a864886f70d0101010500")


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
    tag_n, modulus, offset = read_tlv(key)
    require(tag_n == 0x02, "the RSA key has no modulus")
    return (len(modulus.lstrip(b"\0")) * 8)


def tbs_certificate(spki, common_name, days, serial, now=None):
    require(rsa_public_key(spki) == 2048, "the key is not RSA-2048")
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
        seq(SHA256_WITH_RSA),
        subject,                                           # issuer: self
        seq(utc(now), utc(now + datetime.timedelta(days=days))),
        subject,
        spki,
        tlv(0xA3, extensions))


def certificate(tbs, signature):
    require(len(signature) == 256, "the signature is not an RSA-2048 signature (%d bytes)" % len(signature))
    return seq(tbs, seq(SHA256_WITH_RSA), tlv(0x03, b"\0" + signature))


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
    tbs = body[:tbs_end]
    tag, algorithm, offset = read_tlv(body, tbs_end)
    require(algorithm == SHA256_WITH_RSA, "the certificate is not signed with sha256WithRSAEncryption")
    tag, bits, end = read_tlv(body, offset)
    require(tag == 0x03 and bits[:1] == b"\0" and end == len(body), "the certificate's signature is malformed")
    fields = []
    _, tbs_body, _ = read_tlv(tbs)
    offset = 0
    while offset < len(tbs_body):
        tag, _, nxt = read_tlv(tbs_body, offset)
        fields.append(tbs_body[offset:nxt])
        offset = nxt
    require(len(fields) == 8, "the certificate's fields are not the ones this tool writes")
    return tbs, fields[6], bits[1:]


def verifies(spki, data, signature):
    """RSASSA-PKCS1-v1_5 / SHA-256, checked by openssl (this file implements no cryptography)."""
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
    c = sub.add_parser("check")
    c.add_argument("--certificate", required=True)
    c.add_argument("--public-key", required=True)
    c = sub.add_parser("evidence")
    for a in ("--device-serial", "--object-id", "--key-reference", "--label", "--public-key", "--certificate", "--blob", "--out"):
        c.add_argument(a, required=True)
    a = p.parse_args(argv)
    try:
        if a.command == "tbs":
            _write(a.out, tbs_certificate(_read(a.public_key), a.subject, a.days, a.serial_hex))
        elif a.command == "assemble":
            _write(a.out, pem(certificate(_read(a.tbs), _read(a.signature))), "w")
        elif a.command == "check":
            tbs, spki, signature = certificate_parts(unpem(_read(a.certificate).decode("ascii")))
            require(spki == _read(a.public_key), "the certificate is for another public key than the card's")
            require(verifies(spki, tbs, signature), "the certificate's signature does not verify under its own key")
            print("CERTIFICATE-VERIFIES %s" % hashlib.sha256(spki).hexdigest())
        else:
            require(re.fullmatch(r"[A-Za-z0-9]{4,32}", a.device_serial) is not None, "--device-serial is not a serial")
            require(re.fullmatch(r"[0-9a-f]{2,4}", a.object_id) is not None, "--object-id is not a hex id")
            require(re.fullmatch(r"[1-9][0-9]{0,2}", a.key_reference) is not None, "--key-reference is not a key reference")
            spki, text = _read(a.public_key), _read(a.certificate).decode("ascii")
            certificate_parts(unpem(text))
            record = {"evidence": SCHEMA, "device_serial": a.device_serial, "object_id": a.object_id,
                      "key_reference": int(a.key_reference), "label": a.label,
                      "public_key_der_b64": base64.b64encode(spki).decode("ascii"),
                      "public_key_sha256": hashlib.sha256(spki).hexdigest(), "certificate_pem": text,
                      "wrapped_blob_sha256": hashlib.sha256(_read(a.blob)).hexdigest()}
            _write(a.out, json.dumps(record, indent=2, sort_keys=True) + "\n", "w")
        return 0
    except (Refused, OSError, ValueError) as refusal:
        print("hsm-signing-cert: REFUSED: %s" % refusal, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
