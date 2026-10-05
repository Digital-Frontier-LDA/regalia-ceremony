"""The card-ceremony record's test vectors (regalia-ceremony#111 step 2, ADR-0002 D30), for this repository's writer and
regalia-kms's verifier alike. Every key comes from a fixed seed and Ed25519 signs deterministically, so running this again
writes the same bytes: test_card_record.py checks that the committed files are exactly what it makes.

    python3 -Es make.py [DIR]      (DIR defaults to this file's directory)

Each vector is a document {"record": ..., "signature": "<128 hex>"} for the root in root.hex. expect.json gives, per file,
"ok" or the reason a verifier must refuse it. The vectors whose content breaks a rule are signed correctly, so they test
the content rules and not the signature."""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import sys

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "..", "..", "scripts", "offline-keys.py")
_loader = importlib.machinery.SourceFileLoader("offline_keys", SCRIPT)
_spec = importlib.util.spec_from_loader("offline_keys", _loader)
ok = importlib.util.module_from_spec(_spec)
_loader.exec_module(ok)


def key(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def raw(private):
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def ssh_line(private):
    pub = bytes.fromhex(raw(private))
    blob = b"".join(len(p).to_bytes(4, "big") + p for p in (b"ssh-ed25519", pub))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


ROOT, OTHER_ROOT = key(1), key(2)
MAIN, BACKUP, RELEASE, MAIN_SSH, BACKUP_SSH = key(11), key(12), key(13), key(21), key(22)

# ---- a STAND-IN Yubico OpenPGP attestation hierarchy (regalia-kms#400, agreed with regalia-kms-1e) --------------------
# Real Yubico signs with RSA; RSA keys cannot come from a fixed seed, so the stand-in's issuers are Ed25519 from fixed
# seeds (1e's opgpattest verifies them): root -> "Yubico OPGP Attestation B 1" -> each card's "YubiKey OPGP Attestation"
# CA -> the SIG, DEC and AUT leaves, with Yubico's extensions as DER (1.3.6.1.4.1.41482.5.x, measured on YubiKey
# 35718625: 5.2 INTEGER 1 generated, 5.3 OCTET firmware, 5.4 OCTET fingerprint, 5.5 OCTET generation time, 5.7 INTEGER
# serial, 5.8 OCTET touch 02 fixed). NOT trusted anywhere but a test that pins this root.
YROOT, YB1 = key(31), key(32)
CARD_CA = {"40000001": key(33), "40000002": key(34)}
DEC = {"40000001": x25519.X25519PrivateKey.from_private_bytes(bytes([41]) * 32),
       "40000002": x25519.X25519PrivateKey.from_private_bytes(bytes([42]) * 32)}
CARDS = {"40000001": {"sig": MAIN, "aut": MAIN_SSH, "primary": "A1" * 20, "subkey": "B1" * 20, "aut_fpr": "F1" * 20},
         "40000002": {"sig": BACKUP, "aut": BACKUP_SSH, "primary": "A2" * 20, "subkey": "B2" * 20, "aut_fpr": "F2" * 20}}
GENERATED = 1791115200                              # 2026-10-04T12:00:00Z, each key's generation time on its card
_NOT_BEFORE, _NOT_AFTER = datetime.datetime(2024, 12, 1, tzinfo=datetime.timezone.utc), datetime.datetime(9999, 12, 31, tzinfo=datetime.timezone.utc)


def _der_integer(n):
    body = n.to_bytes((n.bit_length() + 8) // 8, "big")         # a leading 0 when the high bit is set
    return b"\x02" + bytes([len(body)]) + body


def _der_octets(data):
    return b"\x04" + bytes([len(data)]) + data


def _cert(subject, issuer_name, issuer_key, public, serial, extensions=(), ca=False):
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])).public_key(public)
               .serial_number(serial).not_valid_before(_NOT_BEFORE).not_valid_after(_NOT_AFTER))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    for oid, value in extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.41482.5." + oid), value), critical=False)
    return builder.sign(issuer_key, None)


def attestation_hierarchy():
    """(root PEM, intermediates PEM): the stand-in Yubico root and its "Yubico OPGP Attestation B 1"."""
    root = _cert("Yubico Attestation Root 1 (STAND-IN, tests only)", "Yubico Attestation Root 1 (STAND-IN, tests only)", YROOT,
                 YROOT.public_key(), 1, ca=True)
    b1 = _cert("Yubico OPGP Attestation B 1", root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, YROOT, YB1.public_key(), 2, ca=True)
    return root.public_bytes(serialization.Encoding.PEM), b1.public_bytes(serialization.Encoding.PEM)


def card_attestations(serial):
    """{name: DER} for one owner card: att.der (its "YubiKey OPGP Attestation" CA) and sig/dec/aut.attest.der, the
    leaves with the extensions a real card writes: generated on the card, this serial, the slot's fingerprint, touch fixed."""
    card = CARDS[serial]
    ca = _cert("YubiKey OPGP Attestation", "Yubico OPGP Attestation B 1", YB1, CARD_CA[serial].public_key(), int(serial), ca=True)
    out = {"att.der": ca.public_bytes(serialization.Encoding.DER)}
    for n, (slot, public, fpr) in enumerate((("SIG", card["sig"].public_key(), card["primary"]), ("DEC", DEC[serial].public_key(), card["subkey"]),
                                             ("AUT", card["aut"].public_key(), card["aut_fpr"]))):
        extensions = (("3", _der_octets(bytes([5, 7, 4]))), ("7", _der_integer(int(serial))), ("8", _der_octets(b"\x02")),
                      ("9", _der_octets(b"\x01")), ("4", _der_octets(bytes.fromhex(fpr))),
                      ("5", _der_octets(GENERATED.to_bytes(4, "big"))), ("2", _der_integer(1)))
        leaf = _cert("YubiKey OPGP Attestation " + slot, "YubiKey OPGP Attestation", CARD_CA[serial], public, int(serial) * 10 + n, extensions)
        out["%s.attest.der" % slot.lower()] = leaf.public_bytes(serialization.Encoding.DER)
    return out


def attestation_sha256(serial):
    certs = card_attestations(serial)
    return {slot: hashlib.sha256(certs["%s.attest.der" % slot]).hexdigest() for slot in ("sig", "dec", "aut")}


def valid_record():
    entry = {"alg": "ed25519", "key": raw(ROOT)}
    return {
        "schema": ok.SCHEMA_CARDS, "event": "card-ceremony", "sequence": 1, "supersedes": "",
        "owner_keys": [{"role": "owner-main", "serial": "40000001", "alg": "ed25519", "key": raw(MAIN), "attested": True,
                        "attestation_sha256": attestation_sha256("40000001")},
                       {"role": "owner-backup", "serial": "40000002", "alg": "ed25519", "key": raw(BACKUP), "attested": True,
                        "attestation_sha256": attestation_sha256("40000002")}],
        "ownerauth_recipients": [{"serial": "40000001", "primary": "A1" * 20, "subkey": "B1" * 20},
                                 {"serial": "40000002", "primary": "A2" * 20, "subkey": "B2" * 20}],
        "ssh_signers": [{"serial": "40000001", "key": ssh_line(MAIN_SSH)}, {"serial": "40000002", "key": ssh_line(BACKUP_SSH)}],
        "release_key": {"alg": "ed25519", "key": raw(RELEASE), "fingerprint": "C3" * 20, "cards": ["40000003", "40000004"],
                        "imported": True, "attested": False},
        "session": "0123456789abcdef0123456789abcdef", "root_entry": entry, "root_fingerprint": ok.root_fingerprint(entry),
        "tool": "card-ceremony-vectors/1", "at": "2026-10-04T12:00:00Z"}


def sequence_two():
    """The card record after valid.json's: sequence 2, superseding it (a rotation, a replacement card)."""
    second = valid_record()
    second.update(sequence=2, supersedes=ok.card_record_digest(valid_record()), session="fedcba9876543210fedcba9876543210",
                  at="2026-10-05T12:00:00Z")
    return second


def rebuilt_three():
    """The record a rebuild signs after losing the state directory that held 1 and 2 (regalia-kms#406): 2's content,
    sequence 3, superseding 2."""
    third = sequence_two()
    third.update(sequence=3, supersedes=ok.card_record_digest(sequence_two()), session="00112233445566778899aabbccddeeff",
                 at="2026-10-06T12:00:00Z")
    return third


def rebuild_record():
    """The rebuild's own root-signed record, under its own domain, for the rebuilt state directories below."""
    entry = {"alg": "ed25519", "key": raw(ROOT)}
    disc = (json.dumps(signed(sequence_two()), sort_keys=True, indent=1) + "\n").encode()
    record = {"schema": ok.SCHEMA_REBUILD, "event": "card-record-rebuild",
              "baseline": {"sequence": 2, "digest": ok.card_record_digest(sequence_two()), "source": "chain"},
              "disc_record_sha256": __import__("hashlib").sha256(disc).hexdigest(),
              "rebuilt": {"sequence": 3, "digest": ok.card_record_digest(rebuilt_three())}, "root_entry": entry,
              "root_fingerprint": ok.root_fingerprint(entry), "session": "00112233445566778899aabbccddeeff",
              "tool": "card-ceremony-vectors/1", "at": "2026-10-06T12:00:00Z"}
    return json.dumps({"record": record, "signature": ROOT.sign(ok.REBUILD_DOMAIN + ok.canonical(record)).hex()}, sort_keys=True) + "\n"


def signed(record, private=ROOT, domain=ok.RECORD_DOMAIN):
    return {"record": record, "signature": private.sign(domain + ok.canonical(record)).hex()}


def vectors():
    """(file name, document, expected): expected is "ok" or the refusal reason card_record_check/verify_card_record gives."""
    out = [("valid.json", signed(valid_record()), "ok")]
    bad = signed(valid_record())
    bad["signature"] = bad["signature"][:-2] + ("00" if bad["signature"][-2:] != "00" else "01")
    out.append(("bad-signature.json", bad, "the signature does not verify under the pinned root"))
    out.append(("wrong-domain.json", signed(valid_record(), domain=b"regalia-membership/v1\0"),
                "the signature does not verify under the pinned root"))
    r = valid_record()
    r["release_key"]["key"] = r["owner_keys"][0]["key"]
    out.append(("release-is-owner.json", signed(r), "the release key is an owner key: the release cards hold no owner key (D30.7)"))
    r = valid_record()
    del r["owner_keys"][1]
    out.append(("missing-owner-backup.json", signed(r), "owner_keys holds exactly the two owner cards' SIG keys (D30.7)"))
    r = valid_record()
    r["owner_keys"][0]["comment"] = "an extra field"
    out.append(("unknown-field.json", signed(r), "owner_keys[0] has an unknown field: comment"))
    out.append(("sequence-2.json", signed(sequence_two()), "ok"))
    out.append(("rebuilt-3.json", signed(rebuilt_three()), "ok"))
    r = valid_record()
    r["supersedes"] = ok.card_record_digest(valid_record())
    out.append(("first-supersedes.json", signed(r), "the first card record (sequence 1) supersedes nothing: supersedes is \"\""))
    r = valid_record()
    r["root_entry"] = {"alg": "ed25519", "key": raw(OTHER_ROOT)}
    r["root_fingerprint"] = ok.root_fingerprint(r["root_entry"])
    out.append(("other-root.json", signed(r, OTHER_ROOT), "the record names another root than the pinned one"))
    return out


def log_line(record, at, **change):
    line = {"kind": "card-record", "sequence": record["sequence"], "digest": ok.card_record_digest(record),
            "key": record["root_entry"]["key"], "at": at}
    line.update(change)
    return json.dumps(line, sort_keys=True)


def freshness():
    """The card-record freshness cases (regalia-kms#403), shared with regalia-kms's consumer: each a state directory
    (its marker, or none, and its signing record, verbatim) and the record judged in it. A reader copies a case's
    directory, makes it 0700 and its marker 0600 (git keeps no modes), then runs read_signing_state and
    card_record_current. Returns {case: (marker text or None, signing record text, record file, expected, rebuild
    record text or None, the chain's pin or None)}: a rebuilt directory (regalia-kms#406) also holds its rebuild record,
    and a case with a pin is judged as after genesis, card_record_current(..., pin=)."""
    one, two = log_line(valid_record(), "2026-10-04T12:00:01Z"), log_line(sequence_two(), "2026-10-05T12:00:01Z")
    marker = json.dumps({"schema": ok.SCHEMA_SIGNING_STATE, "root": raw(ROOT)}, sort_keys=True) + "\n"
    other = json.dumps({"schema": ok.SCHEMA_SIGNING_STATE, "root": raw(OTHER_ROOT)}, sort_keys=True) + "\n"
    manifest = json.dumps({"kind": "manifest", "epoch": 1}, sort_keys=True)
    d2, d3 = ok.card_record_digest(sequence_two()), ok.card_record_digest(rebuilt_three())
    base = json.dumps({"kind": ok.BASELINE_KIND, "sequence": 2, "digest": d2, "key": raw(ROOT), "at": "2026-10-06T12:00:00Z",
                       "source": "chain"}, sort_keys=True)
    three = log_line(rebuilt_three(), "2026-10-06T12:00:01Z")
    rb = rebuild_record()
    rebuilt = {
        "current-rebuilt": (marker, base + "\n" + three + "\n", "rebuilt-3.json", "ok", rb, None),
        "current-rebuilt-pinned": (marker, base + "\n" + three + "\n", "rebuilt-3.json", "ok", rb, (3, d3)),
        "pin-mismatch": (marker, base + "\n" + three + "\n", "rebuilt-3.json", "this card record is not the one the chain pins (sequence 2)",
                         rb, (2, d2)),
        "baseline-not-first": (marker, three + "\n" + base + "\n", "rebuilt-3.json",
                               "a card-record-baseline line is not the first card line of the signing record", rb, None),
        "two-baselines": (marker, base + "\n" + base + "\n" + three + "\n", "rebuilt-3.json",
                          "the signing record holds more than one card-record-baseline line", rb, None),
        "rebuild-record-missing": (marker, base + "\n" + three + "\n", "rebuilt-3.json", "the signing record has a baseline but", None, None),
    }
    plain = {
        "current-1": (marker, one + "\n", "valid.json", "ok"),
        "current-2": (marker, one + "\n" + manifest + "\n" + two + "\n", "sequence-2.json", "ok"),
        "superseded": (marker, one + "\n" + two + "\n", "valid.json", "this card record is not the newest the root signed (sequence 1 of 2)"),
        "gap": (marker, two + "\n", "sequence-2.json", "the signing record's card-record lines are not 1..1 without a gap"),
        "foreign-key": (marker, one + "\n" + log_line(sequence_two(), "2026-10-05T12:00:01Z", key="00" * 32) + "\n", "sequence-2.json",
                        "a card-record line names another root than the pinned one"),
        "torn-line": (marker, one + "\n" + two[:40] + "\n", "sequence-2.json", "line 2 of the signing record is not JSON (a torn write?)"),
        "not-an-object": (marker, one + "\n[1, 2]\n", "valid.json", "line 2 of the signing record is not an object with a kind"),
        "bool-sequence": (marker, log_line(valid_record(), "2026-10-04T12:00:01Z", sequence=True) + "\n", "valid.json",
                          "a card-record line of the signing record is malformed (sequence an integer, digest 64 hex)"),
        "no-marker": (None, one + "\n", "valid.json", "has no regalia-signing-state.json"),
        "marker-other-root": (other, one + "\n", "valid.json", "regalia-signing-state.json names another root than the pinned one"),
    }
    return dict({case: value + (None, None) for case, value in plain.items()}, **rebuilt)


def write(directory):
    for name, document, _ in vectors():
        with open(os.path.join(directory, name), "w") as f:
            f.write(json.dumps(document, sort_keys=True, indent=1) + "\n")
    with open(os.path.join(directory, "expect.json"), "w") as f:
        f.write(json.dumps({name: expected for name, _, expected in vectors()}, sort_keys=True, indent=1) + "\n")
    with open(os.path.join(directory, "root.hex"), "w") as f:
        f.write(raw(ROOT) + "\n")
    cases = freshness()
    for case, (marker, log, _, _, rebuild, _) in cases.items():
        where = os.path.join(directory, "freshness", case)
        os.makedirs(where, exist_ok=True)
        if marker is not None:
            with open(os.path.join(where, ok.SIGNING_STATE), "w") as f:
                f.write(marker)
        if rebuild is not None:
            with open(os.path.join(where, ok.REBUILD_RECORD), "w") as f:
                f.write(rebuild)
        with open(os.path.join(where, ok.SIGNING_RECORD), "w") as f:
            f.write(log)
    with open(os.path.join(directory, "freshness-expect.json"), "w") as f:
        f.write(json.dumps({case: dict({"record": record, "expect": expected}, **({"pin": list(pin)} if pin else {}))
                            for case, (_, _, record, expected, _, pin) in cases.items()}, sort_keys=True, indent=1) + "\n")
    # the owner cards' attestation certificates under the stand-in hierarchy (regalia-kms#400): one directory per card,
    # as the producer lays them out, and the stand-in root and intermediates a test pins in place of Yubico's
    root_pem, intermediates_pem = attestation_hierarchy()
    for serial in CARDS:
        where = os.path.join(directory, "attestations", "owner-card-%s" % serial)
        os.makedirs(where, exist_ok=True)
        for name, der in card_attestations(serial).items():
            with open(os.path.join(where, name), "wb") as f:
                f.write(der)
    with open(os.path.join(directory, "attestations", "standin-yubico-root.pem"), "wb") as f:
        f.write(root_pem)
    with open(os.path.join(directory, "attestations", "standin-yubico-intermediates.pem"), "wb") as f:
        f.write(intermediates_pem)
    # the laptop's root signing record after both card records (regalia-kms#403): one line each, in order
    with open(os.path.join(directory, "signing-record.jsonl"), "w") as f:
        for record, at in ((valid_record(), "2026-10-04T12:00:01Z"), (sequence_two(), "2026-10-05T12:00:01Z")):
            line = {"kind": "card-record", "sequence": record["sequence"], "digest": ok.card_record_digest(record),
                    "key": record["root_entry"]["key"], "at": at}
            f.write(json.dumps(line, sort_keys=True) + "\n")


if __name__ == "__main__":
    write(sys.argv[1] if len(sys.argv) > 1 else HERE)
    print("root %s (sha256 %s)" % (raw(ROOT), hashlib.sha256(bytes.fromhex(raw(ROOT))).hexdigest()))
