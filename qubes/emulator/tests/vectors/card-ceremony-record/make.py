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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

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


def valid_record():
    entry = {"alg": "ed25519", "key": raw(ROOT)}
    return {
        "schema": ok.SCHEMA_CARDS, "event": "card-ceremony",
        "owner_keys": [{"role": "dev-main", "serial": "40000001", "alg": "ed25519", "key": raw(MAIN), "attested": True,
                        "attestation_sha256": {"sig": "d1" * 32, "dec": "d2" * 32}},
                       {"role": "dev-backup", "serial": "40000002", "alg": "ed25519", "key": raw(BACKUP), "attested": True,
                        "attestation_sha256": {"sig": "e1" * 32, "dec": "e2" * 32}}],
        "ownerauth_recipients": [{"serial": "40000001", "primary": "A1" * 20, "subkey": "B1" * 20},
                                 {"serial": "40000002", "primary": "A2" * 20, "subkey": "B2" * 20}],
        "ssh_signers": [{"serial": "40000001", "key": ssh_line(MAIN_SSH)}, {"serial": "40000002", "key": ssh_line(BACKUP_SSH)}],
        "release_key": {"alg": "ed25519", "key": raw(RELEASE), "fingerprint": "C3" * 20, "cards": ["40000003", "40000004"],
                        "imported": True, "attested": False},
        "session": "0123456789abcdef0123456789abcdef", "root_entry": entry, "root_fingerprint": ok.root_fingerprint(entry),
        "tool": "card-ceremony-vectors/1", "at": "2026-10-04T12:00:00Z"}


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
    out.append(("release-is-owner.json", signed(r), "the release key is an owner key: the release cards hold no owner key (D30.3)"))
    r = valid_record()
    del r["owner_keys"][1]
    out.append(("missing-dev-backup.json", signed(r), "owner_keys holds exactly the two developer cards' SIG keys (D30.3)"))
    r = valid_record()
    r["owner_keys"][0]["comment"] = "an extra field"
    out.append(("unknown-field.json", signed(r), "owner_keys[0] has an unknown field: comment"))
    r = valid_record()
    r["root_entry"] = {"alg": "ed25519", "key": raw(OTHER_ROOT)}
    r["root_fingerprint"] = ok.root_fingerprint(r["root_entry"])
    out.append(("other-root.json", signed(r, OTHER_ROOT), "the record names another root than the pinned one"))
    return out


def write(directory):
    for name, document, _ in vectors():
        with open(os.path.join(directory, name), "w") as f:
            f.write(json.dumps(document, sort_keys=True, indent=1) + "\n")
    with open(os.path.join(directory, "expect.json"), "w") as f:
        f.write(json.dumps({name: expected for name, _, expected in vectors()}, sort_keys=True, indent=1) + "\n")
    with open(os.path.join(directory, "root.hex"), "w") as f:
        f.write(raw(ROOT) + "\n")


if __name__ == "__main__":
    write(sys.argv[1] if len(sys.argv) > 1 else HERE)
    print("root %s (sha256 %s)" % (raw(ROOT), hashlib.sha256(bytes.fromhex(raw(ROOT))).hexdigest()))
