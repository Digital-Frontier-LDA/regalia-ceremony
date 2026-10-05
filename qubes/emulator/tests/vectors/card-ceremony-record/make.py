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
        "schema": ok.SCHEMA_CARDS, "event": "card-ceremony", "sequence": 1, "supersedes": "",
        "owner_keys": [{"role": "owner-main", "serial": "40000001", "alg": "ed25519", "key": raw(MAIN), "attested": True,
                        "attestation_sha256": {"sig": "d1" * 32, "dec": "d2" * 32}},
                       {"role": "owner-backup", "serial": "40000002", "alg": "ed25519", "key": raw(BACKUP), "attested": True,
                        "attestation_sha256": {"sig": "e1" * 32, "dec": "e2" * 32}}],
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
    # the laptop's root signing record after both card records (regalia-kms#403): one line each, in order
    with open(os.path.join(directory, "signing-record.jsonl"), "w") as f:
        for record, at in ((valid_record(), "2026-10-04T12:00:01Z"), (sequence_two(), "2026-10-05T12:00:01Z")):
            line = {"kind": "card-record", "sequence": record["sequence"], "digest": ok.card_record_digest(record),
                    "key": record["root_entry"]["key"], "at": at}
            f.write(json.dumps(line, sort_keys=True) + "\n")


if __name__ == "__main__":
    write(sys.argv[1] if len(sys.argv) > 1 else HERE)
    print("root %s (sha256 %s)" % (raw(ROOT), hashlib.sha256(bytes.fromhex(raw(ROOT))).hexdigest()))
