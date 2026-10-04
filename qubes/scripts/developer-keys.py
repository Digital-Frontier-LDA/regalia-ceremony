#!/usr/bin/env python3
"""developer-keys.py — the developers' Shamir set and the release key (ADR-0002 D29.2 and D30, regalia-ceremony#124):
a set of its own (never the offline keys' set, nor the KMS users' DKEK), sealing a key map that holds, for now, the
release key (Ed25519), which is imported onto the SIG slot of the two release-specialist YubiKeys.

    python3 -Es developer-keys.py generate --threshold K --shares N --out DIR --breakglass-recipient FILE
    python3 -Es developer-keys.py verify-forms --sealed FILE --shares-file FILE        (the forms typed back on stdin)
    python3 -Es developer-keys.py release-import --sealed FILE --yubikey-serial N --out DIR [--replace]
                                          (the k shares on stdin; the card's PINs, and any confirmation, from the terminal)
    python3 -Es developer-keys.py vouched --record FILE --card-record FILE --root-key HEX

CURRENT LIMITATIONS (2026-10-04; each removed here when it is lifted):
  * MODELLED ONLY. No key has been imported onto a real card: release-import's yubikit calls run against a stand-in
    in the tests. Whether put_key leaves a FIXED touch policy that was set before it is unmeasured (it is read back
    either way, below), and a signature from the imported key, which needs a touch, has never been made
    (regalia-ceremony#123, the D30.6 bench, the owner present).
  * No ceremony.sh step runs this; it is typed by hand (#124).
  * The developers' set seals the release key only. The other developer secrets (staging, dev/CI) are not sealed yet.
  * Rotation after a stolen release card (D30.4: a new key, a published rotation) is not here.
  * The key is in clear in the laptop's RAM during generate and each import, as the offline keys are; the directory
    must be a RAM file system and swap must be off, and that is the bound.

TRUST (regalia-kms-d9 on #124). The release key signs its own generation record: a proof of possession, nothing more,
so the record says status "pending". Anyone with the laptop could make such a set. The key is trusted only once a
ROOT-SIGNED card-ceremony record (offline-keys.py card_record_check, rc#121) names its public key and fingerprint and
binds the release cards' serials; `vouched` is that check, and every later reader must make it. Per-card import results
are unsigned facts the card record is written from: a release key never vouches for a card. Recovery onto a replacement
card (D30.5) therefore needs this set's k shares AND the root's, for the new card's entry in a new card record.

RELEASE-IMPORT, in this order, failing closed:
  1. exactly one YubiKey attached, the serial typed, never a bench card (offline-keys BENCH_YUBIKEYS);
  2. the k shares on stdin open the sealed key map (refused for another set, by SLIP-39 identifier and master id);
  3. the admin and user PINs are typed at the terminal, never argv: either equal to its factory default (12345678,
     123456) is refused, and both must verify, so the card's own PINs are not the defaults (a typed non-default PIN
     that verifies proves it, and no retry is spent trying the default);
  4. an occupied SIG slot is refused, unless --replace and the serial typed again;
  5. the touch policy is set to FIXED on SIG BEFORE the key goes in, and read back FIXED;
  6. put_key, then the generation time and the fingerprint data objects, from the sealed header, so both cards show
     one OpenPGP v4 fingerprint, computed here from the public key and that time;
  7. read back: SIG IMPORTED, its public key the sealed one, the touch policy FIXED (not CACHED_FIXED), the fingerprint
     data object the computed one. Any of these failing after the key is on the card: the key is deleted from the
     card by this tool and the slot read back empty, and the card is refused as unusable for release; if even the
     delete fails, the operator is told to reset the card's OpenPGP applet before it leaves the room;
  8. release-import-<serial>.json: the facts, unsigned, for the card record.
A FIXED touch policy cannot be lowered without resetting the applet, so a wrong key on a release card also means a
reset.
"""
import argparse
import base64
import contextlib
import datetime
import getpass
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("offline_keys", os.path.join(HERE, "offline-keys.py"))
ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("offline_keys", _loader))
_loader.exec_module(ok)
Refused, require, canonical, zero = ok.Refused, ok.require, ok.canonical, ok.zero

SET = "developers"
SCHEMA_SEALED = "regalia.developer-keys-sealed/v1"
SCHEMA_BUNDLE = "regalia.developer-keys/v1"
SCHEMA_RECORD = "regalia.developer-keys-record/v1"
SCHEMA_IMPORT = "regalia.release-import/v1"
RECORD_DOMAIN = b"regalia-developer-keys-record/v1\0"    # never a root record's, nor a membership signing input
SEAL_INFO = b"regalia-developer-keys/v1 seal"
KEYS = (("release", "ed25519"),)       # the key map: the release key for now; other developer secrets later
FILES = ("developers.sealed.json", "developers-shares.txt", "developers.breakglass.age", "developers.record.json")
DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN = "12345678", "123456"
TOOL = "developer-keys.py/1"
ED25519_OID = bytes.fromhex("2B06010401DA470F01")      # 1.3.6.1.4.1.11591.15.1, OpenPGP's legacy EdDSA curve


def stamp(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_public(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def v4_fingerprint(public, created):
    """The OpenPGP v4 fingerprint (RFC 4880 12.2) of an Ed25519 signing key (algorithm 22, EdDSA with the legacy
    curve OID) created at `created`: SHA-1 over 0x99, the two-byte length and the public-key packet body. Upper-case
    hex, 40 characters, as gpg prints it and the card record carries it."""
    require(isinstance(public, (bytes, bytearray)) and len(public) == 32, "an Ed25519 public key is 32 bytes")
    require(isinstance(created, int) and 0 < created < 1 << 32, "the creation time is a 32-bit Unix time")
    body = (b"\x04" + created.to_bytes(4, "big") + b"\x16" + bytes([len(ED25519_OID)]) + ED25519_OID
            + (263).to_bytes(2, "big") + b"\x40" + bytes(public))
    return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()


# ---- the sealed key map -----------------------------------------------------------------------------

def bundle_bytes(keys):
    from cryptography.hazmat.primitives import serialization
    out = {"schema": SCHEMA_BUNDLE, "keys": {}}
    for name, alg in KEYS:
        der = keys[name].private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        out["keys"][name] = {"alg": alg, "pkcs8": base64.b64encode(der).decode()}
    return bytearray(canonical(out))


def seal(master, keys, identifier, created):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    publics = {}
    for name, alg in KEYS:
        raw = raw_public(keys[name])
        publics[name] = {"alg": alg, "key": raw.hex(), "created": created, "fingerprint": v4_fingerprint(raw, created)}
    header = {"schema": SCHEMA_SEALED, "set": SET, "master_id": ok.master_id(master), "slip39_identifier": identifier, "publics": publics}
    nonce, plain = secrets.token_bytes(12), bundle_bytes(keys)
    key = bytearray(ok.hkdf(master, SEAL_INFO))
    try:
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, bytes(plain), canonical(header))
    finally:
        zero(key)
        zero(plain)
    return dict(header, nonce=nonce.hex(), ciphertext=base64.b64encode(ciphertext).decode())


def load_sealed(path):
    with open(path, "rb") as f:
        sealed = json.loads(f.read(1 << 20))
    require(isinstance(sealed, dict) and sealed.get("schema") == SCHEMA_SEALED and sealed.get("set") == SET,
            "%s is not the developers' sealed file (the offline keys' set is offline-keys.py's)" % path)
    return sealed


def unseal(master, sealed):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    require(ok.master_id(master) == sealed["master_id"], "these shares rebuild another master secret than the one this file was sealed under")
    header = {k: sealed[k] for k in ("schema", "set", "master_id", "slip39_identifier", "publics")}
    key = bytearray(ok.hkdf(master, SEAL_INFO))
    try:
        plain = AESGCM(bytes(key)).decrypt(bytes.fromhex(sealed["nonce"]), base64.b64decode(sealed["ciphertext"]), canonical(header))
    except InvalidTag:
        raise Refused("the sealed file does not open under this master secret (altered, or another set)") from None
    finally:
        zero(key)
    return json.loads(plain)


def open_key(sealed, stream, name="release"):
    """The named key from the k shares on `stream`. Returns (the private key, the share indices used)."""
    master, indices, _ = ok.combine(ok.read_shares(stream), sealed)
    try:
        bundle = unseal(master, sealed)
    finally:
        zero(master)
    key = ok._private_key(bundle["keys"][name])
    del bundle
    require(raw_public(key).hex() == sealed["publics"][name]["key"], "the sealed %s key is not the one its header publishes" % name)
    return key, indices


# ---- generate ---------------------------------------------------------------------------------------

def generate(threshold, shares, out, recipient_file, now=None, run=subprocess.run):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    require(isinstance(threshold, int) and isinstance(shares, int) and 2 <= threshold <= shares <= 16,
            "the scheme is k-of-n with 2 <= k <= n <= 16 (D13)")
    require(os.path.isdir(out), "--out %s is not a directory" % out)
    for name in FILES:
        require(not os.path.lexists(os.path.join(out, name)), "%s already exists: nothing is overwritten" % os.path.join(out, name))
    ok.check_place(out)
    recipient = ok._age_recipient(recipient_file)
    when = now or datetime.datetime.now(datetime.timezone.utc)
    created = int(when.timestamp())
    keys = {"release": ed25519.Ed25519PrivateKey.generate()}
    master = bytearray(secrets.token_bytes(32))
    try:
        mnemonics, identifier = ok.split(master, threshold, shares)
        sealed = seal(master, keys, identifier, created)
        mid = ok.master_id(master)
    finally:
        zero(master)
    written = []

    def write(name, data, mode):
        path = os.path.join(out, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        written.append(path)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    try:
        plain = bundle_bytes(keys)
        try:
            path = os.path.join(out, FILES[2])
            written.append(path)
            done = run(["age", "-r", recipient, "-o", path], input=bytes(plain), capture_output=True)
            require(done.returncode == 0, "age could not encrypt to the break-glass recipient: %s" % done.stderr.decode(errors="replace").strip()[-200:])
            with open(path, "rb") as f:
                data = f.read()
            require(data.startswith(b"age-encryption.org/v1"), "age wrote no age file")
            for entry in json.loads(bytes(plain))["keys"].values():
                require(entry["pkcs8"].encode() not in data and base64.b64decode(entry["pkcs8"]) not in data,
                        "the break-glass file holds a key in the clear")
        finally:
            zero(plain)
        write(FILES[0], canonical(sealed) + b"\n", 0o644)
        write(FILES[1], ("".join(m + "\n" for m in mnemonics)).encode(), 0o600)
        files = {}
        for name in (FILES[0], FILES[2]):
            with open(os.path.join(out, name), "rb") as f:
                files[name] = hashlib.sha256(f.read()).hexdigest()
        record = {"schema": SCHEMA_RECORD, "event": "generate", "set": SET, "status": "pending", "threshold": threshold, "shares": shares,
                  "slip39_identifier": identifier, "master_id": mid, "publics": sealed["publics"], "files": files, "tool": TOOL,
                  "at": stamp(when)}
        signature = keys["release"].sign(RECORD_DOMAIN + canonical(record))     # possession, not authority: see TRUST
        write(FILES[3], canonical({"record": record, "signature": signature.hex()}) + b"\n", 0o644)
    except BaseException:
        for path in written:              # nothing half-made: every file this run wrote, by its exact name
            if os.path.lexists(path):
                os.unlink(path)
        raise
    del keys
    return record


# ---- the forms, typed back --------------------------------------------------------------------------

def verify_forms(sealed_path, shares_path, stream):
    """Every form typed back equals its share (SLIP-39 checksum first), a k-subset of the forms opens the sealed key
    map, and only then is the shares file overwritten with zeros and unlinked, by its exact path. Returns the form
    numbers checked."""
    from shamir_mnemonic.share import Share
    ok.check_place(os.path.dirname(os.path.abspath(shares_path)))
    sealed = load_sealed(sealed_path)
    with open(shares_path) as f:
        made = {Share.from_mnemonic(ok.normalise(m)).index: ok.normalise(m) for m in f.read().splitlines() if m.strip()}
    typed = {}
    for line in ok.read_forms(stream):
        try:
            share = Share.from_mnemonic(ok.normalise(line))
        except Exception as error:      # noqa: BLE001 - a mistyped word fails the checksum: said, never guessed at
            raise Refused("a form typed back is not a valid SLIP-39 share (%s): check that form against its share" % error) from None
        require(share.identifier == sealed["slip39_identifier"], "a form typed back belongs to another set (identifier %d)" % share.identifier)
        require(made.get(share.index) == ok.normalise(line), "form %d typed back is not the share made for it: recopy form %d"
                % (share.index + 1, share.index + 1))
        require(share.index not in typed, "form %d was typed back twice" % (share.index + 1))
        typed[share.index] = ok.normalise(line)
    require(sorted(typed) == sorted(made), "forms %s were not typed back: every form is checked before the shares go"
            % ",".join(str(i + 1) for i in sorted(set(made) - set(typed))))
    threshold = Share.from_mnemonic(next(iter(made.values()))).member_threshold
    master, _, _ = ok.combine([typed[i] for i in sorted(typed)[:threshold]], sealed)
    try:
        unseal(master, sealed)
    finally:
        zero(master)
    size = os.path.getsize(shares_path)
    with open(shares_path, "r+b") as f:
        f.write(b"\0" * size)
        f.flush()
        os.fsync(f.fileno())
    os.unlink(shares_path)
    return [i + 1 for i in sorted(typed)]


# ---- the release cards ------------------------------------------------------------------------------

@contextlib.contextmanager
def open_card(serial):
    """The one YubiKey attached, which must be `serial`: (its OpenPGP session, its firmware version)."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.openpgp import OpenPgpSession
    devices = list_all_devices()
    require(len(devices) == 1, "%d YubiKeys are attached: attach only release card %s" % (len(devices), serial))
    device, info = devices[0]
    require(str(info.serial) == serial, "the YubiKey attached is %s, not the %s typed" % (info.serial, serial))
    with device.open_connection(SmartCardConnection) as connection:
        yield OpenPgpSession(connection), "%d.%d.%d" % tuple(info.version)


def _ask(prompt):
    with open("/dev/tty") as tty:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        return tty.readline().strip()


def _ask_secret(prompt):
    return getpass.getpass(prompt)


def release_import(sealed_path, serial, out, stream, replace=False, ask=_ask, ask_secret=_ask_secret, card=open_card, now=None):
    from yubikit.openpgp import KEY_REF, KEY_STATUS, UIF
    serial = str(serial)
    require(re.fullmatch(r"[1-9][0-9]{0,9}", serial) is not None, "--yubikey-serial is the release card's decimal serial")
    require(serial not in ok.BENCH_YUBIKEYS, "YubiKey %s is a bench card: the ceremony never uses a bench serial (D28.5, D30)" % serial)
    require(os.path.isdir(out), "--out %s is not a directory" % out)
    facts_path = os.path.join(out, "release-import-%s.json" % serial)
    require(not os.path.lexists(facts_path), "%s already exists: nothing is overwritten" % facts_path)
    ok.check_place(out)
    sealed = load_sealed(sealed_path)
    public = sealed["publics"]["release"]
    key, indices = open_key(sealed, stream)
    try:
        admin = ask_secret("Admin PIN of release card %s: " % serial)
        user = ask_secret("User PIN of release card %s: " % serial)
        require(admin != DEFAULT_ADMIN_PIN and user != DEFAULT_USER_PIN,
                "a PIN typed is the factory default: set the card's admin and user PINs first (ykman openpgp access), "
                "or anyone holding it could re-key it")
        with card(serial) as (session, firmware):
            try:
                session.verify_pin(user)
                session.verify_admin(admin)
            except Exception as error:      # noqa: BLE001 - a wrong PIN costs a retry: said, never retried here
                raise Refused("release card %s refused a PIN (%s): nothing was changed; check the PIN before trying again, "
                              "each failure spends one of its three tries" % (serial, error)) from None
            status = session.get_key_information()[KEY_REF.SIG]
            if status != KEY_STATUS.NONE:
                require(replace, "release card %s already holds a SIG key (%s): refused; replacing it takes --replace" % (serial, status.name))
                require(ask("Release card %s already holds a SIG key. Type its serial to replace it: " % serial) == serial,
                        "the serial typed is not %s: nothing was changed" % serial)
            # the touch policy before the key: a release key is never on a card without it (regalia-kms-d9 on #124)
            session.set_uif(KEY_REF.SIG, UIF.FIXED)
            require(session.get_uif(KEY_REF.SIG) == UIF.FIXED, "release card %s did not take a FIXED touch policy on SIG: nothing was imported" % serial)
            session.put_key(KEY_REF.SIG, key)
            try:
                session.set_generation_time(KEY_REF.SIG, public["created"])
                session.set_fingerprint(KEY_REF.SIG, bytes.fromhex(public["fingerprint"]))
                problems = []
                if session.get_key_information()[KEY_REF.SIG] != KEY_STATUS.IMPORTED:
                    problems.append("SIG is not reported IMPORTED")
                if raw_public_of(session.get_public_key(KEY_REF.SIG)) != public["key"]:
                    problems.append("SIG holds another public key than the sealed one")
                if session.get_uif(KEY_REF.SIG) != UIF.FIXED:
                    problems.append("the touch policy on SIG is not FIXED")
                fingerprints = session.get_application_related_data().discretionary.fingerprints
                computed = v4_fingerprint(bytes.fromhex(public["key"]), public["created"])
                if (fingerprints.get(KEY_REF.SIG) or b"").hex().upper() != computed or computed != public["fingerprint"]:
                    problems.append("the fingerprint on SIG is not the computed v4 fingerprint %s" % computed)
                require(not problems, "; ".join(problems))
            except Exception as error:      # noqa: BLE001 - the key is on the card: whatever went wrong, it is taken off
                reason = str(error)
                try:
                    session.delete_key(KEY_REF.SIG)
                    gone = session.get_key_information()[KEY_REF.SIG] == KEY_STATUS.NONE
                except Exception:           # noqa: BLE001
                    gone = False
                if not gone:
                    raise Refused("release card %s is UNUSABLE and its SIG key could NOT be deleted (%s): reset its OpenPGP applet "
                                  "(ykman openpgp reset) before it leaves the room" % (serial, reason)) from None
                raise Refused("release card %s is unusable for release (%s): the key was deleted from it and the slot read "
                              "back empty" % (serial, reason)) from None
    finally:
        del key
    facts = {"schema": SCHEMA_IMPORT, "serial": serial, "firmware": firmware, "alg": "ed25519", "key": public["key"],
             "fingerprint": public["fingerprint"], "created": public["created"], "touch": "fixed", "imported": True,
             "attested": False, "slip39_identifier": sealed["slip39_identifier"], "master_id": sealed["master_id"],
             "share_indices": indices, "tool": TOOL, "at": stamp(now)}
    fd = os.open(facts_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical(facts) + b"\n")
        f.flush()
        os.fsync(f.fileno())
    return facts


def raw_public_of(public_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        return None
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


# ---- trust ------------------------------------------------------------------------------------------

def verify_possession(document):
    """The developers' generation record, signed by the release key it names: a proof of possession, never of
    authority (its status is "pending"). Returns the record."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    require(isinstance(document, dict) and set(document) == {"record", "signature"}, "not a developers' record")
    record = document["record"]
    require(isinstance(record, dict) and record.get("schema") == SCHEMA_RECORD and record.get("set") == SET, "not a developers' record")
    require(record.get("status") == "pending", "a developers' record is pending until a root-signed card record names its key")
    release = record["publics"]["release"]
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(release["key"])).verify(bytes.fromhex(document["signature"]),
                                                                                         RECORD_DOMAIN + canonical(record))
    except (InvalidSignature, ValueError):
        raise Refused("the developers' record is not signed by the release key it names") from None
    return record


def vouched(developers_document, card_document, pinned_root):
    """The release key, trusted: possession (the developers' record, signed by it) AND authority (a card record signed
    by the PINNED root names the same key and fingerprint, and binds the release cards). Returns the card record's
    release_key entry (with its card serials)."""
    record = verify_possession(developers_document)
    cards = ok.verify_card_record(card_document, pinned_root)
    release = record["publics"]["release"]
    require(cards["release_key"]["key"] == release["key"] and cards["release_key"]["fingerprint"] == release["fingerprint"],
            "the release key is not the one the root-signed card record names: it is pending, and nothing trusts it")
    return cards["release_key"]


# ---- command line -----------------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(prog="developer-keys.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--threshold", type=int, required=True)
    g.add_argument("--shares", type=int, required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--breakglass-recipient", required=True)
    v = sub.add_parser("verify-forms")
    v.add_argument("--sealed", required=True)
    v.add_argument("--shares-file", required=True)
    r = sub.add_parser("release-import")
    r.add_argument("--sealed", required=True)
    r.add_argument("--yubikey-serial", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--replace", action="store_true", help="the card's SIG slot holds a key: replace it (the serial is typed again)")
    t = sub.add_parser("vouched")
    t.add_argument("--record", required=True, help="developers.record.json")
    t.add_argument("--card-record", required=True, help="the root-signed card-ceremony record")
    t.add_argument("--root-key", required=True, help="the pinned root, 64 hex")
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            record = generate(args.threshold, args.shares, args.out, args.breakglass_recipient)
            release = record["publics"]["release"]
            print("GENERATED the developers' set %d of %d (identifier %d), PENDING: release key %s, fingerprint %s"
                  % (args.threshold, args.shares, record["slip39_identifier"], release["key"], release["fingerprint"]))
        elif args.command == "verify-forms":
            checked = verify_forms(args.sealed, args.shares_file, sys.stdin)
            print("FORMS VERIFIED %s: each equals its share and they open the sealed keys; the shares file is shredded"
                  % ",".join(str(i) for i in checked))
        elif args.command == "release-import":
            facts = release_import(args.sealed, args.yubikey_serial, args.out, sys.stdin, args.replace)
            print("IMPORTED the release key onto card %s (fingerprint %s, touch fixed, not attested): %s"
                  % (facts["serial"], facts["fingerprint"], os.path.join(args.out, "release-import-%s.json" % facts["serial"])))
        else:
            with open(args.record, "rb") as f:
                developers = json.loads(f.read(1 << 20))
            with open(args.card_record, "rb") as f:
                cards = json.loads(f.read(1 << 20))
            entry = vouched(developers, cards, args.root_key)
            print("VOUCHED: release key %s, on cards %s" % (entry["fingerprint"], ", ".join(entry["cards"])))
    except (Refused, OSError, ValueError, KeyError) as error:
        print("developer-keys: REFUSED: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
