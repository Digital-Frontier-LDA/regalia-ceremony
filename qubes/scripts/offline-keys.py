#!/usr/bin/env python3
"""offline-keys.py — the offline keys of ADR-0002 D28 (regalia#559, regalia-ceremony#111): the membership root and
the three boot-image signing keys, generated as software keys on the air-gapped ceremony laptop, held by one
Shamir share set of their own (separate from break-glass), and backed up to the break-glass key.

    python3 -Es offline-keys.py generate --threshold K --shares N --out DIR --breakglass-recipient FILE
    python3 -Es offline-keys.py verify-forms --sealed FILE --shares-file FILE [--partial]   (the forms typed back on stdin)
    python3 -Es offline-keys.py verify-record --record FILE

THE SHAPE. SLIP-39 splits a 128- or 256-bit master secret and ssss one short line, and neither holds an RSA private
key. So, as a KMS splits its unseal key and not the keys it protects: one 256-bit OFFLINE MASTER SECRET is split
k-of-n with SLIP-39 (shamir-mnemonic, pinned), and the four keys are sealed under a key derived from it:
  * offline-keys.sealed.json      AES-256-GCM over the key bundle, under HKDF-SHA256(master, "…/v1 seal"), with the
                                  public header (each key's name, algorithm and SubjectPublicKeyInfo, and the
                                  master's id) as its additional data. Public: stored openly, like a DKEK blob (D19).
                                  Symmetric, so nothing here waits for a quantum computer.
  * offline-shares.txt            the SLIP-39 shares (0600), copied by hand onto the holders' forms (D12). Every
                                  k-subset is reconstruct-verified (all of them up to 200 combinations, else 200 drawn
                                  at random), and a (k-1)-subset must recover nothing. That proves the split, not the
                                  copies: verify-forms then takes every form typed back (each must pass SLIP-39's
                                  checksum and equal its share, and a typed-back k-subset must rebuild THIS master),
                                  and only then shreds this file (regalia-kms-d9 on #114). A copying slip is found
                                  while the shares still exist, not at the first signing session.
  * offline-keys.breakglass.age   the key bundle itself, encrypted with age to the break-glass recipient (D28.1's
                                  backup: a lost offline set never strands the fleet). The plaintext reaches age on
                                  stdin, and the file must hold none of it in the clear.
  * offline-keys.record.json      what was made (the publics, k and n, the SLIP-39 identifier, the master id, both
                                  files' SHA-256, and that each key signed a fresh challenge its published public key
                                  verifies), signed by the new root key in this same session, over
                                  RECORD_DOMAIN + its canonical bytes. RECORD_DOMAIN can never begin a membership
                                  signing input (regalia-kms: b"regalia-membership/v1\\0"), nor the reverse.

THE KEYS. root: Ed25519 (regalia-kms root-key.json takes {"alg": "ed25519", "key": "<hex>"}); pcr-initrd, pcr-system,
secure-boot: RSA-2048, the boot image's keys of regalia#554 under the labels hsm-signing-key.sh gave them.

WHERE IT RUNS. DIR must be a RAM file system (tmpfs or ramfs) and swap must be off: the keys and the master secret
must never reach a disk. CEREMONY_ALLOW_NONTMPFS=1 and CEREMONY_ALLOW_SWAP=1 are for tests. Key material and the
master are kept in bytearrays where this code holds them, and zeroed when done; Python and the libraries it calls
may hold copies this cannot reach. So do the share mnemonics, which are Python strings until the process exits:
all n of them are the master. What bounds all of these is that the process ends, in RAM, on a laptop with no swap.
"""
import argparse
import base64
import datetime
import hashlib
import itertools
import json
import os
import random
import re
import secrets
import subprocess
import sys

SCHEMA_BUNDLE = "regalia.offline-keys/v1"
SCHEMA_SEALED = "regalia.offline-keys-sealed/v1"
SCHEMA_RECORD = "regalia.offline-keys-record/v1"
RECORD_DOMAIN = b"regalia-ceremony-record/v1\0"
MEMBERSHIP_DOMAIN = b"regalia-membership/v1\0"       # regalia-kms deploy/baremetal/membership.py DOMAIN
KEYS = (("root", "ed25519"), ("pcr-initrd", "rsa-2048"), ("pcr-system", "rsa-2048"), ("secure-boot", "rsa-2048"))
FILES = ("offline-keys.sealed.json", "offline-shares.txt", "offline-keys.breakglass.age", "offline-keys.record.json")
MAX_SUBSETS = 200
TOOL = "offline-keys.py/1"


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def zero(buf):
    if isinstance(buf, bytearray):
        buf[:] = bytes(len(buf))


def hkdf(master, info, length=32):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(bytes(master))


def master_id(master):
    return hkdf(master, b"regalia-offline-keys/v1 id", 16).hex()


# ---- where it runs ----------------------------------------------------------------------------------

def fs_type(path):
    """The file system type of the mount that holds `path` (the longest mount point that is a prefix of it)."""
    real, best, kind = os.path.realpath(path), "", None
    with open("/proc/mounts") as f:
        for line in f:
            fields = line.split()
            if len(fields) < 3:
                continue
            point = fields[1].replace("\\040", " ")
            if (real == point or real.startswith(point.rstrip("/") + "/")) and len(point) >= len(best):
                best, kind = point, fields[2]
    return kind


def swap_in_use():
    with open("/proc/swaps") as f:
        return [line.split()[0] for line in f.read().splitlines()[1:] if line.strip()]


def check_place(out):
    kind = fs_type(out)
    require(kind in ("tmpfs", "ramfs") or os.environ.get("CEREMONY_ALLOW_NONTMPFS") == "1",
            "%s is on %s, not a RAM file system: the offline keys never touch a disk" % (out, kind))
    swaps = swap_in_use()
    require(not swaps or os.environ.get("CEREMONY_ALLOW_SWAP") == "1",
            "swap is on (%s): a page of a key could be written to it. Turn swap off (swapoff -a) first" % ", ".join(swaps))


# ---- the keys ---------------------------------------------------------------------------------------

def new_keys():
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    keys = {}
    for name, alg in KEYS:
        keys[name] = ed25519.Ed25519PrivateKey.generate() if alg == "ed25519" else rsa.generate_private_key(65537, 2048)
    return keys


def publics(keys):
    from cryptography.hazmat.primitives import serialization
    out = {}
    for name, alg in KEYS:
        spki = keys[name].public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        out[name] = {"alg": alg, "spki": base64.b64encode(spki).decode()}
    return out


def operation_proofs(keys):
    """Each key signs a fresh challenge as it will be used (Ed25519 for the root; RSA PKCS#1 v1.5 with SHA-256, as
    sbsign and systemd-measure sign) and the signature must verify under the public key the sealed header will
    publish: a header that does not match its bundle is found here, not at the first kernel signing (regalia-kms-d9
    on #114). Returns {name: "verified"}."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    out, published = {}, publics(keys)
    for name, alg in KEYS:
        challenge = secrets.token_bytes(32)
        public = serialization.load_der_public_key(base64.b64decode(published[name]["spki"]))
        try:
            if alg == "ed25519":
                public.verify(keys[name].sign(challenge), challenge)
            else:
                public.verify(keys[name].sign(challenge, padding.PKCS1v15(), hashes.SHA256()), challenge, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise Refused("key %s does not sign for the public key that would be published" % name) from None
        out[name] = "verified"
    return out


def root_entry(keys):
    from cryptography.hazmat.primitives import serialization
    raw = keys["root"].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"alg": "ed25519", "key": raw.hex()}


def bundle_bytes(keys):
    """The key bundle, PKCS#8 each, as a bytearray (zeroed by the caller)."""
    from cryptography.hazmat.primitives import serialization
    out = {"schema": SCHEMA_BUNDLE, "keys": {}}
    for name, alg in KEYS:
        der = keys[name].private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        out["keys"][name] = {"alg": alg, "pkcs8": base64.b64encode(der).decode()}
    return bytearray(canonical(out))


def seal(master, keys, identifier):
    """The sealed file. Its header names the SLIP-39 set's identifier, so a session refuses shares of another set
    by name before combining them (regalia-kms-d9 on #114)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    header = {"schema": SCHEMA_SEALED, "master_id": master_id(master), "slip39_identifier": identifier, "publics": publics(keys)}
    nonce = secrets.token_bytes(12)
    plain = bundle_bytes(keys)
    key = bytearray(hkdf(master, b"regalia-offline-keys/v1 seal"))
    try:
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, bytes(plain), canonical(header))
    finally:
        zero(key)
        zero(plain)
    return dict(header, nonce=nonce.hex(), ciphertext=base64.b64encode(ciphertext).decode())


def unseal(master, sealed):
    """The key bundle (a dict of the four PKCS#8 keys) from the sealed file and a master secret, or Refused."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    require(sealed.get("schema") == SCHEMA_SEALED, "not a sealed offline-key file")
    require(master_id(master) == sealed["master_id"], "these shares rebuild another master secret than the one this file was sealed under")
    header = {k: sealed[k] for k in ("schema", "master_id", "slip39_identifier", "publics")}
    key = bytearray(hkdf(master, b"regalia-offline-keys/v1 seal"))
    try:
        plain = AESGCM(bytes(key)).decrypt(bytes.fromhex(sealed["nonce"]), base64.b64decode(sealed["ciphertext"]), canonical(header))
    except InvalidTag:
        raise Refused("the sealed file does not open under this master secret (altered, or another set)") from None
    finally:
        zero(key)
    return json.loads(plain)


# ---- the share set ----------------------------------------------------------------------------------

def split(master, threshold, shares):
    from shamir_mnemonic import combine_mnemonics, generate_mnemonics
    from shamir_mnemonic.share import Share
    mnemonics = generate_mnemonics(1, [(threshold, shares)], bytes(master))[0]
    subsets = list(itertools.combinations(range(shares), threshold))
    if len(subsets) > MAX_SUBSETS:
        subsets = random.SystemRandom().sample(subsets, MAX_SUBSETS)
    for subset in subsets:
        require(combine_mnemonics([mnemonics[i] for i in subset]) == bytes(master),
                "shares %s did not rebuild the master secret: nothing is handed out" % ",".join(str(i + 1) for i in subset))
    try:
        rebuilt = combine_mnemonics(mnemonics[:threshold - 1])
    except Exception:          # noqa: BLE001 - shamir-mnemonic refuses too few shares with its own error
        rebuilt = None
    require(rebuilt != bytes(master), "%d shares rebuilt the master secret: the threshold is not %d" % (threshold - 1, threshold))
    return mnemonics, Share.from_mnemonic(mnemonics[0]).identifier


# ---- generate ---------------------------------------------------------------------------------------

def generate(threshold, shares, out, recipient_file, now=None, run=subprocess.run):
    require(isinstance(threshold, int) and isinstance(shares, int) and 2 <= threshold <= shares <= 16,
            "the scheme is k-of-n with 2 <= k <= n <= 16 (D13)")
    require(os.path.isdir(out), "--out %s is not a directory" % out)
    for name in FILES:
        require(not os.path.lexists(os.path.join(out, name)), "%s already exists: nothing is overwritten" % os.path.join(out, name))
    check_place(out)
    with open(recipient_file) as f:
        recipient = f.readline().strip()
    require(re.fullmatch(r"age1[0-9a-z]+", recipient) is not None, "%s does not hold an age recipient" % recipient_file)

    keys = new_keys()
    proofs = operation_proofs(keys)
    master = bytearray(secrets.token_bytes(32))
    try:
        mnemonics, identifier = split(master, threshold, shares)
        sealed = seal(master, keys, identifier)
        mid = master_id(master)
    finally:
        zero(master)

    # the break-glass copy: the bundle on age's stdin, never in a file of ours
    plain = bundle_bytes(keys)
    tmp = os.path.join(out, ".offline-keys.breakglass.age.tmp")
    try:
        done = run(["age", "-r", recipient, "-o", tmp], input=bytes(plain), capture_output=True)
        require(done.returncode == 0, "age could not encrypt to the break-glass recipient: %s" % done.stderr.decode(errors="replace").strip()[-200:])
        with open(tmp, "rb") as f:
            written = f.read()
        require(written.startswith(b"age-encryption.org/v1"), "age wrote no age file")
        for entry in json.loads(bytes(plain))["keys"].values():
            require(entry["pkcs8"].encode() not in written and base64.b64decode(entry["pkcs8"]) not in written,
                    "the break-glass file holds a key in the clear")
        os.rename(tmp, os.path.join(out, FILES[2]))
    finally:
        zero(plain)
        if os.path.lexists(tmp):
            os.unlink(tmp)

    def write(name, data, mode):
        fd = os.open(os.path.join(out, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    write(FILES[0], canonical(sealed) + b"\n", 0o644)
    write(FILES[1], ("".join(m + "\n" for m in mnemonics)).encode(), 0o600)
    files = {}
    for name in (FILES[0], FILES[2]):
        with open(os.path.join(out, name), "rb") as f:
            files[name] = hashlib.sha256(f.read()).hexdigest()
    at = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {"schema": SCHEMA_RECORD, "event": "generate", "threshold": threshold, "shares": shares,
              "slip39_identifier": identifier, "master_id": mid, "publics": sealed["publics"], "root_entry": root_entry(keys),
              "files": files, "operation_proof": proofs, "tool": TOOL, "at": at}
    signature = keys["root"].sign(RECORD_DOMAIN + canonical(record))      # the root, in this session (D28, 24's re-plan)
    write(FILES[3], canonical({"record": record, "signature": signature.hex()}) + b"\n", 0o644)
    del keys
    return record


# ---- the hand-copied forms -------------------------------------------------------------------------

def normalise(mnemonic):
    return " ".join(mnemonic.lower().split())


def verify_forms(sealed_path, shares_path, stream, partial=False):
    """The forms as the holders will keep them, typed back before the shares are gone: each must be a valid SLIP-39
    share (its checksum) equal to one of the shares made, a k-subset of the typed forms must rebuild the master the
    sealed file was made under, and every form must be typed back unless `partial` (then at least k, and the record
    of it names the forms not checked). On success the shares file is overwritten with zeros and unlinked, by its exact
    path. Returns (the indices checked, the indices not checked)."""
    from shamir_mnemonic import combine_mnemonics
    from shamir_mnemonic.share import Share
    with open(sealed_path, "rb") as f:
        sealed = json.loads(f.read(1 << 20))
    require(sealed.get("schema") == SCHEMA_SEALED, "not a sealed offline-key file")
    with open(shares_path) as f:
        made = {Share.from_mnemonic(normalise(m)).index: normalise(m) for m in f.read().splitlines() if m.strip()}
    typed = {}
    for line in read_forms(stream):
        try:
            share = Share.from_mnemonic(normalise(line))
        except Exception as error:      # noqa: BLE001 - a mistyped word fails the checksum: said, never guessed at
            raise Refused("a form typed back is not a valid SLIP-39 share (%s): check that form against its share" % error) from None
        require(share.identifier == sealed["slip39_identifier"], "a form typed back belongs to another set (identifier %d)" % share.identifier)
        require(made.get(share.index) == normalise(line), "form %d typed back is not the share made for it: recopy form %d" % (share.index + 1, share.index + 1))
        require(share.index not in typed, "form %d was typed back twice" % (share.index + 1))
        typed[share.index] = normalise(line)
    threshold = Share.from_mnemonic(next(iter(made.values()))).member_threshold
    missing = sorted(set(made) - set(typed))
    require(len(typed) >= threshold, "%d forms typed back; at least %d are needed to show they open the keys" % (len(typed), threshold))
    require(partial or not missing, "forms %s were not typed back: type every form back (or --partial, which the output states)"
            % ", ".join(str(i + 1) for i in missing))
    try:
        master = bytearray(combine_mnemonics([typed[i] for i in sorted(typed)[:threshold]]))
    except Exception as error:         # noqa: BLE001 - shares that do not combine are a refusal, said by the library
        raise Refused("the forms typed back do not combine: %s" % error) from None
    try:
        require(master_id(master) == sealed["master_id"], "the forms typed back rebuild another master secret than the sealed file's")
    finally:
        zero(master)
    size = os.path.getsize(shares_path)
    with open(shares_path, "r+b") as f:
        f.write(bytes(size))
        f.flush()
        os.fsync(f.fileno())
    os.unlink(shares_path)
    return sorted(typed), missing


def read_forms(stream, limit=64):
    lines = [line.strip() for line in stream.read(1 << 16).splitlines() if line.strip()]
    require(0 < len(lines) <= limit, "no forms were typed back on standard input")
    return lines


def verify_record(document):
    """A record's signature under the root entry it names. Returns the record, or Refused."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    require(isinstance(document, dict) and set(document) == {"record", "signature"}, "not an offline-key record")
    record = document["record"]
    require(record.get("schema") == SCHEMA_RECORD, "schema must be %s" % SCHEMA_RECORD)
    entry = record["root_entry"]
    require(entry.get("alg") == "ed25519" and re.fullmatch(r"[0-9a-f]{64}", entry.get("key", "")) is not None, "the root entry is not an Ed25519 key")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["key"])).verify(bytes.fromhex(document["signature"]),
                                                                                     RECORD_DOMAIN + canonical(record))
    except (InvalidSignature, ValueError):
        raise Refused("the record's signature does not verify under its root entry") from None
    return record


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--threshold", type=int, required=True)
    g.add_argument("--shares", type=int, required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--breakglass-recipient", required=True, help="the file holding the break-glass age recipient (public)")
    w = sub.add_parser("verify-forms", help="the holders' forms typed back on standard input, one per line")
    w.add_argument("--sealed", required=True)
    w.add_argument("--shares-file", required=True)
    w.add_argument("--partial", action="store_true", help="at least k forms, the rest named as not checked")
    v = sub.add_parser("verify-record")
    v.add_argument("--record", required=True)
    args = ap.parse_args(argv)
    try:
        if args.command == "generate":
            record = generate(args.threshold, args.shares, args.out, args.breakglass_recipient)
            print("ROOT-ENTRY %s" % json.dumps(record["root_entry"], sort_keys=True))
            for name, pub in sorted(record["publics"].items()):
                print("KEY %s %s spki-sha256 %s" % (name, pub["alg"], hashlib.sha256(base64.b64decode(pub["spki"])).hexdigest()))
            for name, digest in sorted(record["files"].items()):
                print("FILE %s sha256 %s" % (name, digest))
            print("SHARES %s: %d-of-%d, SLIP-39 identifier %d. Copy each BY HAND onto its holder's form (D12)"
                  % (os.path.join(args.out, FILES[1]), record["threshold"], record["shares"], record["slip39_identifier"]))
        elif args.command == "verify-forms":
            checked, missing = verify_forms(args.sealed, args.shares_file, sys.stdin, args.partial)
            print("FORMS VERIFIED %s: each equals its share and they open the sealed keys; the shares file is shredded"
                  % ",".join(str(i + 1) for i in checked))
            if missing:
                print("FORMS NOT CHECKED %s (--partial)" % ",".join(str(i + 1) for i in missing))
        else:
            with open(args.record, "rb") as f:
                record = verify_record(json.loads(f.read(1 << 20)))
            print("VERIFIED %s at %s, root %s" % (record["event"], record["at"], record["root_entry"]["key"]))
    except (Refused, OSError, ValueError, KeyError) as error:
        print("offline-keys: REFUSED: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
