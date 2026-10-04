#!/usr/bin/env python3
"""offline-keys.py — the offline keys of ADR-0002 D28 (regalia#559, regalia-ceremony#111): the membership root and
the three boot-image signing keys, generated as software keys on the air-gapped ceremony laptop, held by one
Shamir share set of their own (separate from break-glass), and backed up to the break-glass key.

    python3 -Es offline-keys.py generate --threshold K --shares N --out DIR --breakglass-recipient FILE
    python3 -Es offline-keys.py verify-forms --sealed FILE --shares-file FILE [--partial]   (the forms typed back on stdin)
    python3 -Es offline-keys.py sign --sealed FILE --who NAME --out DIR --tool-root DIR --tool-digest HEX [--output FILE]…
                                     --exec /usr/bin/python3 -Es -m deploy.baremetal.(manifest|uki) sign …
                                          (the k shares on standard input, one per line)
    python3 -Es offline-keys.py tree-digest --root DIR
    python3 -Es offline-keys.py ownerauth --sealed FILE --nodes a,b,c --yk-keys FILE --breakglass-recipient FILE --out DIR
                                          (the k shares on standard input: the root signs the record)
    python3 -Es offline-keys.py ownerauth-verify --record FILE --dir DIR --yubikey-serial N [--gnupghome DIR]   (each YubiKey)
    python3 -Es offline-keys.py ownerauth-verify --record FILE --dir DIR --summary
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

A SIGNING SESSION (sign). The shares come on standard input, one per line, never on the command line: exactly the
set's threshold of them, each once, of the set the sealed file names (refused by its SLIP-39 identifier before they
are combined, then by its master id), or nothing is opened. Nothing signs raw bytes: a key is only ever handed to the
regalia-kms tool that checks what it signs (regalia-kms-24, -d9 and -1e on #115):
  * the root, only to `manifest sign --signer root --key-fd {keyfd:root} --offline-session {session}`, which still makes
    every check it makes for a token-held root (the chain, the transition, the measurement step, the typed confirmation);
  * the three boot keys together, only to `uki.py sign --initrd-key-fd {keyfd:pcr-initrd} --system-key-fd
    {keyfd:pcr-system} --secure-boot-key-fd {keyfd:secure-boot} --offline-session {session}`, which makes both PCR 11
    signatures and the Secure Boot signature and checks each.
  Each runs as `/usr/bin/python3 -Es -m <module> sign …` from a regalia-kms tree whose digest (every file under
  deploy/; `tree-digest` prints it) must equal --tool-digest, typed from the ceremony image's build evidence; with its
  environment cleared to PATH and LC_ALL, stdin /dev/null (manifest sign reads its confirmation from /dev/tty), and
  that tree as its working directory. Each key reaches it as a sealed memfd, its number substituted for {keyfd:NAME},
  closed after the command; never a file. {session} is a fresh 128-bit id that both tools' records and this one carry.
  The session record is written first, whatever the command did, and then any refusal: who, the keys, the command as
  typed, the tree and its digest, the exit status, the SHA-256 of its stdout and stderr (passed through to the
  operator as they come) and of every --output it was to write, any file in the RAM directory written meanwhile that
  holds a private key, there or in /tmp or /dev/shm (refused, and named), the tool tree's digest again after the
  command (refused if it changed), the share numbers used, the set's identifier and master id; signed by the
  root over RECORD_DOMAIN, as at generation. What a tool could still keep of a key is bounded by the laptop: no
  network, RAM only, no swap, and the process's end.

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
import time

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


def root_fingerprint(entry):
    """The root's fingerprint as the operator types it at `manifest sign --genesis` and `enrol check`: SHA-256 of the
    raw 32-byte Ed25519 public key, 64 hex (regalia-kms#360). The record carries it, signed by that very root, so it is
    typed from the record and not read back from the tool asking for it."""
    return hashlib.sha256(bytes.fromhex(entry["key"])).hexdigest()


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
              "root_fingerprint": root_fingerprint(root_entry(keys)),
              "files": files, "operation_proof": proofs, "tool": TOOL, "at": at}
    signature = keys["root"].sign(RECORD_DOMAIN + canonical(record))      # the root, in this session (D28, 24's re-plan)
    write(FILES[3], canonical({"record": record, "signature": signature.hex()}) + b"\n", 0o644)
    del keys
    return record


# ---- the hand-copied forms -------------------------------------------------------------------------

def normalise(mnemonic):
    return " ".join(mnemonic.lower().split())


def verify_forms(sealed_path, shares_path, stream, partial=False, now=None):
    """The forms as the holders will keep them, typed back before the shares are gone: each must be a valid SLIP-39
    share (its checksum) equal to one of the shares made, a k-subset of the typed forms must rebuild the master the
    sealed file was made under, and every form must be typed back unless `partial` (then at least k, and the record
    of it names the forms not checked). On success the shares file is overwritten with zeros and unlinked, by its exact
    path. Returns (the indices checked, the indices not checked)."""
    from shamir_mnemonic import combine_mnemonics
    from shamir_mnemonic.share import Share
    out = os.path.dirname(os.path.abspath(shares_path))
    check_place(out)                    # the keys are opened below, to sign the record of this check
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
        bundle = unseal(master, sealed)
    finally:
        zero(master)
    # the evidence keeps which forms were proven, not only the screen (regalia-kms-d9 on #114): a forms-verified
    # record, signed by the root the forms just opened
    root = _private_key(bundle["keys"]["root"])
    del bundle
    from cryptography.hazmat.primitives import serialization
    at = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {"schema": SCHEMA_RECORD, "event": "forms-verified", "checked": [i + 1 for i in sorted(typed)],
              "not_checked": [i + 1 for i in missing], "slip39_identifier": sealed["slip39_identifier"], "master_id": sealed["master_id"],
              "root_entry": {"alg": "ed25519", "key": root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()},
              "tool": TOOL, "at": at}
    write_record(out, "forms-verified-%s" % at.replace(":", ""), root, record)
    del root
    size = os.path.getsize(shares_path)
    with open(shares_path, "r+b") as f:
        f.write(bytes(size))
        f.flush()
        os.fsync(f.fileno())
    os.unlink(shares_path)
    return sorted(typed), missing


def read_hidden(stream, what):
    """All of `stream`, to its end. When it is a terminal, with echo off for the length of the read (and the operator
    told how to end it): a share typed at the console is never shown, nor left in the terminal's scrollback (found by
    the end-to-end run on #111, where the shares typed into `sign` were echoed)."""
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        fd = None
    if fd is None or not os.isatty(fd):
        return stream.read(1 << 16)
    import termios
    old = termios.tcgetattr(fd)
    new = list(old)
    new[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(fd, termios.TCSANOW, new)
    try:
        sys.stderr.write("type the %s, one per line, then Ctrl-D on an empty line (nothing is shown)\n" % what)
        sys.stderr.flush()
        return stream.read(1 << 16)
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)


def read_forms(stream, limit=64):
    lines = [line.strip() for line in read_hidden(stream, "forms, as written on the paper").splitlines() if line.strip()]
    require(0 < len(lines) <= limit, "no forms were typed back on standard input")
    return lines


# ---- a signing session ------------------------------------------------------------------------------

def read_shares(stream, limit=64):
    lines = [line.strip() for line in read_hidden(stream, "shares").splitlines()]
    shares = [line for line in lines if line]
    require(0 < len(shares) <= limit, "no shares were given on standard input")
    return shares


def combine(shares, sealed):
    """The master secret, as a bytearray, from exactly the set's threshold of distinct shares of the set the sealed
    file was made under. Returns (master, the share indices used, the SLIP-39 identifier)."""
    from shamir_mnemonic import combine_mnemonics
    from shamir_mnemonic.share import Share
    try:
        parsed = [Share.from_mnemonic(m) for m in shares]
    except Exception as error:           # noqa: BLE001 - a mistyped word is a refusal, said by the library
        raise Refused("a share is not a valid SLIP-39 share: %s" % error) from None
    identifiers = {p.identifier for p in parsed}
    require(len(identifiers) == 1, "the shares come from %d different sets" % len(identifiers))
    require(parsed[0].identifier == sealed["slip39_identifier"], "these shares are of set %d, not of the set this file was sealed under (%d)"
            % (parsed[0].identifier, sealed["slip39_identifier"]))
    indices = [p.index for p in parsed]
    twice = sorted({i + 1 for i in indices if indices.count(i) > 1})
    require(not twice, "a share was given twice (share %s)" % ",".join(str(i) for i in twice))
    threshold = parsed[0].member_threshold
    require(len(parsed) == threshold, "%d shares given; this set needs exactly %d: no more are taken than open it" % (len(parsed), threshold))
    try:
        master = bytearray(combine_mnemonics(shares))
    except Exception as error:           # noqa: BLE001
        raise Refused("the shares do not combine: %s" % error) from None
    if master_id(master) != sealed["master_id"]:
        zero(master)
        raise Refused("these shares rebuild another master secret than the one this file was sealed under")
    return master, sorted(i + 1 for i in indices), parsed[0].identifier     # numbered as the forms are, from 1


def _private_key(entry):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_der_private_key(base64.b64decode(entry["pkcs8"]), None)


# The only commands a session runs, by the keys they take (regalia-kms-24 and -d9 on #115): the root only through
# regalia-kms's `manifest sign`, the three boot keys only through `uki.py sign`, which makes both PCR 11 signatures and
# the Secure Boot signature itself and checks each (regalia-kms-1e). Each runs from the regalia-kms tree whose digest
# the operator types from the ceremony image's build evidence. A key reaches it as an inherited, sealed memfd, its
# number where the command says {keyfd:NAME}; never a file, never a path.
PYTHON = "/usr/bin/python3"
TOOLS = {
    "manifest": {"module": "deploy.baremetal.manifest", "keys": ("root",),
                 "required": ("--signer", "root", "--key-fd", "{keyfd:root}", "--offline-session", "{session}")},
    "uki": {"module": "deploy.baremetal.uki", "keys": ("pcr-initrd", "pcr-system", "secure-boot"),
            "required": ("--initrd-key-fd", "{keyfd:pcr-initrd}", "--system-key-fd", "{keyfd:pcr-system}",
                         "--secure-boot-key-fd", "{keyfd:secure-boot}", "--offline-session", "{session}")},
}
PRIVATE_MARKERS = (b"PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY")
SCAN_DIRS = ("/tmp", "/dev/shm")      # beside the session's own directory: where else a tool could write (both RAM there)


def tree_digest(root):
    """The digest of a regalia-kms tree as its package build ships it: every file under deploy/ (no byte-code), sorted
    by relative path, each as "path NUL sha256 LF" (regalia-kms-1e on #115). A link anywhere in it is refused."""
    base = os.path.join(root, "deploy")
    require(os.path.isdir(base) and not os.path.islink(base), "%s has no deploy/ directory" % root)
    lines = []
    for here, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in dirs + files:
            require(not os.path.islink(os.path.join(here, name)), "%s is a link: the tree is not pinned through links" % os.path.join(here, name))
        for name in sorted(files):
            if name.endswith(".pyc"):
                continue
            path = os.path.join(here, name)
            with open(path, "rb") as f:
                lines.append(b"%s\0%s\n" % (os.path.relpath(path, root).encode(), hashlib.sha256(f.read()).hexdigest().encode()))
    return hashlib.sha256(b"".join(sorted(lines))).hexdigest()


def check_command(command):
    """The command, as typed: one of TOOLS, run as `/usr/bin/python3 -Es -m <module> sign …`, carrying each required
    argument once and no placeholder it is not entitled to. Returns (the tool's name, the keys it takes)."""
    require(command, "--exec needs a command")
    found = [name for name, tool in TOOLS.items() if list(command[:5]) == [PYTHON, "-Es", "-m", tool["module"], "sign"]]
    require(found, "--exec runs only %s" % " or ".join("`%s -Es -m %s sign …`" % (PYTHON, t["module"]) for t in TOOLS.values()))
    tool = TOOLS[found[0]]
    rest = list(command[5:])
    pairs = list(zip(tool["required"][::2], tool["required"][1::2]))
    for flag, value in pairs:
        require(rest.count(flag) == 1 and rest.index(flag) + 1 < len(rest) and rest[rest.index(flag) + 1] == value,
                "the %s command must carry %s %s, once" % (found[0], flag, value))
    allowed = {value for _, value in pairs}
    stray = [a for a in rest if "{" in a and a not in allowed]
    require(not stray, "a placeholder this command is not entitled to: %s" % ", ".join(stray))
    return found[0], tool["keys"]


def _memfd(name, pem):
    """A sealed memfd holding `pem`, rewound: what the tool reads to EOF (regalia-kms-1e requires F_SEAL_WRITE)."""
    import fcntl
    fd = os.memfd_create("offline-key-" + name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, bytes(pem))
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _tee(stream, sink, digest):
    for chunk in iter(lambda: stream.read(4096), b""):
        digest.update(chunk)
        sink.write(chunk)
        sink.flush()


def _leaks(out, since, keys_der):
    """Files written since the command started, in the session's RAM directory and in SCAN_DIRS, that hold a private
    key: a PEM marker, or the DER of a key this session opened (regalia-kms-d9 on #115). Named relative to the session
    directory when inside it, absolute otherwise."""
    found = []
    for top in (out,) + tuple(d for d in SCAN_DIRS if os.path.isdir(d)):
        found += [p for p in _leaks_under(top, since, keys_der) if p not in found]
    return sorted(os.path.relpath(p, out) if p.startswith(os.path.abspath(out) + os.sep) else p for p in found)


def _leaks_under(top, since, keys_der):
    found = []
    for here, _, files in os.walk(top):
        for name in files:
            path = os.path.abspath(os.path.join(here, name))
            try:
                if os.lstat(path).st_mtime < since:
                    continue
                with open(path, "rb") as f:
                    data = f.read(64 << 20)
            except OSError:
                continue
            if any(m in data for m in PRIVATE_MARKERS) or any(der in data for der in keys_der):
                found.append(path)
    return found


def sign(sealed_path, who, out, stream, command, tool_root, tool_digest, outputs=(), now=None, popen=subprocess.Popen,
         sinks=None):
    """A signing session (see the module's docstring). Returns (the session record, its path)."""
    import threading
    require(re.fullmatch(r"[A-Za-z][A-Za-z0-9 ._-]{0,63}", who or "") is not None, "--who names the person signing (letters, digits, . _ - and spaces)")
    require(os.path.isdir(out), "--out %s is not a directory" % out)
    check_place(out)
    tool, key_names = check_command(list(command or []))
    require(re.fullmatch(r"[0-9a-f]{64}", tool_digest or "") is not None, "--tool-digest is the regalia-kms tree's SHA-256 from the image's build evidence")
    actual = tree_digest(tool_root)
    require(actual == tool_digest, "the regalia-kms tree at %s is %s, not %s: not the tree the image's evidence names" % (tool_root, actual, tool_digest))
    for path in outputs:
        require(not os.path.lexists(path), "--output %s already exists: the command's outputs are recorded, never assumed" % path)
    with open(sealed_path, "rb") as f:
        sealed = json.loads(f.read(1 << 20))
    require(sealed.get("schema") == SCHEMA_SEALED, "not a sealed offline-key file")
    master, indices, identifier = combine(read_shares(stream), sealed)
    try:
        bundle = unseal(master, sealed)
    finally:
        zero(master)
    from cryptography.hazmat.primitives import serialization
    root = _private_key(bundle["keys"]["root"])
    pems = {n: bytearray(_private_key(bundle["keys"][n]).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                       serialization.NoEncryption())) for n in key_names}
    ders = [base64.b64decode(entry["pkcs8"]) for entry in bundle["keys"].values()]
    del bundle
    session_id = secrets.token_hex(16)
    at = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    session = {"schema": SCHEMA_RECORD, "event": "sign", "session": session_id, "keys": list(key_names), "who": who, "tool": tool,
               "command": list(command), "tool_root": os.path.abspath(tool_root), "tool_digest": tool_digest,
               "share_indices": indices, "slip39_identifier": identifier, "master_id": sealed["master_id"],
               "root_entry": {"alg": "ed25519", "key": root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()},
               "at": at}
    fds, hashes = {}, {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    sinks = sinks or {"stdout": sys.stdout.buffer, "stderr": sys.stderr.buffer}
    started = time.time() - 1
    try:
        for name in key_names:
            fds[name] = _memfd(name, pems[name])
        argv = [a.replace("{session}", session_id) for a in command]
        for name, fd in fds.items():
            argv = [str(fd) if a == "{keyfd:%s}" % name else a for a in argv]
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tool_root,
                     env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}, pass_fds=tuple(fds.values()), close_fds=True)
        threads = [threading.Thread(target=_tee, args=(getattr(proc, k), sinks[k], hashes[k])) for k in ("stdout", "stderr")]
        for t in threads:
            t.start()
        exit_status = proc.wait()
        for t in threads:
            t.join()
    finally:
        for fd in fds.values():
            os.close(fd)
        for pem in pems.values():
            zero(pem)
    session["exit"] = exit_status
    session["stdout_sha256"], session["stderr_sha256"] = hashes["stdout"].hexdigest(), hashes["stderr"].hexdigest()
    session["outputs"] = {}
    for path in outputs:
        if os.path.isfile(path) and not os.path.islink(path):
            with open(path, "rb") as f:
                session["outputs"][os.path.abspath(path)] = hashlib.sha256(f.read()).hexdigest()
        else:
            session["outputs"][os.path.abspath(path)] = None
    session["key_material_found"] = _leaks(out, started, ders)
    try:                                 # anything the command wrote into the tree it ran from (regalia-kms-d9 on #115)
        session["tool_digest_after"] = tree_digest(tool_root)
    except Refused as refusal:
        session["tool_digest_after"] = "refused: %s" % refusal
    # recorded first, whatever happened (regalia-kms-d9 on #115): every refusal below names a record that exists
    record_path = write_record(out, "session-%s-%s" % (at.replace(":", ""), tool), root, session)
    del root
    require(exit_status == 0, "the command exited %d: the session is recorded (%s), nothing it wrote is vouched for" % (exit_status, record_path))
    require(not session["key_material_found"], "KEY MATERIAL LEFT IN %s by the command: %s. Recorded (%s); destroy those files and this RAM "
            "directory before anything leaves the laptop" % (out, ", ".join(session["key_material_found"]), record_path))
    require(session["tool_digest_after"] == tool_digest, "the regalia-kms tree changed while the command ran (%s): recorded (%s); "
            "nothing it wrote is vouched for" % (session["tool_digest_after"], record_path))
    missing = [path for path, digest in session["outputs"].items() if digest is None]
    require(not missing, "the command did not write %s: recorded (%s)" % (", ".join(missing), record_path))
    return session, record_path


# ---- the TPM owner authorizations (regalia-kms#242) -------------------------------------------------------

SCHEMA_OWNERAUTH = "regalia.ownerauth-record/v1"
OWNERAUTH_LABEL = b"regalia-ownerauth/v1\0"


def ownerauth_check(value, node_id):
    """The check value regalia-kms's owner-auth reader compares (regalia-kms-95, #242 PR C): HMAC-SHA256 keyed by the 32
    raw bytes, over the label and the node ID."""
    import hmac
    return hmac.new(bytes(value), OWNERAUTH_LABEL + node_id.encode("ascii"), hashlib.sha256).hexdigest()


def _age_recipient(path):
    with open(path) as f:
        found = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    require(len(found) == 1 and re.fullmatch(r"age1[0-9a-z]+", found[0]) is not None, "%s holds one break-glass age recipient" % path)
    return found[0]


def _gpg(home, *args, run=subprocess.run, **kw):
    return run(["gpg", "--homedir", home, "--batch", "--no-tty", "--no-options", "--quiet", *args], capture_output=True, **kw)


def yubikey_recipients(keys_path, home, run=subprocess.run):
    """The approval YubiKeys' OpenPGP public keys (exported from the cards, armoured or binary), imported into `home`, a
    throwaway GnuPG home in the RAM directory: for each key its primary fingerprint and its ONE usable encryption subkey
    (cv25519 on the card's decryption slot; regalia-kms-24's choice after the 2026-10-04 bench). A key with none, or more
    than one, or expired or revoked, is refused. Returns [{"primary", "subkey"}] in the file's order."""
    done = _gpg(home, "--import", keys_path, run=run)
    require(done.returncode == 0, "gpg could not import %s: %s" % (keys_path, done.stderr.decode(errors="replace").strip()[-200:]))
    listing = _gpg(home, "--with-colons", "--fixed-list-mode", "--list-keys", run=run)
    require(listing.returncode == 0, "gpg could not list the imported keys")
    keys, current, last = [], None, None
    for line in listing.stdout.decode().splitlines():
        f = line.split(":")
        if f[0] == "pub":
            current = {"validity": f[1], "subkeys": []}
            keys.append(current)
            last = current
        elif f[0] == "sub" and current is not None:
            sub = {"validity": f[1], "caps": f[11]}
            current["subkeys"].append(sub)
            last = sub
        elif f[0] == "fpr" and last is not None:
            last["fpr"] = f[9]
    require(keys, "%s holds no OpenPGP public key" % keys_path)
    out = []
    for key in keys:
        require(key["validity"] not in ("e", "r", "d", "i"), "key %s is expired, revoked or invalid" % key.get("fpr"))
        enc = [s for s in key["subkeys"] if "e" in s["caps"] and s["validity"] not in ("e", "r", "d", "i")]
        require(len(enc) == 1, "key %s has %d usable encryption subkeys, not one (the card's decryption slot)" % (key.get("fpr"), len(enc)))
        out.append({"primary": key["fpr"], "subkey": enc[0]["fpr"]})
    require(len({k["subkey"] for k in out}) == len(out), "an encryption subkey is listed twice")
    return out


def ownerauth(sealed_path, nodes, yk_keys, breakglass_recipient, out, stream, now=None, run=subprocess.run):
    """Each KMS host's TPM owner authorization (regalia-kms#242: set at enrolment, kept off the host): 32 random bytes per
    node, as 64 lowercase hex and a newline, encrypted with gpg to every approval YubiKey's OpenPGP decryption subkey
    (any one card decrypts) in ownerauth-<node>.yk.gpg, and with age to the break-glass key in ownerauth-<node>.bg.age.
    The plaintext reaches gpg and age on stdin only, and neither file may hold it in the clear. Both files' SHA-256 and
    the check value go into ownerauth.record.json, signed by the root, which this session opens from the k shares on
    `stream` for that alone. Returns the record."""
    import shutil
    require(nodes and len(set(nodes)) == len(nodes) and all(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", n) for n in nodes),
            "--nodes names each node once, by its node ID")
    require(os.path.isdir(out), "--out %s is not a directory" % out)
    check_place(out)
    names = ["ownerauth-%s.yk.gpg" % n for n in nodes] + ["ownerauth-%s.bg.age" % n for n in nodes] + ["ownerauth.record.json"]
    for name in names:
        require(not os.path.lexists(os.path.join(out, name)), "%s already exists: nothing is overwritten" % os.path.join(out, name))
    bg = _age_recipient(breakglass_recipient)
    home = os.path.join(out, ".gnupg-ownerauth")
    require(not os.path.lexists(home), "%s exists: a run before this one did not finish; remove it by that name" % home)
    os.mkdir(home, 0o700)
    try:
        yk = yubikey_recipients(yk_keys, home, run)
        with open(sealed_path, "rb") as f:
            sealed = json.loads(f.read(1 << 20))
        require(sealed.get("schema") == SCHEMA_SEALED, "not a sealed offline-key file")
        master, indices, identifier = combine(read_shares(stream), sealed)
        try:
            bundle = unseal(master, sealed)
        finally:
            zero(master)
        root = _private_key(bundle["keys"]["root"])
        del bundle
        from cryptography.hazmat.primitives import serialization
        entry = {"alg": "ed25519", "key": root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        written, record_nodes = [], {}
        try:
            for node in nodes:
                value = bytearray(secrets.token_bytes(32))
                plain = bytearray(value.hex().encode() + b"\n")
                try:
                    digests = {}
                    for kind, path in (("yk", os.path.join(out, "ownerauth-%s.yk.gpg" % node)), ("bg", os.path.join(out, "ownerauth-%s.bg.age" % node))):
                        written.append(path)
                        if kind == "yk":
                            argv = ["gpg", "--homedir", home, "--batch", "--no-tty", "--no-options", "--quiet", "--trust-model", "always",
                                    "--no-auto-key-locate", "--output", path]
                            for k in yk:
                                argv += ["--recipient", k["subkey"] + "!"]
                            argv.append("--encrypt")
                        else:
                            argv = ["age", "-r", bg, "-o", path]
                        done = run(argv, input=bytes(plain), capture_output=True)
                        require(done.returncode == 0, "%s could not encrypt %s: %s" % (argv[0], path, done.stderr.decode(errors="replace").strip()[-200:]))
                        with open(path, "rb") as f:
                            data = f.read()
                        require(data[:1] and (data[0] & 0x80 if kind == "yk" else data.startswith(b"age-encryption.org/v1")),
                                "%s is not an %s file" % (path, "OpenPGP" if kind == "yk" else "age"))
                        require(bytes(plain).strip() not in data and bytes(value) not in data, "%s holds the owner authorization in the clear" % path)
                        digests[kind + "_sha256"] = hashlib.sha256(data).hexdigest()
                    record_nodes[node] = dict(digests, check=ownerauth_check(value, node))
                finally:
                    zero(value)
                    zero(plain)
        except BaseException:
            for path in written:              # nothing half-made is left: every file this run wrote, by its exact name
                if os.path.lexists(path):
                    os.unlink(path)
            raise
    finally:
        shutil.rmtree(home, ignore_errors=True)      # the throwaway GnuPG home: public keys only, by its exact path
    record = {"schema": SCHEMA_OWNERAUTH, "event": "ownerauth", "nodes": record_nodes, "yk_recipients": yk, "root_entry": entry,
              "root_fingerprint": root_fingerprint(entry), "session": secrets.token_hex(16), "share_indices": indices,
              "slip39_identifier": identifier, "master_id": sealed["master_id"], "tool": TOOL,
              "at": (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    write_record(out, "ownerauth", root, record)
    del root
    return record


VERIFY_LOG = "ownerauth-verify.jsonl"


def ownerauth_verify(record_path, directory, serial, gnupghome=None, now=None, run=subprocess.run):
    """With ONE approval YubiKey inserted (gpg reaching it through scdaemon, in the operator's GnuPG home or
    `gnupghome`): every node's .yk.gpg is decrypted to a pipe, never shown, and must be 64 hex and a newline whose check
    value is the record's, from a file whose SHA-256 is the record's, decrypted by a subkey the record names (gpg's
    DECRYPTION_KEY status line) (regalia-kms-d9 on #120: the envelopes are proven to open, not assumed to). The result,
    good or not, is appended to DIR/ownerauth-verify.jsonl. Returns the nodes proven."""
    import hmac
    with open(record_path, "rb") as f:
        record = verify_record(json.loads(f.read(1 << 20)))
    require(record.get("schema") == SCHEMA_OWNERAUTH, "not an owner-authorization record")
    require(re.fullmatch(r"[0-9]{1,12}", str(serial)) is not None, "--yubikey-serial is the inserted YubiKey's serial")
    subkeys = {k["subkey"]: k["primary"] for k in record["yk_recipients"]}
    proven, failed, used = [], {}, set()
    for node, facts in sorted(record["nodes"].items()):
        path = os.path.join(directory, "ownerauth-%s.yk.gpg" % node)
        try:
            with open(path, "rb") as f:
                require(hashlib.sha256(f.read()).hexdigest() == facts["yk_sha256"], "%s is not the file the record names" % path)
            argv = ["gpg"] + (["--homedir", gnupghome] if gnupghome else []) + ["--batch", "--status-fd", "2", "--decrypt", path]
            done = run(argv, capture_output=True)
            plain = bytearray(done.stdout)
            try:
                require(done.returncode == 0, "gpg could not open it with this YubiKey")
                keys = re.findall(rb"\[GNUPG:\] DECRYPTION_KEY ([0-9A-F]{40})", done.stderr)
                require(keys and keys[-1].decode() in subkeys, "it was opened by a key the record does not name")
                used.add(keys[-1].decode())
                require(re.fullmatch(rb"[0-9a-f]{64}\n", bytes(plain)) is not None, "it does not hold 64 hex and a newline")
                value = bytearray(bytes.fromhex(bytes(plain[:64]).decode()))
                try:
                    require(hmac.compare_digest(ownerauth_check(value, node), facts["check"]), "its value is not the one the record checks")
                finally:
                    zero(value)
            finally:
                zero(plain)
            proven.append(node)
        except (Refused, OSError) as error:
            failed[node] = str(error)
    require(len(used) <= 1, "this run used more than one key (%s): insert ONE YubiKey at a time" % ", ".join(sorted(used)))
    entry = {"serial": str(serial), "subkey": used.pop() if used else None, "proven": proven, "failed": failed, "session": record["session"],
             "at": (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    fd = os.open(os.path.join(directory, VERIFY_LOG), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    require(not failed, "YubiKey %s did NOT open: %s" % (serial, "; ".join("%s (%s)" % kv for kv in sorted(failed.items()))))
    return proven


def ownerauth_summary(record_path, directory):
    """Whether every approval YubiKey (each encryption subkey the record names) has opened every node's envelope, by
    ownerauth-verify's log. Returns {subkey: serial}; refused, naming what is missing, otherwise. The ceremony does not
    finish without it."""
    with open(record_path, "rb") as f:
        record = verify_record(json.loads(f.read(1 << 20)))
    require(record.get("schema") == SCHEMA_OWNERAUTH, "not an owner-authorization record")
    nodes = sorted(record["nodes"])
    seen = {}
    log = os.path.join(directory, VERIFY_LOG)
    if os.path.exists(log):
        with open(log) as f:
            for line in f:
                e = json.loads(line)
                if e.get("session") == record["session"] and sorted(e.get("proven", [])) == nodes and not e.get("failed") and e.get("subkey"):
                    seen[e["subkey"]] = e["serial"]
    missing = [k["subkey"] for k in record["yk_recipients"] if k["subkey"] not in seen]
    require(not missing, "not yet proven to open every envelope: the YubiKeys with subkeys %s" % ", ".join(m[-16:] for m in missing))
    return seen


def write_record(out, stem, root, record):
    """OUT/<stem>.record.json: `record` signed by the root over RECORD_DOMAIN, never overwriting. Returns the path."""
    path = os.path.join(out, stem + ".record.json")
    signature = root.sign(RECORD_DOMAIN + canonical(record))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical({"record": record, "signature": signature.hex()}) + b"\n")
        f.flush()
        os.fsync(f.fileno())
    return path


def verify_record(document):
    """A record's signature under the root entry it names. Returns the record, or Refused."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    require(isinstance(document, dict) and set(document) == {"record", "signature"}, "not an offline-key record")
    record = document["record"]
    require(record.get("schema") in (SCHEMA_RECORD, SCHEMA_OWNERAUTH), "schema must be %s or %s" % (SCHEMA_RECORD, SCHEMA_OWNERAUTH))
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
    s = sub.add_parser("sign", help="a signing session: the k shares on standard input, one per line")
    s.add_argument("--sealed", required=True)
    s.add_argument("--who", required=True, help="the person signing, as recorded")
    s.add_argument("--out", required=True, help="the session's RAM directory, where its record goes")
    s.add_argument("--tool-root", required=True, help="the regalia-kms tree the command runs from")
    s.add_argument("--tool-digest", required=True, help="that tree's digest, from the ceremony image's build evidence")
    s.add_argument("--output", action="append", default=[], help="a file the command must write (its SHA-256 is recorded)")
    s.add_argument("--exec", nargs=argparse.REMAINDER, dest="exec_argv", required=True,
                   help="/usr/bin/python3 -Es -m deploy.baremetal.(manifest|uki) sign …, last on the line")
    t = sub.add_parser("tree-digest", help="the digest of a regalia-kms tree, as --tool-digest takes it")
    t.add_argument("--root", required=True)
    o = sub.add_parser("ownerauth", help="each KMS host's TPM owner authorization, for regalia-kms#242: the k shares on standard input")
    o.add_argument("--sealed", required=True)
    o.add_argument("--nodes", required=True, help="the node IDs, comma-separated (a,b,c)")
    o.add_argument("--yk-keys", required=True, help="the approval YubiKeys' OpenPGP public keys, exported from the cards")
    o.add_argument("--breakglass-recipient", required=True)
    o.add_argument("--out", required=True, help="a RAM directory for the files and the record")
    ov = sub.add_parser("ownerauth-verify", help="with one approval YubiKey inserted: prove it opens every node's envelope")
    ov.add_argument("--record", required=True)
    ov.add_argument("--dir", required=True, help="where the envelopes are; the log is appended there")
    ov.add_argument("--gnupghome", help="the GnuPG home that reaches the inserted card (default: the operator's)")
    ov.add_argument("--yubikey-serial", help="the inserted YubiKey's serial, as ykman reports it")
    ov.add_argument("--summary", action="store_true", help="refuse unless every YubiKey has opened every envelope")
    v = sub.add_parser("verify-record")
    v.add_argument("--record", required=True)
    args = ap.parse_args(argv)
    try:
        if args.command == "generate":
            record = generate(args.threshold, args.shares, args.out, args.breakglass_recipient)
            print("ROOT-ENTRY %s" % json.dumps(record["root_entry"], sort_keys=True))
            print("ROOT-FINGERPRINT %s  (sha256 of the raw 32-byte Ed25519 key, as enrol check and manifest sign --genesis take it)"
                  % record["root_fingerprint"])
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
        elif args.command == "sign":
            session, path = sign(args.sealed, args.who, args.out, sys.stdin, args.exec_argv, args.tool_root, args.tool_digest, args.output)
            print("SIGNED by %s with %s (shares %s), session %s; record %s" % (session["tool"], ", ".join(session["keys"]),
                  ",".join(str(i) for i in session["share_indices"]), session["session"], path))
        elif args.command == "ownerauth":
            record = ownerauth(args.sealed, args.nodes.split(","), args.yk_keys, args.breakglass_recipient, args.out, sys.stdin)
            for node, facts in sorted(record["nodes"].items()):
                print("OWNERAUTH %s yk %s bg %s check %s" % (node, facts["yk_sha256"][:16], facts["bg_sha256"][:16], facts["check"][:16]))
            print("RECORD %s (root %s)" % (os.path.join(args.out, "ownerauth.record.json"), record["root_fingerprint"]))
        elif args.command == "ownerauth-verify":
            if args.summary:
                for subkey, serial in sorted(ownerauth_summary(args.record, args.dir).items()):
                    print("PROVEN YubiKey %s (subkey …%s) opens every node's envelope" % (serial, subkey[-16:]))
                print("OWNERAUTH ENVELOPES PROVEN for every approval YubiKey")
            else:
                require(args.yubikey_serial, "--yubikey-serial names the inserted YubiKey")
                proven = ownerauth_verify(args.record, args.dir, args.yubikey_serial, args.gnupghome)
                print("YubiKey %s opens %s" % (args.yubikey_serial, ", ".join(proven)))
        elif args.command == "tree-digest":
            print(tree_digest(args.root))
        else:
            with open(args.record, "rb") as f:
                record = verify_record(json.loads(f.read(1 << 20)))
            print("VERIFIED %s at %s, root %s, fingerprint %s" % (record["event"], record["at"], record["root_entry"]["key"],
                                                                  root_fingerprint(record["root_entry"])))
    except (Refused, OSError, ValueError, KeyError) as error:
        print("offline-keys: REFUSED: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
