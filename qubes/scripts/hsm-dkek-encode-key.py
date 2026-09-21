#!/usr/bin/env python3
"""hsm-dkek-encode-key.py — wrap a private key under a DKEK, so a SmartCard-HSM can UNWRAP it.

WHY THIS EXISTS. Importing a key the ceremony generated off-card is the one step that still needed
a Java Smart Card Shell: `sc-hsm-tool` can unwrap a blob but cannot BUILD one, and the blob format
lived only in scsh's DKEK.js. regalia#486 decided the ceremony path drops scsh rather than pinning
a JVM and an unsigned vendor zip on the machine that mints keys, so the format is implemented here,
in the open, against the same primitives the card uses.

    hsm-dkek-encode-key.py --p12 funding.p12 --p12-pass-file p12.pw \\
        --dkek-share dkek.pbe --dkek-pw-file dkek.pw --out funding-wrapped.bin

THE BLOB, for an EC key (DKEK.js encodeKey):

    KCV(8) || 0x0C || u16(len(oid)) || oid || 00 00 | 00 00 | 00 00 || AES-CBC(KENC, IV=0, pad(kb))
          || AES-CMAC(KMAC, everything above)

    kb = random(8) || u16(bit length of p)
         || u16||a  u16||b  u16||p  u16||n  u16||(04 Gx Gy)  u16||d  u16||(04 Qx Qy)

    KCV  = SHA256(dkek)[:8]      KENC = SHA256(dkek || 00000001)      KMAC = SHA256(dkek || 00000002)

padded ISO 9797-1 method 2 (0x80 then zeros) to 8 bytes, then another 8 zero bytes when that leaves
an odd AES block — scsh's own comment: "pad() pads to 8 byte blocks, but we 16 byte blocks".

THE CURVE PARAMETERS ARE WRITTEN OUT, not read from the key. The card is handed the domain it must
use, and `cryptography` does not expose a,b,p,n,G for a named curve. They are checked before use:
G must lie on the curve and the public point must equal d*G, so a wrong table cannot silently
produce a blob the card accepts for a key nobody has.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

try:
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:                                            # pragma: no cover - environment
    sys.exit("this needs `cryptography` (qubes/requirements.txt pins it)")

# id-TA-ECDSA-SHA-256, 0.4.0.127.0.7.2.2.2.2.3 — the TR-03110 OID the card expects for an EC key.
EC_ALGO_OID = bytes.fromhex("04007F000702020202 03".replace(" ", ""))

# Domain parameters, from SEC 2 / FIPS 186-4. Checked against the key before they are used.
CURVES = {
    "secp256k1": dict(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        a=0x0000000000000000000000000000000000000000000000000000000000000000,
        b=0x0000000000000000000000000000000000000000000000000000000000000007,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    "secp256r1": dict(
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
}
CURVE_ALIASES = {"prime256v1": "secp256r1"}


def derive_share_key(salt: bytes, password: bytes) -> bytes:
    """The 48 bytes (32 key + 16 IV) that decrypt a `.pbe` DKEK share.

    Three rounds of `d = md5^10_000_000(d || password || salt)`, exactly DKEK.deriveDKEKShareKey.
    That is 30 million sequential MD5 calls — about 45 seconds here against roughly 20 in the JVM.
    It is the cost of the format, not of this implementation, and it is paid once per ceremony.
    """
    d = b""
    out = b""
    for _ in range(3):
        d = d + password + salt
        for _ in range(10_000_000):
            d = hashlib.md5(d).digest()
        out += d
    return out


def decrypt_share(blob: bytes, password: bytes) -> bytes:
    """The 32-byte share inside a `sc-hsm-tool --create-dkek-share` file."""
    if len(blob) != 64 or blob[:8] != b"Salted__":
        raise ValueError("this is not an encrypted DKEK share (expected 64 bytes starting Salted__)")
    keyiv = derive_share_key(blob[8:16], password)
    dec = Cipher(algorithms.AES(keyiv[:32]), modes.CBC(keyiv[32:48])).decryptor()
    plain = dec.update(blob[16:]) + dec.finalize()
    # The share carries its own check: the trailing block is 16 bytes of 0x10. Without it a wrong
    # password yields 48 bytes of noise that would be wrapped into a blob the card silently rejects.
    if plain[-16:] != bytes([0x10]) * 16:
        raise ValueError("decryption of the DKEK share failed — wrong password?")
    return plain[:32]


def _minimal_bytes(n: int) -> bytes:
    """OpenSC prints and rebuilds these as MINIMAL big-endian byte strings.

    THE LEADING-ZERO DROP IS PART OF THE FORMAT, not a bug to correct here. OpenSC's
    recreate_password_from_shares converts the reconstructed integer with BN_bn2bin, which emits no
    leading zero byte — so a password whose first byte happened to be zero comes back SEVEN bytes
    long, and the share file decrypts under those seven bytes. Padding it back to eight would
    reconstruct a password the real tool never used. (This is the 1-in-128 asymmetry recorded in
    regalia#460.)
    """
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def reconstruct_share_password(prime: int, shares: list[tuple[int, int]]) -> bytes:
    """Lagrange interpolation at x=0 over GF(prime), as OpenSC does it.

    `sc-hsm-tool --create-dkek-share --pwd-shares-threshold t --pwd-shares-total n` does not use a
    typed password at all: it generates 8 random bytes (with the top bit of the first cleared, so
    the secret stays below the 64-bit prime), splits them with Shamir over that prime, and prints
    only the shares. The password itself is never written down. So reconstructing it from the
    shares is the ONLY way to open such a share file without the card in the loop -- and without it
    the JVM-free import path cannot serve a ceremony that used the share ceremony, which is every
    real one.
    """
    if prime < 2:
        raise ValueError("the prime is not usable")
    ids = [x for x, _ in shares]
    if len(set(ids)) != len(ids):
        raise ValueError("two shares carry the same ID; they cannot be interpolated")
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        numerator, denominator = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = numerator * -xj % prime
                denominator = denominator * (xi - xj) % prime
        inverse = pow(denominator, -1, prime)
        secret = (secret + yi * numerator % prime * inverse) % prime
    return _minimal_bytes(secret)


def parse_share_file(text: str, use: list[int] | None = None) -> tuple[int, list[tuple[int, int]]]:
    """Read the prime and shares out of what `--create-dkek-share` printed.

        Prime       : ab:cd:...
        Share ID    : 1
        Share value : 12:34:...

    The prime is printed once per share and must agree everywhere: a file whose shares disagree on
    it is a file assembled from two different ceremonies, and interpolating across them would yield
    a confident wrong password rather than an error.
    """
    primes: list[int] = []
    shares: list[tuple[int, int]] = []
    pending_id: int | None = None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "Prime":
            primes.append(int(value.replace(":", ""), 16))
        elif key == "Share ID":
            pending_id = int(value)
        elif key == "Share value":
            if pending_id is None:
                raise ValueError("a share value appears before its share ID")
            shares.append((pending_id, int(value.replace(":", ""), 16)))
            pending_id = None
    if not primes:
        raise ValueError("no 'Prime' line in the share file")
    if len(set(primes)) != 1:
        raise ValueError("the shares disagree about the prime; this file mixes two ceremonies")
    if not shares:
        raise ValueError("no shares in the file")
    # DUPLICATES ARE REFUSED HERE, BEFORE `use` IS APPLIED. dict(shares) silently keeps the last
    # value for a repeated ID, so a file listing share 1 twice with different values would be
    # collapsed without a word — and selecting by ID would then bypass the duplicate check in
    # reconstruct_share_password entirely. A share file with a repeated ID is a file somebody
    # assembled by hand, and interpolating whatever survived the collapse yields a confident wrong
    # password rather than an error.
    ids = [n for n, _ in shares]
    repeated = sorted({n for n in ids if ids.count(n) > 1})
    if repeated:
        raise ValueError(f"share ID(s) {repeated} appear more than once in this file")
    if use is not None:
        by_id = dict(shares)
        missing = [n for n in use if n not in by_id]
        if missing:
            raise ValueError(f"share(s) {missing} are not in this file")
        shares = [(n, by_id[n]) for n in use]
    return primes[0], shares


def dkek_keys(dkek: bytes) -> tuple[bytes, bytes, bytes]:
    kcv = hashlib.sha256(dkek).digest()[:8]
    kenc = hashlib.sha256(dkek + bytes.fromhex("00000001")).digest()
    kmac = hashlib.sha256(dkek + bytes.fromhex("00000002")).digest()
    return kcv, kenc, kmac


def curve_params(key: ec.EllipticCurvePrivateKey) -> dict:
    name = key.curve.name
    name = CURVE_ALIASES.get(name, name)
    if name not in CURVES:
        raise ValueError(f"curve {key.curve.name} is not one this tool has parameters for "
                         f"({', '.join(sorted(CURVES))})")
    c = CURVES[name]
    # THE TABLE IS CHECKED, NOT TRUSTED. G on the curve, and the key's own public point equal to
    # d*G: a wrong constant here would hand the card a domain that is not the key's.
    p, a, b = c["p"], c["a"], c["b"]
    if (c["gy"] * c["gy"] - (c["gx"] ** 3 + a * c["gx"] + b)) % p != 0:
        raise ValueError(f"the stored generator for {name} is not on the curve — refusing")
    numbers = key.private_numbers()
    pub = numbers.public_numbers
    expected = ec.derive_private_key(numbers.private_value, key.curve).public_key().public_numbers()
    if (pub.x, pub.y) != (expected.x, expected.y):
        raise ValueError("the PKCS#12's public point does not match its private scalar")
    if (pub.y * pub.y - (pub.x ** 3 + a * pub.x + b)) % p != 0:
        raise ValueError(f"the key's public point is not on {name} — the parameters do not describe this key")
    return c


def i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def lv(data: bytes) -> bytes:
    """u16 length, then the value — the shape every field in the key body uses."""
    return len(data).to_bytes(2, "big") + data


def encode_ec_key(key: ec.EllipticCurvePrivateKey, dkek: bytes) -> bytes:
    c = curve_params(key)
    size = (key.curve.key_size + 7) // 8
    numbers = key.private_numbers()
    pub = numbers.public_numbers

    body = os.urandom(8)
    body += i2osp(key.curve.key_size, 2)
    body += lv(i2osp(c["a"], size))
    body += lv(i2osp(c["b"], size))
    body += lv(i2osp(c["p"], size))
    body += lv(i2osp(c["n"], size))
    body += lv(b"\x04" + i2osp(c["gx"], size) + i2osp(c["gy"], size))
    body += lv(i2osp(numbers.private_value, size))
    body += lv(b"\x04" + i2osp(pub.x, size) + i2osp(pub.y, size))

    padded = body + b"\x80"
    while len(padded) % 8:
        padded += b"\x00"
    if len(padded) % 16:
        padded += b"\x00" * 8

    kcv, kenc, kmac = dkek_keys(dkek)
    enc = Cipher(algorithms.AES(kenc), modes.CBC(b"\x00" * 16)).encryptor()
    cipher = enc.update(padded) + enc.finalize()

    head = kcv + bytes([0x0C]) + i2osp(len(EC_ALGO_OID), 2) + EC_ALGO_OID
    head += b"\x00\x00" * 3
    blob = head + cipher
    mac = cmac.CMAC(algorithms.AES(kmac))
    mac.update(blob)
    return blob + mac.finalize()


def read_secret(path: str) -> bytes:
    """A password from a FILE, never from argv — the process table is world-readable."""
    with open(path, "rb") as fh:
        return fh.read().strip(b"\r\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--p12", required=True, help="PKCS#12 holding the key to wrap")
    ap.add_argument("--p12-pass-file", required=True, help="file holding the PKCS#12 password")
    ap.add_argument("--dkek-share", required=True, help="the .pbe share the card also imported")
    ap.add_argument("--dkek-pw-file", help="file holding that share's password")
    ap.add_argument("--dkek-shares-file",
                    help="what `--create-dkek-share --pwd-shares-threshold/-total` printed; the "
                         "password is reconstructed from its shares instead of being typed")
    ap.add_argument("--dkek-shares-use",
                    help="comma-separated share IDs to interpolate (default: the first threshold "
                         "many in the file). Give exactly as many as the threshold.")
    ap.add_argument("--out", required=True, help="where to write the key blob")
    ap.add_argument("--print-kcv", action="store_true",
                    help="also print the DKEK's key check value, which the card reports after import")
    args = ap.parse_args()

    if bool(args.dkek_pw_file) == bool(args.dkek_shares_file):
        return fail("give exactly one of --dkek-pw-file and --dkek-shares-file "
                    "(a share file's password is reconstructed, never also typed)")
    if args.dkek_shares_use and not args.dkek_shares_file:
        return fail("--dkek-shares-use only means something with --dkek-shares-file")
    if args.dkek_shares_file:
        try:
            use = None
            if args.dkek_shares_use:
                use = [int(n) for n in args.dkek_shares_use.split(",") if n.strip()]
                if len(use) != len(set(use)):
                    return fail("--dkek-shares-use names the same share twice; "
                                "interpolation needs distinct IDs")
            prime, shares = parse_share_file(open(args.dkek_shares_file).read(), use)
            password = reconstruct_share_password(prime, shares)
        except (OSError, ValueError) as exc:
            return fail(f"cannot rebuild the share password: {exc}")
    else:
        try:
            password = read_secret(args.dkek_pw_file)
        except OSError as exc:
            return fail(f"cannot read the DKEK password: {exc}")
    try:
        share = decrypt_share(open(args.dkek_share, "rb").read(), password)
    except (OSError, ValueError) as exc:
        return fail(f"cannot read the DKEK share: {exc}")
    # One share, XORed into a zero DKEK, exactly as DKEK.importDKEKShare does. A domain built from
    # several shares is the XOR of all of them; this tool wraps for a single-share domain and says
    # so rather than silently wrapping under a DKEK the card does not hold.
    dkek = share

    try:
        with open(args.p12, "rb") as fh:
            key, _cert, _chain = pkcs12.load_key_and_certificates(
                fh.read(), read_secret(args.p12_pass_file))
    except (OSError, ValueError) as exc:
        return fail(f"cannot read the PKCS#12: {exc}")
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        return fail("only EC keys are implemented here; the ceremony's funding key is secp256k1")

    try:
        blob = encode_ec_key(key, dkek)
    except ValueError as exc:
        return fail(str(exc))

    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    kcv, _, _ = dkek_keys(dkek)
    # The key size is printed so the caller does not have to assume one. It goes into the PrKD,
    # which is what every PKCS#11 consumer reads; a description that disagrees with the key is
    # exactly the mismatch this path exists to avoid, and "probably 256" is not a measurement.
    print(f"wrapped {key.curve.name} key: {len(blob)} bytes -> {args.out}")
    print(f"key size: {key.curve.key_size}")
    if args.print_kcv:
        print(f"dkek kcv: {kcv.hex()}")
    return 0


def fail(message: str) -> int:
    sys.stderr.write(f"hsm-dkek-encode-key: {message}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
