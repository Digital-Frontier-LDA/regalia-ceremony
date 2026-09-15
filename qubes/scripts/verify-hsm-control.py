#!/usr/bin/env python3
"""Prove the HSM controls the private key for the funding pubkey it just exported.

Used in the Nitrokey HSM 2 funding-key ceremony (step 4). The HSM exports only the PUBLIC
key, and the wizard derives the funding address from it. But an exported pubkey is NOT proof
that the device holds the matching PRIVATE key: a faulty keygen, the wrong --id object, or
hostile firmware can hand you a pubkey whose private key the device does not have. Funding the
address derived from such a pubkey loses the money forever — it can never be spent.

This closes that gap: the ceremony signs a fresh random digest on the HSM with the funding key
(pkcs11-tool --sign --id 01 -m ECDSA), and this script verifies that raw ECDSA/secp256k1
signature against the EXPORTED public key. Exit 0 iff it verifies — which can only happen if
the signer holds the private key matching the exported public key. If it fails, the wizard
MUST refuse to print/record the funding address.

  verify-hsm-control.py --der funding-pub.der --digest kat.digest --sig kat.sig

Pure stdlib (vendors secp256k1 point arithmetic) so it runs OFFLINE on the air-gapped vault
qube. The signature is the raw r||s concatenation pkcs11-tool emits for CKM_ECDSA (64 bytes for
secp256k1); the digest is the exact bytes that were signed (a 32-byte hash).
"""
import argparse
import sys

# ---- secp256k1 domain parameters (y^2 = x^3 + 7 mod p) ----------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def inv_mod(a: int, m: int) -> int:
    return pow(a % m, m - 2, m)  # m is prime (P or N)


def is_on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (pow(x, 3, P) + B)) % P == 0


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # point at infinity
    if a == b:
        # doubling: slope = (3x^2) / (2y)
        s = (3 * x1 * x1) * inv_mod(2 * y1, P) % P
    else:
        s = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k: int, pt):
    k %= N
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ---- SubjectPublicKeyInfo DER -> (x, y) point (secp256k1 only) ---------------
OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
OID_SECP256K1 = bytes.fromhex("06052b8104000a")


def _read_tlv(buf, i):
    if i + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[i]; i += 1
    ln = buf[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7f
        if i + n > len(buf):
            raise ValueError("truncated DER length")
        ln = int.from_bytes(buf[i:i + n], "big"); i += n
    if i + ln > len(buf):
        raise ValueError("DER length exceeds buffer")
    return tag, buf[i:i + ln], i + ln


def point_from_der(der: bytes):
    tag, seq, end = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER SEQUENCE")
    if end != len(der):
        raise ValueError("trailing bytes after SubjectPublicKeyInfo")
    tag, alg, j = _read_tlv(seq, 0)
    if tag != 0x30:
        raise ValueError("expected AlgorithmIdentifier SEQUENCE")
    # Strict: the AlgorithmIdentifier must be EXACTLY {id-ecPublicKey, secp256k1} with no
    # trailing/extra parameters. A substring (`in`) test could false-positive if the OID byte
    # sequence appeared elsewhere in a crafted AlgorithmIdentifier — unacceptable for a
    # fail-closed ceremony control. OID_* are the full DER TLVs, so exact concatenation holds.
    if alg != OID_EC_PUBLIC_KEY + OID_SECP256K1:
        if not alg.startswith(OID_EC_PUBLIC_KEY):
            raise ValueError("not an EC public key (id-ecPublicKey OID absent or misplaced)")
        if OID_SECP256K1 not in alg:
            raise ValueError("public key is not on secp256k1 (wrong curve)")
        raise ValueError("unexpected AlgorithmIdentifier (extra/parameters present) — refusing")
    tag, bitstr, _ = _read_tlv(seq, j)
    if tag != 0x03 or not bitstr or bitstr[0] != 0x00:
        raise ValueError("expected a DER BIT STRING (0 unused bits) for the public key")
    return point_from_bytes(bitstr[1:])


def point_from_bytes(pt: bytes):
    """Accept a 65-byte uncompressed (04||X||Y) or 33-byte compressed (02/03||X) point."""
    if len(pt) == 65 and pt[0] == 0x04:
        x = int.from_bytes(pt[1:33], "big")
        y = int.from_bytes(pt[33:65], "big")
    elif len(pt) == 33 and pt[0] in (2, 3):
        x = int.from_bytes(pt[1:33], "big")
        if not (0 < x < P):
            raise ValueError("compressed point x out of field range")
        rhs = (pow(x, 3, P) + B) % P
        y = pow(rhs, (P + 1) // 4, P)  # p % 4 == 3 -> sqrt = rhs^((p+1)/4)
        if (y * y - rhs) % P != 0:
            raise ValueError("compressed point is not on secp256k1")
        if (y & 1) != (pt[0] & 1):
            y = P - y
    else:
        raise ValueError(f"unexpected EC point length/format: {len(pt)} bytes")
    point = (x, y)
    if not is_on_curve(point):
        raise ValueError("public key point is not on secp256k1")
    return point


# ---- ECDSA verification (raw r||s over a 32-byte digest) ---------------------
def verify(pub_point, digest: bytes, sig: bytes) -> bool:
    if len(sig) % 2 != 0 or len(sig) == 0:
        return False
    half = len(sig) // 2
    r = int.from_bytes(sig[:half], "big")
    s = int.from_bytes(sig[half:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(digest, "big")
    if digest and (len(digest) * 8) > N.bit_length():
        z >>= (len(digest) * 8 - N.bit_length())
    w = inv_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    point = point_add(scalar_mul(u1, G), scalar_mul(u2, pub_point))
    if point is None:
        return False
    return (point[0] % N) == r


def main():
    ap = argparse.ArgumentParser(description="Prove an HSM controls the private key for an exported pubkey.")
    ap.add_argument("--der", required=True, help="SubjectPublicKeyInfo DER the HSM exported")
    ap.add_argument("--digest", required=True, help="file with the exact digest bytes that were signed")
    ap.add_argument("--sig", required=True, help="raw ECDSA signature (r||s) from pkcs11-tool --sign")
    a = ap.parse_args()
    try:
        with open(a.der, "rb") as f:
            pub = point_from_der(f.read())
        with open(a.digest, "rb") as f:
            digest = f.read()
        with open(a.sig, "rb") as f:
            sig = f.read()
    except (OSError, ValueError) as e:
        print(f"keypair-control proof ERROR: {e}", file=sys.stderr)
        return 2
    # Validate lengths so an operator mistake (a DER/ASN.1 signature, or a digest file with a
    # trailing newline) fails with a precise message instead of a generic verify failure.
    if len(digest) != 32:
        print(f"keypair-control proof ERROR: digest is {len(digest)} bytes, expected 32 "
              f"(raw SHA-256; no trailing newline)", file=sys.stderr)
        return 2
    if len(sig) != 64:
        print(f"keypair-control proof ERROR: signature is {len(sig)} bytes, expected 64 "
              f"(raw CKM_ECDSA r||s from pkcs11-tool --sign; not an ASN.1/DER signature)", file=sys.stderr)
        return 2
    if verify(pub, digest, sig):
        return 0
    print("keypair-control proof FAILED: signature does not verify against the exported pubkey",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
