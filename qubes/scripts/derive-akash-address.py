#!/usr/bin/env python3
"""Derive the akash bech32 address from a secp256k1 PUBLIC key.

Used at the end of the Nitrokey HSM 2 funding-key ceremony: the HSM exports only
the PUBLIC key (safe), and this turns it into the akash1… funding address you can
verify on-chain. Pure stdlib — vendors bech32 + ripemd160 so it runs OFFLINE on
any Python 3 (modern OpenSSL dropped ripemd160 from hashlib).

  derive-akash-address.py --der funding-pub.der          # SubjectPublicKeyInfo DER (what the HSM exports)
  derive-akash-address.py --hex 02ab…                     # compressed (33B) or uncompressed (65B) hex
  derive-akash-address.py --der pub.der --hrp akashvaloper

It ALSO closes the Option-B (seed) recovery loop: given a recovered BIP39 mnemonic it derives
the funding address air-gapped so RECOVERY-TECHNICAL.md Step 4 ("verify recovered seed ->
funding address before moving funds") is actually executable with the shipped kit — the
mnemonic is SECRET so it is read from a file, never argv:

  derive-akash-address.py --mnemonic-file funding.mnemonic          # BIP39 -> m/44'/118'/0'/0/0 -> akash1…
  derive-akash-address.py --mnemonic-file f --hd-path "m/44'/118'/0'/0/1"

Address = bech32(hrp, ripemd160(sha256(compressed_pubkey))).  No private key leaves the
machine, no network. Mnemonic->pubkey uses pure-stdlib BIP39 (PBKDF2) + BIP32 (HMAC-SHA512)
+ secp256k1 point math, so it runs OFFLINE on any Python 3 with no third-party wheels.
"""
import argparse
import hashlib
import hmac
import os
import sys
import unicodedata

# ---- bech32 (BIP-0173 reference implementation) -----------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk

def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _create_checksum(hrp, data):
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def bech32_encode(hrp, witprog):
    data = _convertbits(list(witprog), 8, 5)
    combined = data + _create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)

# ---- ripemd160 (pure-python; OpenSSL 3 dropped it from hashlib) --------------
def _ripemd160(msg):
    import struct
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
    rl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    rr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    kl = [0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e]
    kr = [0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000]
    def f(j, x, y, z):
        if j < 16: return x ^ y ^ z
        if j < 32: return (x & y) | (~x & z)
        if j < 48: return (x | ~y) ^ z
        if j < 64: return (x & z) | (y & ~z)
        return x ^ (y | ~z)
    h0,h1,h2,h3,h4 = 0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0
    ml = len(msg)
    msg = msg + b"\x80" + b"\x00" * ((55 - ml) % 64) + struct.pack("<Q", ml * 8)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off+64]))
        al,bl,cl,dl,el = h0,h1,h2,h3,h4
        ar,br,cr,dr,er = h0,h1,h2,h3,h4
        for j in range(80):
            t = (al + f(j, bl, cl, dl) + X[rl[j]] + kl[j//16]) & 0xffffffff
            t = (rol(t, sl[j]) + el) & 0xffffffff
            al,bl,cl,dl,el = el,t,bl,rol(cl,10),dl
            t = (ar + f(79-j, br, cr, dr) + X[rr[j]] + kr[j//16]) & 0xffffffff
            t = (rol(t, sr[j]) + er) & 0xffffffff
            ar,br,cr,dr,er = er,t,br,rol(cr,10),dr
        t  = (h1 + cl + dr) & 0xffffffff
        h1 = (h2 + dl + er) & 0xffffffff
        h2 = (h3 + el + ar) & 0xffffffff
        h3 = (h4 + al + br) & 0xffffffff
        h4 = (h0 + bl + cr) & 0xffffffff
        h0 = t
    return struct.pack("<5I", h0, h1, h2, h3, h4)

# ---- pubkey handling --------------------------------------------------------
# secp256k1 field prime and curve constant b (y^2 = x^3 + 7 mod p).
SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
SECP256K1_B = 7

def _require_on_curve_x(x: int) -> None:
    """Reject an x coordinate that cannot lie on secp256k1 (x out of range, or
    x^3+7 has no square root mod p). A point off the curve would derive a
    valid-looking but UNFUNDABLE address, so this must fail loudly."""
    if not (0 < x < SECP256K1_P):
        raise ValueError("public key x coordinate out of field range (off-curve — would derive a WRONG address)")
    rhs = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
    # Euler's criterion: rhs is a quadratic residue iff rhs^((p-1)/2) == 1.
    if pow(rhs, (SECP256K1_P - 1) // 2, SECP256K1_P) != 1:
        raise ValueError("public key is not on secp256k1 (off-curve x — would derive a WRONG address)")

def compress(point: bytes) -> bytes:
    """Return the 33-byte compressed form. Accepts 33B (already compressed) or 65B (04||X||Y).

    Validates the point is actually ON secp256k1 before trusting it — a corrupted
    or single-bit-glitched point of the right length must NOT silently produce a
    valid-looking but unfundable address."""
    if len(point) == 33 and point[0] in (2, 3):
        x = int.from_bytes(point[1:33], "big")
        _require_on_curve_x(x)
        return point
    if len(point) == 65 and point[0] == 4:
        x = int.from_bytes(point[1:33], "big")
        y = int.from_bytes(point[33:65], "big")
        if not (0 < x < SECP256K1_P) or not (0 < y < SECP256K1_P):
            raise ValueError("public key coordinate out of field range (off-curve — would derive a WRONG address)")
        if (y * y - (pow(x, 3, SECP256K1_P) + SECP256K1_B)) % SECP256K1_P != 0:
            raise ValueError("public key point is not on secp256k1 (off-curve — would derive a WRONG address)")
        return bytes([2 + (point[64] & 1)]) + point[1:33]
    raise ValueError(f"unexpected EC point length/format: {len(point)} bytes, prefix {point[0]:#x}")

# OIDs we require: id-ecPublicKey (1.2.840.10045.2.1) + secp256k1 (1.3.132.0.10).
OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
OID_SECP256K1 = bytes.fromhex("06052b8104000a")

def point_from_der(der: bytes) -> bytes:
    """Extract + validate the EC point from a SubjectPublicKeyInfo DER (secp256k1 only)."""
    def read_tlv(buf, i):
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
    tag, seq, end = read_tlv(der, 0)         # outer SEQUENCE
    if tag != 0x30:                           # explicit (not assert: -O strips asserts)
        raise ValueError("not a DER SEQUENCE")
    if end != len(der):
        raise ValueError("trailing bytes after SubjectPublicKeyInfo")
    tag, alg, j = read_tlv(seq, 0)           # AlgorithmIdentifier SEQUENCE
    if tag != 0x30:
        raise ValueError("expected AlgorithmIdentifier SEQUENCE")
    if OID_EC_PUBLIC_KEY not in alg:
        raise ValueError("not an EC public key (id-ecPublicKey OID absent)")
    if OID_SECP256K1 not in alg:
        raise ValueError("public key is not on secp256k1 (wrong curve — would derive a WRONG address)")
    tag, bitstr, _ = read_tlv(seq, j)        # BIT STRING
    if tag != 0x03 or not bitstr or bitstr[0] != 0x00:
        raise ValueError("expected a DER BIT STRING (0 unused bits) for the public key")
    return bitstr[1:]                         # drop the 'unused bits' byte -> raw point

def derive(point: bytes, hrp: str) -> str:
    comp = compress(point)
    h = _ripemd160(hashlib.sha256(comp).digest())
    return bech32_encode(hrp, h)

# ---- secp256k1 group ops (mnemonic -> pubkey, pure stdlib) -------------------
# y^2 = x^3 + 7 over F_p; generator G and group order n from SEC 2. Only used for the
# Option-B recovery path (BIP32 child-key derivation); the HSM path never touches these.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _pt_add(p, q):
    """Affine point addition on secp256k1. None is the point at infinity."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None                                   # P + (-P) = O
    if p == q:
        m = (3 * x1 * x1) * pow(2 * y1, -1, SECP256K1_P) % SECP256K1_P
    else:
        m = (y2 - y1) * pow((x2 - x1) % SECP256K1_P, -1, SECP256K1_P) % SECP256K1_P
    x3 = (m * m - x1 - x2) % SECP256K1_P
    y3 = (m * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)

def _scalar_mult(k: int, p):
    """Double-and-add k*P."""
    r = None
    while k:
        if k & 1:
            r = _pt_add(r, p)
        p = _pt_add(p, p)
        k >>= 1
    return r

def _pubkey_compressed(priv: int) -> bytes:
    if not (0 < priv < SECP256K1_N):
        raise ValueError("private scalar out of range [1, n-1]")
    x, y = _scalar_mult(priv, (SECP256K1_GX, SECP256K1_GY))
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")

# ---- BIP39 (mnemonic -> seed) + BIP32 (seed -> child privkey), pure stdlib ---
DEFAULT_HD_PATH = "m/44'/118'/0'/0/0"   # Cosmos SLIP-44 coin type 118; what cosmjs/tx-signer use

# Canonical SHA-256 of the published BIP39 English wordlist (newline-joined, trailing
# newline). We integrity-check any wordlist against this before trusting it to validate a
# funding mnemonic — validating against a corrupted list would be worse than not validating.
_BIP39_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

def _bip39_wordlist():
    """Return the 2048-word BIP39 English wordlist, or None if it cannot be obtained
    without a third-party wheel. Sources, in order: the 'mnemonic' package (the ceremony
    kit ships it — bip39-slip39-backup.py requires it), else a 'bip39-english.txt' dropped
    next to this script (pure-stdlib path). The result is SHA-256-verified against the
    canonical published wordlist so we never validate against a tampered/corrupted list."""
    words = None
    try:
        from mnemonic import Mnemonic
        words = list(Mnemonic("english").wordlist)
    except Exception:
        sidecar = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bip39-english.txt")
        try:
            with open(sidecar, encoding="utf-8") as f:
                words = f.read().split()
        except OSError:
            return None
    if not words or len(words) != 2048:
        return None
    joined = ("\n".join(words) + "\n").encode("utf-8")
    if hashlib.sha256(joined).hexdigest() != _BIP39_WORDLIST_SHA256:
        return None
    return words

def _validate_bip39(mnemonic: str) -> None:
    """Hard-fail on a transcription-corrupted BIP39 mnemonic (a non-BIP39 word or a broken
    checksum) BEFORE deriving. A wrong funding seed derives a plausible-but-WRONG akash
    address at exit 0, and on a set-once custodial path that silently loses funds — so this
    is a defense-in-depth layer ahead of (and independent of) the manual on-chain address
    comparison, mirroring bip39-slip39-backup.py's m.check(). If no BIP39 wordlist is
    available (no 'mnemonic' package, no sidecar file), warn loudly rather than silently
    trusting the input — never leaks the secret mnemonic in the message."""
    words = mnemonic.split()
    wl = _bip39_wordlist()
    if wl is None:
        sys.stderr.write("WARNING: BIP39 wordlist unavailable — could NOT verify the mnemonic's "
                         "words or checksum. Install the 'mnemonic' package or drop a verified "
                         "bip39-english.txt next to this script, then re-run; otherwise double-check "
                         "the derived address on-chain before moving any funds.\n")
        return
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic has %d words — not a valid BIP39 length (12/15/18/21/24); "
                         "transcription error? would derive a WRONG address" % len(words))
    index = {w: i for i, w in enumerate(wl)}
    unknown = sum(1 for w in words if w not in index)
    if unknown:
        raise ValueError("mnemonic contains %d word(s) absent from the BIP39 English wordlist "
                         "(transcription error?) — would derive a WRONG address" % unknown)
    bits = "".join(format(index[w], "011b") for w in words)
    ent_len = len(words) * 11 * 32 // 33            # ENT bits; remainder is the checksum
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    expect = "".join(format(b, "08b") for b in hashlib.sha256(ent).digest())[:len(bits) - ent_len]
    if bits[ent_len:] != expect:
        raise ValueError("BIP39 checksum mismatch (transcription error?) — would derive a WRONG address")

def _bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39 seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic"+NFKD(passphrase), 2048)."""
    m = unicodedata.normalize("NFKD", " ".join(mnemonic.split()))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode("utf-8"), salt.encode("utf-8"), 2048, 64)

def _bip32_master(seed: bytes):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    if not (0 < k < SECP256K1_N):
        raise ValueError("invalid BIP32 master key (IL out of range)")
    return k, i[32:]                                  # (privkey int, chain code)

def _ckd_priv(k: int, chain: bytes, index: int):
    if index & 0x80000000:                            # hardened
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:                                             # normal
        data = _pubkey_compressed(k) + index.to_bytes(4, "big")
    i = hmac.new(chain, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    if il >= SECP256K1_N:
        raise ValueError("BIP32 IL >= n (invalid child; would need next index)")
    ki = (il + k) % SECP256K1_N
    if ki == 0:
        raise ValueError("BIP32 child key is zero (invalid child)")
    return ki, i[32:]

def _parse_hd_path(path: str):
    parts = path.strip().split("/")
    if not parts or parts[0] != "m":
        raise ValueError("HD path must start with 'm/' (e.g. m/44'/118'/0'/0/0)")
    out = []
    for seg in parts[1:]:
        if seg == "":
            continue
        hardened = seg[-1] in ("'", "h", "H")
        num = seg[:-1] if hardened else seg
        n = int(num)
        if not (0 <= n < 0x80000000):
            raise ValueError("HD path index out of range: %s" % seg)
        out.append(n + 0x80000000 if hardened else n)
    return out

def address_from_mnemonic(mnemonic: str, hrp: str = "akash",
                          hd_path: str = DEFAULT_HD_PATH, passphrase: str = "",
                          evm: bool = False) -> str:
    """Recovered BIP39 mnemonic -> akash address (BIP32 m/44'/118'/0'/0/0 by default).

    Lets RECOVERY-TECHNICAL.md Step 4 verify a recovered funding seed air-gapped: a wrong
    SLIP-39 passphrase (or wrong shares) yields a DIFFERENT seed -> different address, caught
    here before any funds move. No secret is returned — only the public address."""
    if not mnemonic or not mnemonic.split():
        raise ValueError("empty mnemonic")
    _validate_bip39(mnemonic)
    k, chain = _bip32_master(_bip39_seed(mnemonic, passphrase))
    for index in _parse_hd_path(hd_path):
        k, chain = _ckd_priv(k, chain, index)
    if evm:
        return bech32_encode(hrp, _eth_address_bytes(k))
    return derive(_pubkey_compressed(k), hrp)


# ── Ethermint / EVM derivation ───────────────────────────────────────────────────────────────
# Cosmos SDK chains address a key as bech32(hrp, ripemd160(sha256(compressed))). Ethermint chains
# (Evmos, Injective, Dymension, Canto, XPLA, ZetaChain, Cronos) instead take the ETHEREUM address —
# keccak256 of the uncompressed key without its 0x04 prefix, last 20 bytes — and bech32-wrap that,
# under coin type 60 rather than 118.
#
# Two different algorithms producing two well-formed addresses from one key is the whole hazard:
# get it wrong and you publish a plausible, checksummed address nobody can spend from. So the
# choice is EXPLICIT (--evm) and every ambiguous combination is refused rather than guessed.
#
# VERIFIED, not assumed: this module's own BIP32 + the keccak step below reproduce the published
# vector for the BIP39 all-zeros seed at m/44'/60'/0'/0/0 —
#     0x9858EfFD232B4033E47d90003D41EC34EcaEda94
# and the bech32 wrap reuses bech32_encode, which is pinned to the canonical BIP-173 example.
EVM_HRPS = {
    "evmos": "Evmos", "inj": "Injective", "dym": "Dymension", "canto": "Canto",
    "xpla": "XPLA", "zeta": "ZetaChain", "crc": "Cronos", "cronos": "Cronos",
}
EVM_HD_PATH = "m/44'/60'/0'/0/0"


def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak as _k              # pycryptodome
        return _k.new(data=data, digest_bits=256).digest()
    except ImportError:
        pass
    try:
        from eth_hash.auto import keccak as _k            # eth-hash
        return _k(data)
    except ImportError:
        raise SystemExit(
            "EVM derivation needs keccak256. Install pycryptodome (pinned in the ceremony's\n"
            "requirements.txt) or eth-hash. Refusing rather than substituting SHA3-256, which is\n"
            "a DIFFERENT function and would yield a wrong address."
        )


def _eth_address_bytes(priv: int) -> bytes:
    """The 20-byte Ethereum address for a secp256k1 private scalar."""
    x, y = _scalar_mult(priv, (SECP256K1_GX, SECP256K1_GY))
    return _keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:]


def _coin_type(hd_path: str):
    parts = hd_path.replace("'", "").replace("h", "").split("/")
    if len(parts) > 2 and parts[0] in ("m", "M") and parts[2].isdigit():
        return int(parts[2])
    return None


def _check_evm_consistency(evm: bool, hrp: str, hd_path: str) -> None:
    """Fail closed on every ambiguous combination. Each of these would otherwise emit a
    well-formed, checksummed, WRONG address — the failure that is only discovered when funds
    do not arrive."""
    ct = _coin_type(hd_path)
    known_evm_hrp = hrp in EVM_HRPS
    if not evm and known_evm_hrp:
        raise SystemExit(
            f"REFUSING: --hrp {hrp!r} is {EVM_HRPS[hrp]}, an Ethermint/EVM chain, but --evm was not given.\n"
            "  Its address is keccak256-based, not ripemd160(sha256(...)). Re-run with --evm.\n"
            "  Do NOT work around this by picking a different --hrp."
        )
    if not evm and ct == 60:
        raise SystemExit(
            f"REFUSING: the HD path {hd_path!r} uses coin type 60 (Ethereum) but --evm was not given.\n"
            "  Coin type 60 means the EVM derivation. Re-run with --evm, or use coin type 118."
        )
    if evm and ct is not None and ct != 60:
        raise SystemExit(
            f"REFUSING: --evm was given but the HD path {hd_path!r} uses coin type {ct}, not 60.\n"
            "  An EVM chain derived down the Cosmos path yields an address that chain cannot spend."
        )

def main():
    ap = argparse.ArgumentParser(description="Derive an akash address from a secp256k1 public key "
                                             "or a recovered BIP39 mnemonic.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--der", help="path to a SubjectPublicKeyInfo DER (HSM pubkey export)")
    g.add_argument("--hex", help="public key hex (compressed 33B or uncompressed 65B)")
    g.add_argument("--mnemonic-file", dest="mnemonic_file",
                   help="path to a file holding the recovered BIP39 mnemonic (SECRET — read from "
                        "a file, never argv). Derives via BIP32 --hd-path. Use a tmpfs path.")
    ap.add_argument("--hrp", default="akash", help="bech32 prefix (default: akash)")
    ap.add_argument("--evm", action="store_true",
                    help="Ethermint/EVM chain (Evmos, Injective, …): keccak256-based address, coin type 60")
    ap.add_argument("--hd-path", dest="hd_path", default=None,
                    help="BIP32 derivation path for --mnemonic-file (default %s)" % DEFAULT_HD_PATH)
    ap.add_argument("--bip39-passphrase-file", dest="bip39_passphrase_file", default="",
                    help="optional file with the BIP39 (25th-word) passphrase for --mnemonic-file "
                         "(off-argv; trailing whitespace trimmed). Overridden by the "
                         "BIP39_PASSPHRASE env var if set. Default: empty.")
    a = ap.parse_args()
    # Resolve the path ONLY when the caller left it unset. Comparing against DEFAULT_HD_PATH
    # instead would silently REWRITE an explicitly-passed coin-118 path to coin-60 whenever the
    # two strings happened to match — turning the guard into the very substitution it exists to
    # prevent. Found by this file's own negative control.
    if a.hd_path is None:
        a.hd_path = EVM_HD_PATH if a.evm else DEFAULT_HD_PATH
    _check_evm_consistency(a.evm, a.hrp, a.hd_path)

    if a.mnemonic_file:
        with open(a.mnemonic_file) as f:
            mnemonic = f.read()
        env_pw = os.environ.get("BIP39_PASSPHRASE")
        if env_pw is not None:
            passphrase = env_pw.strip()
        elif a.bip39_passphrase_file:
            with open(a.bip39_passphrase_file) as f:
                passphrase = f.read().strip()
        else:
            passphrase = ""
        if passphrase:
            # LOUD, secret-free warning: a non-empty BIP39 (25th-word) passphrase is being applied,
            # so this address is for seed+passphrase, NOT the empty-passphrase funding wallet. Unlike
            # the SLIP-39 tools this used to apply it silently — a stray env/file value would record a
            # WRONG recovery anchor. The passphrase VALUE is never printed.
            src = "BIP39_PASSPHRASE env" if os.environ.get("BIP39_PASSPHRASE") else "--bip39-passphrase-file"
            sys.stderr.write("WARNING: a non-empty BIP39 (25th-word) passphrase from %s is being "
                             "applied. This address is for seed+passphrase, NOT the empty-passphrase "
                             "wallet. For a set-once custodial anchor the passphrase must be empty; "
                             "unset it and re-derive if this was unintended.\n" % src)
        try:
            addr = address_from_mnemonic(mnemonic, a.hrp, a.hd_path, passphrase, a.evm)
        except ValueError as e:
            # Clean exit, not a traceback — the message never contains the secret mnemonic.
            sys.exit("error: %s" % e)
        print(addr)
        return
    if a.der:
        with open(a.der, "rb") as f:
            point = point_from_der(f.read())
    else:
        point = bytes.fromhex(a.hex.strip())
    print(derive(point, a.hrp))

if __name__ == "__main__":
    sys.exit(main())
