#!/usr/bin/env python3
"""seed-to-pkcs12.py — derive the funding key from a BIP39 seed and package it as the PKCS#12
container the SmartCard-HSM import path consumes.

  seed-to-pkcs12.py --mnemonic-file funding.mnemonic --out funding.p12 --password-file p12.pw
  seed-to-pkcs12.py --selftest

WHY THIS EXISTS: a key generated INSIDE the HSM is recoverable only from its DKEK blob, restored
onto a compatible SmartCard-HSM. The custody model requires every secret to be reconstructible
from the 4-of-6 Shamir shares alone. So the key is derived FROM THE SEED and imported into the
device: the seed on metal stays authoritative, the HSM protects the key in operation, and losing
every device costs an import rather than the funds.

Nitrokey documents the import path as PKCS#12 + DKEK via Smart Card Shell
(docs.nitrokey.com/nitrokeys/features/hsm/import-keys-certs). OpenSC cannot do it —
sc_hsm_store_key() is a stub returning SC_ERROR_NOT_SUPPORTED and pkcs15-init is explicitly
unsupported on this card — so this tool stops at the container and the operator drives scsh.

THE FAILURE THIS GUARDS: an imported key whose address differs from the seed's derivation. Fund
that address and the money is controlled by a key nobody can reconstruct. So the derived address
is computed here, printed, and MUST be compared to what the card reports after import. The
address is public; the private key is written only into the PKCS#12 and never printed.

SECRETS OFF ARGV: the mnemonic and the PKCS#12 password are read from files, never the command
line — argv is visible in ps, /proc/<pid>/cmdline and shell history.
"""
import argparse
import importlib.machinery
import importlib.util
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_deriver():
    """Reuse derive-akash-address.py's audited BIP39/BIP32/secp256k1 math rather than
    reimplementing it. A second implementation of key derivation is a second chance to derive
    the WRONG key, and this one has tests and a ceremony behind it."""
    path = os.environ.get("CEREMONY_DERIVER") or os.path.join(HERE, "derive-akash-address.py")
    if not os.path.exists(path):
        sys.exit("seed-to-pkcs12: cannot find derive-akash-address.py (set CEREMONY_DERIVER)")
    ldr = importlib.machinery.SourceFileLoader("_deriver", path)
    spec = importlib.util.spec_from_loader("_deriver", ldr)
    mod = importlib.util.module_from_spec(spec)
    ldr.exec_module(mod)
    return mod


def derive_privkey(mnemonic, hd_path=None, passphrase=""):
    """Return (privkey_int, akash_address) for the BIP39 mnemonic at the cosmos HD path."""
    d = _load_deriver()
    hd_path = hd_path or d.DEFAULT_HD_PATH
    d._validate_bip39(mnemonic)
    k, chain = d._bip32_master(d._bip39_seed(mnemonic, passphrase))
    for index in d._parse_hd_path(hd_path):
        k, chain = d._ckd_priv(k, chain, index)
    if not (0 < k < d.SECP256K1_N):
        sys.exit("seed-to-pkcs12: derived scalar out of range — refusing to build a container")
    return k, d.derive(d._pubkey_compressed(k), "akash")


def _sec1_der(priv_int):
    """RFC 5915 SEC1 EC PRIVATE KEY DER for secp256k1. Built by hand so no third-party crypto
    library sits in the path between the seed and the container."""
    priv = priv_int.to_bytes(32, "big")
    d = _load_deriver()
    pub = d._pubkey_compressed(priv_int)
    # decompress for the optional publicKey BIT STRING: openssl accepts compressed, but the
    # uncompressed point is what every tool round-trips cleanly.
    x, y = d._scalar_mult(priv_int, (d.SECP256K1_GX, d.SECP256K1_GY))
    pub_unc = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    assert len(pub) == 33

    def tlv(tag, val):
        if len(val) < 0x80:
            return bytes([tag, len(val)]) + val
        n = (len(val).bit_length() + 7) // 8
        return bytes([tag, 0x80 | n]) + len(val).to_bytes(n, "big") + val

    version = tlv(0x02, b"\x01")
    privkey = tlv(0x04, priv)
    curve_oid = bytes.fromhex("06052b8104000a")                  # secp256k1
    params = tlv(0xA0, curve_oid)
    pubbits = tlv(0xA1, tlv(0x03, b"\x00" + pub_unc))
    return tlv(0x30, version + privkey + params + pubbits)


def build_p12(mnemonic, out_path, password, hd_path=None, passphrase="", quiet=False):
    if not shutil.which("openssl"):
        sys.exit("seed-to-pkcs12: openssl not found — required to build the PKCS#12 container")
    priv_int, address = derive_privkey(mnemonic, hd_path, passphrase)

    tmp = tempfile.mkdtemp()
    try:
        os.chmod(tmp, 0o700)
        key_der = os.path.join(tmp, "k.der")
        key_pem = os.path.join(tmp, "k.pem")
        crt_pem = os.path.join(tmp, "c.pem")
        with open(os.open(key_der, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as fh:
            fh.write(_sec1_der(priv_int))
        # DER -> PEM, then a self-signed cert. PKCS#12 is a key+cert container: the cert is
        # structural packaging, not a trust statement, so it is self-signed with a neutral
        # subject and never leaves the workdir.
        for cmd in (
            ["openssl", "ec", "-inform", "DER", "-in", key_der, "-out", key_pem],
            ["openssl", "req", "-new", "-x509", "-key", key_pem, "-out", crt_pem,
             "-days", "3650", "-subj", "/CN=akash-funding"],
        ):
            r = subprocess.run(cmd, capture_output=True)
            if r.returncode != 0:
                sys.exit("seed-to-pkcs12: %s failed: %s" % (cmd[1], r.stderr.decode()[:200]))
        # Password reaches openssl over STDIN — never argv, never the filesystem.
        #
        # The three ways to hand openssl a password are all worse than this one:
        #   -passout pass:<pw>   puts it on argv, readable via ps / /proc/<pid>/cmdline
        #   -passout env:VAR     puts it in the environment, readable via /proc/<pid>/environ
        #   -passout file:<path> writes it to disk, even if only briefly and at 0600
        # `stdin` is a pipe that exists only for the life of the call, so the secret is never
        # observable by another process and never lands on a filesystem that might be a
        # non-tmpfs fallback. This also removes the clear-text-storage finding at the source
        # rather than arguing about it.
        r = subprocess.run(["openssl", "pkcs12", "-export", "-inkey", key_pem, "-in", crt_pem,
                            "-out", out_path, "-name", "akash-funding",
                            "-passout", "stdin"],
                           input=password.encode(), capture_output=True)
        if r.returncode != 0:
            sys.exit("seed-to-pkcs12: pkcs12 export failed: %s" % r.stderr.decode()[:200])
        os.chmod(out_path, 0o600)
    finally:
        # The temp tree held the raw private key in three encodings. Remove it before returning
        # on EVERY path, including the failure paths above.
        shutil.rmtree(tmp, ignore_errors=True)

    if not os.path.getsize(out_path):
        sys.exit("seed-to-pkcs12: produced an EMPTY container — do not proceed")

    if not quiet:
        print("  PKCS#12 written: %s" % out_path)
        print("  derived funding address: %s" % address)
        print("  AFTER IMPORT the card MUST report this exact address. If it differs, the")
        print("  imported key is NOT the seed's key — do NOT fund it.")
    return address


def selftest():
    """Prove the container really carries the seed-derived key: build it, read the key back out
    with openssl, and require the public point to match the derivation. A container that holds a
    DIFFERENT key would import cleanly and produce an unspendable address."""
    mnemonic = ("abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon about")
    tmp = tempfile.mkdtemp()
    try:
        p12 = os.path.join(tmp, "t.p12")
        pw = secrets.token_hex(8)
        addr = build_p12(mnemonic, p12, pw, quiet=True)
        # Read back over stdin too — same reasoning as the export path: no password on argv,
        # in the environment, or on disk.
        r = subprocess.run(["openssl", "pkcs12", "-in", p12, "-nocerts", "-nodes",
                            "-passin", "stdin"], input=pw.encode(), capture_output=True)
        assert r.returncode == 0, "could not read the container back: %s" % r.stderr.decode()[:200]
        r2 = subprocess.run(["openssl", "ec", "-pubout"], input=r.stdout, capture_output=True)
        assert r2.returncode == 0, "could not extract the public key"
        d = _load_deriver()
        priv_int, _ = derive_privkey(mnemonic)
        expect = d._pubkey_compressed(priv_int).hex()
        r3 = subprocess.run(["openssl", "ec", "-pubin", "-conv_form", "compressed", "-outform",
                             "DER"], input=r2.stdout, capture_output=True)
        assert expect in r3.stdout.hex(), "container public key != derived public key"
        # the well-known test vector for this mnemonic on m/44'/118'/0'/0/0
        assert addr.startswith("akash1"), "unexpected address form: %s" % addr
        print("seed-to-pkcs12 selftest: OK (container round-trips to the derived key; %s)" % addr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _read(path, what):
    if not path or not os.path.exists(path):
        sys.exit("seed-to-pkcs12: %s file is required and must exist (never pass it on argv)" % what)
    with open(path) as fh:
        val = fh.read().strip()
    if not val:
        sys.exit("seed-to-pkcs12: %s file is empty" % what)
    return val


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mnemonic-file")
    ap.add_argument("--password-file", help="PKCS#12 container password (off argv)")
    ap.add_argument("--out", default="funding.p12")
    ap.add_argument("--hd-path", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    os.umask(0o077)
    if a.selftest:
        selftest()
        return
    mnemonic = _read(a.mnemonic_file, "mnemonic")
    password = _read(a.password_file, "PKCS#12 password")
    build_p12(mnemonic, a.out, password, a.hd_path)


if __name__ == "__main__":
    main()
