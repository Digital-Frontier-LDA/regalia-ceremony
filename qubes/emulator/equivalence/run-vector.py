#!/usr/bin/env python3
"""run-vector.py — the cross-profile ceremony equivalence vector (#36).

TEST VECTOR, NEVER CUSTODY MATERIAL. Every input in vector.json is public: the BIP39 mnemonic is the
published all-zero-entropy test vector, and the shares, the age identity and the ciphertext were
made from it and from fixed strings for this file alone. Nothing here may ever hold, protect or
recover a real value, and nothing derived here may ever be funded.

A portable ceremony is only one ceremony if every supported profile computes the same things. This
runs ONE profile's installed ceremony tools (the salt-provisioned vault-tools image, or the
offline Debian bundle) against those fixed inputs and writes a single JSON document:

  deterministic  outputs that must be identical in every profile: addresses, recovered mnemonics,
                 reconstructed secrets, the age recipient, the QR matrix
  semantic       checks of operations that are randomized by design (a fresh ssss split, a fresh
                 SLIP-39 split, an age encryption, a PKCS#12 container), each true or false
  transcript     tool versions and environment facts. Recorded for the evidence trail, never
                 compared: two profiles may legitimately carry different builds of one tool, and
                 what matters is whether an output moved

compare-vector.py compares deterministic and semantic against expected.json and names every field
that differs. Each profile is compared with the same expected.json, from the same checkout, so a
profile that passes computes exactly what every other passing profile computes.

A failure to run a tool is recorded as that field's value ("ERROR: ..."), never raised: the
comparison should name the field that broke, not stop at the first one.

    run-vector.py --scripts /opt/vault-ceremony --profile salt-vault-tools --out result.json
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKOUT_SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "..", "scripts"))
# The ceremony scripts this vector executes. Each installed copy is also compared with the
# checkout's, so a profile running a stale or edited script fails as a semantic check.
USED_SCRIPTS = ("derive-akash-address.py", "bip39-slip39-backup.py", "seed-to-pkcs12.py")
PERTURBING_ENV = ("BIP39_PASSPHRASE", "SLIP39_PASSPHRASE")


def sha256(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def run(argv, stdin=None, env=None):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=120,
                          env=env if env is not None else os.environ.copy())


def error(proc):
    lines = (proc.stderr or proc.stdout or "").strip().splitlines()
    return "ERROR: exit %d: %s" % (proc.returncode, lines[-1] if lines else "no output")


# ---- bech32 (BIP-173), only to spell the fixed age test identity without committing one -------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_encode(hrp, payload):
    data, acc, bits = [], 0, 0
    for byte in payload:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    polymod = _polymod(values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def age_test_identity(seed_label):
    # The identity is derived from a public label at run time. Its bytes are as public as the
    # label; the point is only that no secret-key-shaped string sits in the repository.
    return bech32_encode("age-secret-key-", hashlib.sha256(seed_label.encode()).digest()).upper()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scripts", required=True, help="the profile's installed ceremony scripts, e.g. /opt/vault-ceremony")
    ap.add_argument("--profile", required=True, help="a label for the transcript, e.g. salt-vault-tools")
    ap.add_argument("--vector", default=os.path.join(HERE, "vector.json"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    vector = json.load(open(a.vector))
    scripts = a.scripts
    work = tempfile.mkdtemp(prefix="equivalence-")
    os.chmod(work, 0o700)
    deterministic, semantic, transcript = {}, {}, {}

    def path(name):
        return os.path.join(work, name)

    def write(name, text, mode="w"):
        with open(path(name), mode) as fh:
            fh.write(text)
        return path(name)

    def script(name):
        return [sys.executable, os.path.join(scripts, name)]

    def derive_from_mnemonic_file(mnemonic_path):
        proc = run(script("derive-akash-address.py") + ["--mnemonic-file", mnemonic_path])
        return proc.stdout.strip() if proc.returncode == 0 else error(proc)

    try:
        # ---- code: the profile runs the checkout's scripts -----------------------------------
        for name in USED_SCRIPTS:
            installed, checked_out = os.path.join(scripts, name), os.path.join(CHECKOUT_SCRIPTS, name)
            semantic["code.%s.installed_matches_checkout" % name] = (
                os.path.isfile(installed) and os.path.isfile(checked_out)
                and sha256(open(installed, "rb").read()) == sha256(open(checked_out, "rb").read()))

        # ---- BIP39 -> akash address ---------------------------------------------------------
        mnemonic_path = write("vector.mnemonic", vector["bip39_mnemonic"] + "\n")
        deterministic["bip39.akash_address"] = derive_from_mnemonic_file(mnemonic_path)

        # ---- HSM public key (SPKI DER) -> akash address ---------------------------------------
        der_path = write("vector.der", bytes.fromhex(vector["secp256k1_spki_der_hex"]), "wb")
        proc = run(script("derive-akash-address.py") + ["--der", der_path])
        deterministic["spki.akash_address"] = proc.stdout.strip() if proc.returncode == 0 else error(proc)

        # ---- SLIP-39: fixed shares recover the vector mnemonic; a fresh split round-trips -----
        shares = vector["slip39_shares"]

        def slip39_recover(indices):
            share_path = write("slip39-%s.txt" % "".join(map(str, indices)),
                               "".join(shares[i - 1] + "\n" for i in indices))
            return run(script("bip39-slip39-backup.py") + ["--recover", "--in", share_path])

        for subset in ((1, 2, 3, 4), (3, 4, 5, 6)):
            label = "".join(map(str, subset))
            proc = slip39_recover(subset)
            recovered = proc.stdout.strip() if proc.returncode == 0 else None
            deterministic["slip39.recover_%s.mnemonic_sha256" % label] = sha256(recovered) if recovered else error(proc)
            if subset == (1, 2, 3, 4):
                deterministic["slip39.recover_1234.akash_address"] = (
                    derive_from_mnemonic_file(write("recovered.mnemonic", recovered + "\n")) if recovered else error(proc))
        semantic["slip39.three_shares_are_refused"] = slip39_recover((1, 2, 3)).returncode != 0
        split = run(script("bip39-slip39-backup.py") + ["--in", mnemonic_path, "--threshold", "4", "--shares", "6"])
        fresh = [line.strip() for line in split.stdout.splitlines() if line.strip() and not line.startswith("#")]
        roundtrip = False
        if split.returncode == 0 and len(fresh) == 6:
            proc = run(script("bip39-slip39-backup.py") + ["--recover", "--in", write("fresh-slip39.txt", "\n".join(fresh[2:]) + "\n")])
            roundtrip = proc.returncode == 0 and proc.stdout.strip() == vector["bip39_mnemonic"]
        semantic["slip39.fresh_split_recovers_from_shares_3_to_6"] = roundtrip

        # ---- ssss: fixed shares reconstruct the fixed secret; a fresh split round-trips -------
        ssss_shares, ssss_secret = vector["ssss_shares"], vector["ssss_secret"]

        def ssss_combine(indices, threshold):
            proc = run(["ssss-combine", "-t", str(threshold), "-q"],
                       stdin="".join(ssss_shares[i - 1] + "\n" for i in indices))
            text = (proc.stderr + proc.stdout).strip().splitlines()
            return proc, (text[-1] if text else "")

        for subset in ((1, 2, 3, 4), (3, 4, 5, 6)):
            proc, secret = ssss_combine(subset, 4)
            deterministic["ssss.combine_%s.recovered_sha256" % "".join(map(str, subset))] = (
                sha256(secret) if proc.returncode == 0 else error(proc))
        semantic["ssss.three_shares_do_not_recover"] = ssss_combine((1, 2, 3), 3)[1] != ssss_secret
        proc = run(["ssss-split", "-t", "4", "-n", "6", "-q"], stdin=ssss_secret + "\n")
        fresh = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        ok = False
        if proc.returncode == 0 and len(fresh) == 6:
            combined = run(["ssss-combine", "-t", "4", "-q"], stdin="\n".join(fresh[2:]) + "\n")
            lines = (combined.stderr + combined.stdout).strip().splitlines()
            ok = combined.returncode == 0 and bool(lines) and lines[-1] == ssss_secret
        semantic["ssss.fresh_split_recovers_from_shares_3_to_6"] = ok

        # ---- age: the fixed identity's recipient and pinned ciphertext; a fresh round trip ---
        identity_path = write("age-identity.txt", age_test_identity(vector["age_identity_label"]) + "\n")
        os.chmod(identity_path, 0o600)
        proc = run(["age-keygen", "-y", identity_path])
        deterministic["age.recipient"] = proc.stdout.strip() if proc.returncode == 0 else error(proc)
        proc = run(["age", "-d", "-i", identity_path, write("pinned.age", vector["age_ciphertext_armored"])])
        deterministic["age.pinned_ciphertext.plaintext_sha256"] = sha256(proc.stdout) if proc.returncode == 0 else error(proc)
        plaintext = "regalia equivalence round trip"
        ok = False
        if deterministic["age.recipient"].startswith("age1"):
            enc = run(["age", "-r", deterministic["age.recipient"], "-o", path("fresh.age")], stdin=plaintext)
            dec = run(["age", "-d", "-i", identity_path, path("fresh.age")]) if enc.returncode == 0 else enc
            ok = dec.returncode == 0 and dec.stdout == plaintext
        semantic["age.fresh_encryption_decrypts"] = ok

        # ---- QR: the matrix at error-correction level H; the PNG decodes back -----------------
        payload = vector["qr_payload"]
        proc = run(["qrencode", "-t", "ASCII", "-l", "H", "-m", "4", "-o", "-", payload])
        deterministic["qr.ascii_level_h_sha256"] = sha256(proc.stdout) if proc.returncode == 0 else error(proc)
        proc = run(["qrencode", "-l", "H", "-s", "6", "-m", "4", "-o", path("qr.png"), payload])
        decoded = run(["zbarimg", "--raw", "-q", path("qr.png")]) if proc.returncode == 0 else proc
        semantic["qr.png_decodes_to_payload"] = decoded.returncode == 0 and decoded.stdout.strip() == payload

        # ---- PKCS#12: the container the HSM import consumes holds the seed's key --------------
        password_path = write("p12.pw", "equivalence-test-vector-only\n")
        os.chmod(password_path, 0o600)
        proc = run(script("seed-to-pkcs12.py") + ["--mnemonic-file", mnemonic_path, "--password-file", password_path,
                                                  "--out", path("vector.p12")])
        if proc.returncode != 0:
            deterministic["pkcs12.akash_address"] = error(proc)
        else:
            key = run(["openssl", "pkcs12", "-in", path("vector.p12"), "-nocerts", "-nodes", "-passin", "file:" + password_path])
            if key.returncode != 0:
                deterministic["pkcs12.akash_address"] = error(key)
            else:
                pub = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=key.stdout.encode(),
                                     capture_output=True, timeout=60)
                if pub.returncode != 0:
                    deterministic["pkcs12.akash_address"] = "ERROR: openssl pkey exit %d" % pub.returncode
                else:
                    with open(path("p12-pub.der"), "wb") as fh:
                        fh.write(pub.stdout)
                    derived = run(script("derive-akash-address.py") + ["--der", path("p12-pub.der")])
                    deterministic["pkcs12.akash_address"] = derived.stdout.strip() if derived.returncode == 0 else error(derived)

        # ---- transcript (never compared) -----------------------------------------------------
        def version(argv):
            if not shutil.which(argv[0]):
                return "absent"
            proc = run(argv)
            lines = (proc.stdout + proc.stderr).strip().splitlines()
            return lines[0] if lines else "no output (exit %d)" % proc.returncode

        transcript["profile"] = a.profile
        transcript["python"] = sys.version.split()[0]
        transcript["age"] = version(["age", "--version"])
        transcript["qrencode"] = version(["qrencode", "-V"])
        transcript["openssl"] = version(["openssl", "version"])
        transcript["zbarimg"] = version(["zbarimg", "--version"])
        transcript["sops"] = version(["sops", "--version"])
        for dist in ("mnemonic", "shamir-mnemonic", "click"):
            try:
                transcript["pip." + dist] = importlib.metadata.version(dist)
            except importlib.metadata.PackageNotFoundError:
                transcript["pip." + dist] = "absent"
        transcript["perturbing_env_set"] = sorted(name for name in PERTURBING_ENV if name in os.environ)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    with open(a.out, "w") as fh:
        json.dump({"deterministic": deterministic, "semantic": semantic, "transcript": transcript}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("wrote %s: %d deterministic, %d semantic fields (profile %s)" % (a.out, len(deterministic), len(semantic), a.profile))


if __name__ == "__main__":
    main()
