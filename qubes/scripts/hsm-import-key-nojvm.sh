#!/usr/bin/env bash
# hsm-import-key-nojvm.sh — put an off-card key onto a SmartCard-HSM with no Java anywhere.
#
# WHAT IT REPLACES. The DKEK-wrapped import was the one ceremony step that still needed Smart Card
# Shell: sc-hsm-tool can UNWRAP a blob but cannot BUILD one, and the blob format lived only in
# scsh's DKEK.js. regalia#486 decided the ceremony drops scsh rather than pinning a JVM and an
# unsigned vendor zip on the machine that mints keys. The two halves now live here:
#
#     hsm-dkek-encode-key.py   builds the blob   (byte-identical to scsh; proven by KCV)
#     hsm-unwrap-key.sh        UNWRAP KEY + the PKCS#15 description
#
# SAME ARGUMENTS as hsm-import-key.sh, so a caller can switch paths without rewriting its call.
#
#   hsm-import-key-nojvm.sh --p12 funding.p12 --pw-file p12.pw --id 1 --label akash-funding \
#       --dkek dkek.pbe --dkek-pw dkek.pw --pin-file pin.txt --reader 0 [--slot 0]
#
# THE CERTIFICATE IS NOT OPTIONAL, and it needs no JVM either — hsm-import-key.sh writes it with
# `pkcs11-tool --write-object`, and so does this. Learned the hard way there: gnupg-pkcs11-scd
# enumerates the token BY CERTIFICATE and returns a plain OK with no KEYPAIRINFO for a bare key;
# `ssh-keygen -D` cannot expose one as an identity; and deleting a certificate on this card also
# removes the public key object, so the key keeps signing while vanishing from every public-key
# tool. A path that dropped the certificate would be a JVM-free regression, not a replacement.
#
# BOTH APDUS OR NEITHER. A bare UNWRAP KEY stores the key and nothing else: OpenSC's sc-hsm
# emulation enumerates private keys from their PKCS#15 description in EF C4xx, so a key imported
# without one is invisible to every PKCS#11 consumer. hsm-unwrap-key.sh writes both and checks all
# four status words; this script fails when it does.
set -uo pipefail

P12="" PW_FILE="" KEY_ID="" LABEL="" CERT=""
MODULE="${HSM_PKCS11_MODULE:-}"
DKEK_SHARE="${HSM_DKEK_SHARE_IN:-}"
DKEK_PW="${HSM_DKEK_PW_IN:-}"
PIN_FILE="${HSM_USER_PIN_FILE:-}"
SLOT="${HSM_SLOT:-}"
READER="${HSM_READER:-}"
KEY_SIZE=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --p12)      P12="$2"; shift 2;;
        --pw-file)  PW_FILE="$2"; shift 2;;
        --id)       KEY_ID="$2"; shift 2;;
        --label)    LABEL="$2"; shift 2;;
        --dkek)     DKEK_SHARE="$2"; shift 2;;
        --dkek-pw)  DKEK_PW="$2"; shift 2;;
        --pin-file) PIN_FILE="$2"; shift 2;;
        --slot)     SLOT="$2"; shift 2;;
        --reader)   READER="$2"; shift 2;;
        --key-size) KEY_SIZE="$2"; shift 2;;
        --cert)     CERT="$2"; shift 2;;
        --module)   MODULE="$2"; shift 2;;
        -h|--help)  sed -n '2,22p' "$0"; exit 0;;
        *) printf 'hsm-import-key-nojvm: unknown argument: %s\n' "$1" >&2; exit 2;;
    esac
done

err() { printf '   \033[31mFAIL\033[0m %s\n' "$1" >&2; }
ok()  { printf '   \033[32mOK\033[0m   %s\n' "$1"; }
inf() { printf '   %s\n' "$1"; }

for v in P12 PW_FILE KEY_ID LABEL CERT DKEK_SHARE DKEK_PW PIN_FILE READER; do
    [ -n "${!v}" ] || { err "missing --${v,,} (or its env equivalent)"; exit 2; }
done
for f in "$P12" "$PW_FILE" "$CERT" "$DKEK_SHARE" "$DKEK_PW" "$PIN_FILE"; do
    [ -r "$f" ] || { err "not readable: $f"; exit 2; }
done

ENCODE="$HERE/hsm-dkek-encode-key.py"
UNWRAP="$HERE/hsm-unwrap-key.sh"
[ -r "$ENCODE" ] || { err "hsm-dkek-encode-key.py missing next to this script"; exit 2; }
[ -x "$UNWRAP" ] || [ -r "$UNWRAP" ] || { err "hsm-unwrap-key.sh missing next to this script"; exit 2; }

# The pinned dependencies, resolved rather than assumed — the encoder needs `cryptography`, and an
# interpreter without it produces a traceback that reads like a key problem.
_cp="$(cd "$HERE/../.." && pwd)/tools/ceremony-python.sh"
# shellcheck source=/dev/null
[ -r "$_cp" ] && . "$_cp" && ceremony_python_require cryptography || {
    [ -r "$_cp" ] && exit 2
    printf '   (no tools/ceremony-python.sh beside this checkout; using PATH python3)\n'
}

# THE CARD IS NAMED BEFORE IT IS WRITTEN TO. hsm-unwrap-key.sh verifies a PIN and stores a key;
# doing that to the wrong card is not recoverable by apologising. When --slot names a card whose
# serial we can read, it is passed down as the expectation.
EXPECT_SERIAL=""
_rs="$(cd "$HERE/../.." && pwd)/tools/hsm-reader-select.sh"
if [ -n "$SLOT" ] && [ -r "$_rs" ]; then
    # shellcheck source=/dev/null
    . "$_rs"
    EXPECT_SERIAL="$(hsm_serial_at_slot_id "$SLOT" 2>/dev/null)" || EXPECT_SERIAL=""
    [ -n "$EXPECT_SERIAL" ] && inf "expecting card $EXPECT_SERIAL at slot $SLOT"
fi

WORK="$(mktemp -d)"
# The blob is key material under a DKEK: it is not a secret the way the private key is, but it is
# one half of one, and it does not belong in /tmp a second longer than the import takes.
cleanup(){ [ -d "$WORK" ] && { find "$WORK" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$WORK"; }; }
trap cleanup EXIT INT TERM
chmod 700 "$WORK"
BLOB="$WORK/key.blob"

inf "encoding $(basename "$P12") under the DKEK (no JVM)"
if ! python3 "$ENCODE" --p12 "$P12" --p12-pass-file "$PW_FILE" \
        --dkek-share "$DKEK_SHARE" --dkek-pw-file "$DKEK_PW" \
        --out "$BLOB" --print-kcv > "$WORK/encode.log" 2>&1; then
    err "could not build the key blob"
    sed 's/^/     /' "$WORK/encode.log" >&2
    exit 1
fi
sed -n 's/^/     /p' "$WORK/encode.log"
[ -s "$BLOB" ] || { err "the encoder reported success and wrote no blob"; exit 1; }
ok "key blob built ($(wc -c < "$BLOB" | tr -d ' ') bytes)"

# The size the PrKD declares. Read from the blob's own curve field rather than assumed: the PrKD
# is what every PKCS#11 consumer reads, and a description that disagrees with the key is the
# failure this path exists to avoid.
if [ -z "$KEY_SIZE" ]; then
    KEY_SIZE="$(sed -n 's/.*key size: *\([0-9]*\).*/\1/p' "$WORK/encode.log" | head -1)"
fi
[ -n "$KEY_SIZE" ] || KEY_SIZE=256

inf "unwrapping onto the card at reader $READER (key id $KEY_ID, label $LABEL)"
# The PIN goes in as an environment variable and hsm-unwrap-key.sh takes it off the environment
# immediately; it never appears in argv.
if ! HSM_USER_PIN="$(cat "$PIN_FILE")" bash "$UNWRAP" \
        --reader "$READER" --key-id "$KEY_ID" --key-size "$KEY_SIZE" \
        --blob "$BLOB" --label "$LABEL" ${EXPECT_SERIAL:+--expect-serial "$EXPECT_SERIAL"}; then
    err "UNWRAP KEY or the PrKD write failed — see the status words above"
    exit 1
fi
ok "key unwrapped onto the card"

# ---- the certificate, and the proof that BOTH landed -----------------------------------------
[ -n "$MODULE" ] || MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
[ -r "$MODULE" ] || { err "PKCS#11 module not readable: $MODULE (set HSM_PKCS11_MODULE or --module)"; exit 1; }
case "$CERT" in
    *.der|*.cer) cp "$CERT" "$WORK/cert.der";;
    *) openssl x509 -in "$CERT" -outform DER -out "$WORK/cert.der" 2>/dev/null \
         || { err "could not convert $CERT to DER"; exit 1; };;
esac
SLOT_ARGS=()
[ -n "$SLOT" ] && SLOT_ARGS=(--slot "$SLOT")
PIN="$(cat "$PIN_FILE")"
if ! pkcs11-tool --module "$MODULE" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} --login --pin "$PIN" \
        --write-object "$WORK/cert.der" --type cert --id "$KEY_ID" --label "$LABEL" \
        > "$WORK/cert.log" 2>&1; then
    err "certificate write failed — the key is on the card but INVISIBLE to gpg and ssh"
    grep -iE "CKR_|error" "$WORK/cert.log" | head -3 >&2
    exit 1
fi
ok "certificate written"

# REPORTING SUCCESS WITHOUT CHECKING is how a key ends up on a card nothing can find.
objs="$(pkcs11-tool --module "$MODULE" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} --login --pin "$PIN" --list-objects 2>/dev/null)"
grep -q "Private Key Object" <<< "$objs" || { err "no private key enumerates after the unwrap"; exit 1; }
grep -q "Certificate Object" <<< "$objs" || { err "no certificate enumerates"; exit 1; }
ok "verified: key and certificate both present"
inf "keys on card: $(printf '%s' "$objs" | grep -c 'Private Key Object')"
inf "certs on card: $(printf '%s' "$objs" | grep -c 'Certificate Object')"
ok "IMPORT-OK"
