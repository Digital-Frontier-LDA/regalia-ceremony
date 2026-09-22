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
#       --dkek dkek.pbe --dkek-pw dkek.pw --pin-file pin.txt --reader 0 [--slot 0] [--cert c.pem]
#
# A REAL CEREMONY HAS NO TYPED DKEK PASSWORD. `--create-dkek-share --pwd-shares-threshold/-total`
# generates one, splits it, and prints only the shares. Pass the share file instead and the
# password is reconstructed from any threshold-sized quorum:
#
#       --dkek-shares dkek-shares.txt [--dkek-shares-use 2,4,5,6]
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
DKEK_SHARES="${HSM_DKEK_SHARES_IN:-}"
DKEK_SHARES_USE="${HSM_DKEK_SHARES_USE:-}"
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
        # A REAL CEREMONY HAS NO TYPED DKEK PASSWORD. `--create-dkek-share
        # --pwd-shares-threshold/-total` generates 8 random bytes, splits them, and prints only
        # the shares; the password itself is never written down. Without this the JVM-free path
        # could serve only the drill's single-password shortcut, which is not how a ceremony runs.
        --dkek-shares)     DKEK_SHARES="$2"; shift 2;;
        --dkek-shares-use) DKEK_SHARES_USE="$2"; shift 2;;
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

for v in P12 PW_FILE KEY_ID LABEL DKEK_SHARE PIN_FILE READER; do
    [ -n "${!v}" ] || { err "missing --${v,,} (or its env equivalent)"; exit 2; }
done
if [ -n "$DKEK_PW" ] && [ -n "$DKEK_SHARES" ]; then
    err "give --dkek-pw OR --dkek-shares, not both — a share file's password is reconstructed, never also typed"
    exit 2
fi
[ -n "$DKEK_PW" ] || [ -n "$DKEK_SHARES" ] || { err "missing --dkek-pw or --dkek-shares"; exit 2; }
for f in "$P12" "$PW_FILE" ${CERT:+"$CERT"} "$DKEK_SHARE" "${DKEK_PW:-$DKEK_SHARES}" "$PIN_FILE"; do
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

# --reader AND --slot MUST BE THE SAME PHYSICAL CARD. They are different addressing schemes:
# --reader is a PC/SC index, used for the APDUs that store the key; --slot is a PKCS#11 slot id,
# used for the certificate write and the enumeration proof. Nothing makes them agree. On this
# bench they do not even have the same values — installing vsmartcard-vpcd put two Virtual PCD
# readers in front of the real ones, so DENK0404144 is PC/SC 2 and PKCS#11 slot id 8.
#
# Getting them crossed would unwrap a key onto one card and then "verify" it on another, reporting
# success for an import that landed somewhere nobody looked. So when both are given and the serials
# are readable, they are compared, and a disagreement is a refusal before anything is written.
#
# (An earlier version passed --expect-serial down to hsm-unwrap-key.sh, which has no such option;
# the call simply failed. It only surfaced once the resolver started working on Linux at all —
# tools/hsm-reader-select.sh defaulted to a macOS module path, so this branch had never run here.)
EXPECT_SERIAL=""
_rs="$(cd "$HERE/../.." && pwd)/tools/hsm-reader-select.sh"
if [ -n "$SLOT" ] && [ -r "$_rs" ]; then
    # shellcheck source=/dev/null
    . "$_rs"
    EXPECT_SERIAL="$(hsm_serial_at_slot_id "$SLOT" 2>/dev/null)" || EXPECT_SERIAL=""
    if [ -n "$EXPECT_SERIAL" ]; then
        inf "slot $SLOT is card $EXPECT_SERIAL"
        _reader_serial="$(hsm_serial_at_reader "$READER" 2>/dev/null)" || _reader_serial=""
        if [ -n "$_reader_serial" ] && [ "$_reader_serial" != "$EXPECT_SERIAL" ]; then
            err "reader $READER is card $_reader_serial but slot $SLOT is card $EXPECT_SERIAL"
            printf '   The key would be unwrapped onto one card and verified on another, and this\n' >&2
            printf '   would report success for an import nobody looked at. Refusing.\n' >&2
            exit 2
        fi
        [ -n "$_reader_serial" ] && inf "reader $READER is the same card — writing to $EXPECT_SERIAL"
    fi
fi

WORK="$(mktemp -d)"
# The blob is key material under a DKEK: it is not a secret the way the private key is, but it is
# one half of one, and it does not belong in /tmp a second longer than the import takes.
cleanup(){ [ -d "$WORK" ] && { find "$WORK" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$WORK"; }; }
trap cleanup EXIT INT TERM
chmod 700 "$WORK"
BLOB="$WORK/key.blob"

inf "encoding $(basename "$P12") under the DKEK (no JVM)"
DKEK_ARGS=()
if [ -n "$DKEK_SHARES" ]; then
    DKEK_ARGS=(--dkek-shares-file "$DKEK_SHARES")
    [ -n "$DKEK_SHARES_USE" ] && DKEK_ARGS+=(--dkek-shares-use "$DKEK_SHARES_USE")
else
    DKEK_ARGS=(--dkek-pw-file "$DKEK_PW")
fi
if ! python3 "$ENCODE" --p12 "$P12" --p12-pass-file "$PW_FILE" \
        --dkek-share "$DKEK_SHARE" "${DKEK_ARGS[@]}" \
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
        --blob "$BLOB" --label "$LABEL"; then
    err "UNWRAP KEY or the PrKD write failed — see the status words above"
    exit 1
fi
ok "key unwrapped onto the card"

# ---- the certificate, and the proof that BOTH landed -----------------------------------------
[ -n "$MODULE" ] || MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
[ -r "$MODULE" ] || { err "PKCS#11 module not readable: $MODULE (set HSM_PKCS11_MODULE or --module)"; exit 1; }
# THE CERTIFICATE IS ALREADY IN THE PKCS#12. A key container is a key AND a certificate, so
# demanding a separate --cert file adds a way for the caller to pass a certificate belonging to a
# different key — and a way for a caller that has only the container to fail for no reason. When
# --cert is omitted it is lifted from the same container the key came from, which is the one
# certificate guaranteed to match.
if [ -z "$CERT" ]; then
    if ! openssl pkcs12 -in "$P12" -clcerts -nokeys -passin "file:$PW_FILE" \
            -out "$WORK/cert.pem" 2>"$WORK/cert-extract.log"; then
        err "no --cert given and the certificate could not be read out of $(basename "$P12")"
        sed 's/^/     /' "$WORK/cert-extract.log" >&2
        exit 1
    fi
    [ -s "$WORK/cert.pem" ] || { err "the PKCS#12 carries no certificate; pass --cert"; exit 1; }
    openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der" 2>/dev/null \
      || { err "the certificate in $(basename "$P12") is not readable as X.509"; exit 1; }
else
    case "$CERT" in
        *.der|*.cer) cp "$CERT" "$WORK/cert.der";;
        *) openssl x509 -in "$CERT" -outform DER -out "$WORK/cert.der" 2>/dev/null \
             || { err "could not convert $CERT to DER"; exit 1; };;
    esac
fi
# THE SAME NUMBER IN TWO BASES IS TWO NUMBERS. --key-id here is a SmartCard-HSM key reference, a
# DECIMAL 1..255, and that is what UNWRAP KEY and the EF C4xx file name use. `pkcs11-tool --id`
# takes HEX. Passing "$KEY_ID" to both meant every id that is not the same in both bases produced
# a key and a certificate with DIFFERENT CKA_IDs — measured on ESP41D722E2 with --id 31:
#
#     Private Key Object   ID: 1f      (decimal 31 -> key reference 0x1F)
#     Certificate Object   ID: 31      (pkcs11-tool read "31" as hex)
#
# Two consequences, and the second is worse. A certificate that does not share its id with the key
# is not associated with it, which is the whole reason the certificate is written. And an UNPAIRED
# certificate is exactly what the KMS identity probe treats as a DEVICE certificate
# (regalia-kms#17), so this would have handed the daemon a key's certificate as a device identity.
#
# Every earlier import used 1, 2, 3 or 5 — the same in both bases — so nothing showed it.
CERT_ID="$(printf '%02x' "$KEY_ID")"
SLOT_ARGS=()
[ -n "$SLOT" ] && SLOT_ARGS=(--slot "$SLOT")
PIN="$(cat "$PIN_FILE")"
if ! pkcs11-tool --module "$MODULE" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} --login --pin "$PIN" \
        --write-object "$WORK/cert.der" --type cert --id "$CERT_ID" --label "$LABEL" \
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
# AND THEY MUST SHARE AN ID. Present-but-unpaired is the state the base confusion above produced,
# and it looks identical to success in a plain object listing.
_ids="$(grep -oiE '^[[:space:]]*ID:[[:space:]]*[0-9a-f]+' <<< "$objs" | grep -oiE '[0-9a-f]+$' | tr 'A-F' 'a-f' | sort -u)"
if [ "$(wc -l <<< "$_ids")" -ne 1 ]; then
    err "the key and its certificate did not land on one id: $(tr '\n' ' ' <<< "$_ids")"
    err "a certificate that does not share the key's CKA_ID is not associated with it, and reads"
    err "to a device-identity probe as an unpaired certificate."
    exit 1
fi
ok "verified: key and certificate both present, sharing id $_ids"
inf "keys on card: $(printf '%s' "$objs" | grep -c 'Private Key Object')"
inf "certs on card: $(printf '%s' "$objs" | grep -c 'Certificate Object')"
ok "IMPORT-OK"
