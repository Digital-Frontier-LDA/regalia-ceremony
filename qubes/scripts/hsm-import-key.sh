#!/usr/bin/env bash
# hsm-import-key.sh — import ANY key into the HSM, with its certificate.
#
#   hsm-import-key.sh --p12 rsa.p12 --pw-file p12.pw --id 32 --label rsa-signing --cert rsa.crt
#
# WHY THIS EXISTS. hsm-auto-import.sh imports exactly one thing: the wallet key, derived from a
# hardcoded BIP39 vector. That is correct for the funding ceremony and useless for everything
# else. A KMS holds an RSA key for GPG/SOPS/CA, a P-256 key for SSH, and a secp256k1 key for the
# wallet — so the import path has to take an arbitrary PKCS#12 rather than build one from a seed.
#
# THE CERTIFICATE IS NOT OPTIONAL. This was learned the hard way:
#   - gnupg-pkcs11-scd enumerates the token BY CERTIFICATE. A bare private key is invisible to
#     it — SCD LEARN returns a plain OK with no KEYPAIRINFO and no error at all.
#   - ssh-keygen -D likewise cannot expose a key as an SSH identity without one.
#   - Deleting a certificate on this card ALSO removes the public key object, so the key keeps
#     signing while silently disappearing from every public-key tool.
# So a key imported without its certificate is a key that most of the stack cannot see. This
# script always writes both, and verifies both landed.
#
# ALWAYS IMPORT, NEVER GENERATE ON-CARD. A key generated on the token is non-exportable by
# construction: it cannot be backed up, and N devices would hold N DIFFERENT keys rather than one
# key replicated. Everything here assumes the key was generated elsewhere, is backed up
# elsewhere, and is being placed onto the card.
set -uo pipefail

P12="" PW_FILE="" KEY_ID="" LABEL="" CERT=""
MODULE="${HSM_PKCS11_MODULE:-}"
DKEK_SHARE="${HSM_DKEK_SHARE_IN:-}"
DKEK_PW="${HSM_DKEK_PW_IN:-}"
PIN_FILE="${HSM_USER_PIN_FILE:-}"
SLOT="${HSM_SLOT:-}"
READER="${HSM_READER:-}"
# THE DEFAULT POINTED AT THE WRONG DIRECTORY. The tarball unpacks as scsh-3.18.77/scsh-3.18.77/,
# and scriptrunner is in the INNER one — so this default produced `./scriptrunner: No such file or
# directory` from inside a `cd`, on stderr, while the drill reported only "key import failed:" with
# an empty reason. Measured 2026-09-21 mid-drill. Accept either layout, and REFUSE with the reason
# named when neither has it: a missing interpreter is not an import failure, and reporting it as
# one sends whoever reads the transcript looking at the card.
SCSH="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}"
[ -x "$SCSH/scriptrunner" ] || [ ! -x "$SCSH/scsh-3.18.77/scriptrunner" ] || SCSH="$SCSH/scsh-3.18.77"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --p12)      P12="$2"; shift 2;;
        --pw-file)  PW_FILE="$2"; shift 2;;
        --id)       KEY_ID="$2"; shift 2;;
        --label)    LABEL="$2"; shift 2;;
        --cert)     CERT="$2"; shift 2;;
        --module)   MODULE="$2"; shift 2;;
        --dkek)     DKEK_SHARE="$2"; shift 2;;
        --dkek-pw)  DKEK_PW="$2"; shift 2;;
        --pin-file) PIN_FILE="$2"; shift 2;;
        --slot)     SLOT="$2"; shift 2;;
        --reader)   READER="$2"; shift 2;;
        -h|--help)  sed -n '2,30p' "$0"; exit 0;;
        *) echo "unknown argument: $1" >&2; exit 2;;
    esac
done

err() { printf '   \033[31mFAIL\033[0m %s\n' "$1" >&2; }
ok()  { printf '   \033[32mOK\033[0m   %s\n' "$1"; }
inf() { printf '   %s\n' "$1"; }

for v in P12 PW_FILE KEY_ID LABEL CERT DKEK_SHARE DKEK_PW PIN_FILE; do
    [ -n "${!v}" ] || { err "missing --${v,,} (or its env equivalent)"; exit 2; }
done
[ -r "$P12" ] || { err "PKCS#12 not readable: $P12"; exit 2; }
[ -r "$CERT" ] || { err "certificate not readable: $CERT"; exit 2; }

# The module path must be absolute. A bare "opensc-pkcs11.so" resolves on some Linux distros and
# NEVER on macOS, where it fails with a dlopen error that reads like a missing card.
if [ -z "$MODULE" ]; then
    for c in /opt/homebrew/lib/opensc-pkcs11.so /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
             /usr/lib64/opensc-pkcs11.so /usr/local/lib/opensc-pkcs11.so; do
        [ -e "$c" ] && { MODULE="$c"; break; }
    done
fi
[ -n "$MODULE" ] && [ -e "$MODULE" ] || { err "PKCS#11 module not found; pass --module"; exit 2; }
inf "module: $MODULE"

# ---- WHICH CARD? ------------------------------------------------------------------------------
# This script writes a key and a certificate onto a token, and an import is destructive to the
# slot it lands in. With one card attached that is unambiguous. With TWO — a geo-redundant fleet,
# or a replacement being provisioned next to the device it replaces — the default binds to
# whatever PC/SC enumerated first, which is not stable across replugs. "Provision the standby"
# then has a real chance of re-provisioning the primary.
#
# So: if more than one token is present and no --slot was given, REFUSE. Picking one and hoping is
# how the wrong card gets wiped, and the operator would not find out until the addresses disagree.
TOKENS="$(pkcs11-tool --module "$MODULE" --list-slots 2>/dev/null | grep -c 'token label' || true)"
if [ -n "$SLOT" ]; then
    case "$SLOT" in *[!0-9]*) err "--slot must be numeric (got: '$SLOT')"; exit 2;; esac
    SLOT_ARGS=(--slot "$SLOT")
    # Slot-aware: the plain --list-slots readout names whichever card is listed first, which with
    # two attached printed the WRONG serial next to the right slot number (measured 2026-09-03).
    # SOURCE the helper before testing for it. This tested `command -v hsm_serial_at_slot_id` in a
    # script that never sourced tools/hsm-reader-select.sh, so the test ALWAYS failed and the
    # broken fallback below was the only path that ever ran.
    _hrs="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-reader-select.sh"
    # shellcheck source=/dev/null
    [ -r "$_hrs" ] && . "$_hrs"
    _disp="$(hsm_serial_at_slot_id "$SLOT" 2>/dev/null || true)"
    # Fallback only if the helper is genuinely unavailable, and scoped to THIS slot's block:
    # --list-slots prints EVERY slot regardless of --slot, so `head -1` reads whichever card is
    # listed first and prints the wrong serial beside the right slot number.
    [ -n "$_disp" ] || _disp="$(pkcs11-tool --module "$MODULE" --list-slots 2>/dev/null \
        | awk -v want="$SLOT" '
            /^Slot / { inblock = ($0 ~ ("\\(0x0*" want "\\)") || $2 == want) ; next }
            inblock && /serial num/ { print $NF; exit }')"
    inf "slot: $SLOT ($_disp)"
elif [ "${TOKENS:-0}" -gt 1 ]; then
    err "$TOKENS tokens are attached and no --slot was given."
    err "REFUSING. This writes to a card destructively, and the default target is whichever"
    err "token enumerated first — not stable across replugs. Name the slot explicitly:"
    pkcs11-tool --module "$MODULE" --list-slots 2>/dev/null | grep -E 'Slot|serial' | sed 's/^/     /' >&2
    exit 2
else
    # Left UNSET rather than set to an empty array: `"${a[@]}"` on an empty array is an
    # unbound-variable error under `set -u` on bash 3.2, which is still /bin/bash on macOS.
    inf "slot: (single token attached)"
fi

# AFTER THE ARGUMENTS AND THE CARD CHOICE, BEFORE ANYTHING IS WRITTEN. Discovering there is no
# interpreter after writing to a card is a bad order to fail in — the drill had already initialised
# the card when the import died on a missing ./scriptrunner. But it must come AFTER the slot guard
# above, not before it: placed first, this refused on a CI runner with no Smart Card Shell before
# --slot was ever considered, and test-fleet-device-selection.sh read the word "Refusing" as the
# slot guard firing. Checking the interpreter is not a reason to skip checking which card.
if [ ! -x "$SCSH/scriptrunner" ]; then
    err "no Smart Card Shell at $SCSH (no executable scriptrunner there)"
    printf '  The DKEK-wrapped import path runs hsm-auto-import.js under Smart Card Shell.\n' >&2
    printf '  Point SCSH_HOME at the directory that CONTAINS scriptrunner — note the tarball\n' >&2
    printf '  unpacks as scsh-3.18.77/scsh-3.18.77/, so it is usually the inner one:\n\n' >&2
    printf '      export SCSH_HOME=$HOME/tools/scsh-3.18.77/scsh-3.18.77\n\n' >&2
    printf '  Stopping here rather than reporting this as a failed import — the card is not at fault.\n' >&2
    # NOT the word "REFUSING". In this script that word belongs to the destructive-card-selection
    # guard above, and test-fleet-device-selection.sh identifies that guard by it. A second,
    # unrelated refusal wearing the same word made a CI runner without Smart Card Shell look like
    # the slot guard firing — and two different refusals sharing a signature is confusing to a
    # reader long before it is confusing to a test.
    exit 2
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

# scsh's `new Card()` takes a reader NAME, not a number — measured 2026-08-02: HSM_READER=0
# fails with 'Card reader 0 not found'. The drill scripts pass the PC/SC index as --reader;
# resolve it to the name pcsc reports. A name passes through unchanged.
if [[ "$READER" =~ ^[0-9]+$ ]]; then
    RNAME="$(opensc-tool -l 2>/dev/null | awk -v n="$READER" \
        '$1==n { line=$0; sub(/^ *[0-9]+ +/, "", line); sub(/^(Yes|No) +/, "", line); print line; exit }')"
    [ -n "$RNAME" ] || { err "no PC/SC reader at index $READER (opensc-tool -l)"; exit 2; }
    inf "reader: $RNAME (index $READER)"
    READER="$RNAME"
fi

# NAME THE CARD WE MEAN, so the shell can refuse if scsh lands somewhere else.
#
# $READER above is a reader NAME, and scsh matches names by PREFIX. When one attached reader's
# name is a strict prefix of another's — measured 2026-09-03, "…CCID Interface" vs
# "…CCID Interface 01" — the shorter one CANNOT BE ADDRESSED AT ALL: asking for its exact full
# name returns the other card. The PKCS#11 slot id does not have that problem, so derive the
# expected serial from --slot and let hsm-auto-import.js assert it before it authenticates.
EXPECT_SERIAL=""
_ik_rs="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/hsm-reader-select.sh"
if [ -n "${SLOT:-}" ] && [ -f "$_ik_rs" ]; then
    # shellcheck source=/dev/null
    . "$_ik_rs"
    EXPECT_SERIAL="$(hsm_serial_at_slot_id "$SLOT" 2>/dev/null)" || EXPECT_SERIAL=""
    [ -n "$EXPECT_SERIAL" ] && inf "expecting card $EXPECT_SERIAL at slot $SLOT"
fi

# ---- 1. the key, via the DKEK-wrapped import path -------------------------------------------
inf "importing key from $(basename "$P12") -> id $KEY_ID"
out="$( cd "$SCSH" && \
    HSM_P12="$P12" HSM_P12_PW_FILE="$PW_FILE" \
    HSM_DKEK_SHARE="$DKEK_SHARE" HSM_DKEK_PW_FILE="$DKEK_PW" \
    HSM_USER_PIN_FILE="$PIN_FILE" HSM_LABEL="$LABEL" HSM_READER="$READER" \
    HSM_EXPECT_SERIAL="$EXPECT_SERIAL" \
    ./scriptrunner "$HERE/hsm-auto-import.js" 2>&1 )"
printf '%s\n' "$out" | grep -E "STEP (wrap|unwrap)|RESULT" | sed 's/^/     /'
if ! grep -q "IMPORT-OK" <<< "$out"; then
    err "key import did not report IMPORT-OK"
    printf '%s\n' "$out" | tail -5 >&2
    exit 1
fi
ok "key imported"

# ---- 2. the certificate ----------------------------------------------------------------------
# DER, because --write-object wants DER and quietly does the wrong thing with PEM.
case "$CERT" in
    *.der|*.cer) cp "$CERT" "$WORK/cert.der";;
    *) openssl x509 -in "$CERT" -outform DER -out "$WORK/cert.der" 2>/dev/null \
         || { err "could not convert $CERT to DER"; exit 1; };;
esac

PIN="$(cat "$PIN_FILE")"
if ! pkcs11-tool --module "$MODULE" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} --login --pin "$PIN" \
        --write-object "$WORK/cert.der" --type cert --id "$KEY_ID" --label "$LABEL" \
        > "$WORK/cert.log" 2>&1; then
    err "certificate write failed — the key is on the card but INVISIBLE to gpg and ssh"
    # CKR_GENERAL_ERROR here has been observed to mean the object store is exhausted after
    # repeated write/delete cycles; a re-initialise clears it.
    grep -iE "CKR_|error" "$WORK/cert.log" | head -3 >&2
    exit 1
fi
ok "certificate written"

# ---- 3. verify BOTH landed -------------------------------------------------------------------
# Reporting success without checking is how a key ends up on a card that nothing can find.
objs="$(pkcs11-tool --module "$MODULE" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} --login --pin "$PIN" --list-objects 2>/dev/null)"
grep -q "Private Key Object" <<< "$objs" || { err "no private key enumerates"; exit 1; }
grep -q "Certificate Object" <<< "$objs" || { err "no certificate enumerates"; exit 1; }
ok "verified: key and certificate both present"
inf "keys on card: $(printf '%s' "$objs" | grep -c 'Private Key Object')"
inf "certs on card: $(printf '%s' "$objs" | grep -c 'Certificate Object')"
