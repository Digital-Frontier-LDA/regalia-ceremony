#!/usr/bin/env bash
# test-import-key-nojvm.sh — the DKEK-wrapped import with no Java anywhere (regalia#486 step 3).
#
# THE STEP THIS REPLACES was the last one needing Smart Card Shell: sc-hsm-tool can UNWRAP a blob
# but cannot BUILD one, and the format lived only in scsh's DKEK.js. This suite drives the real
# encoder (hsm-dkek-encode-key.py, real crypto, real PKCS#12) and stubs only the card, so what is
# asserted is that the two halves actually chain: a blob is built, the SAME blob reaches UNWRAP
# KEY, and the PrKD is written for the id and label the caller asked for.
#
# NO CARD, AND NO JVM — if this suite ever needs a JVM to pass, the point has been lost.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
IMPORT="$SCRIPTS/hsm-import-key-nojvm.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ -r "$IMPORT" ] || { echo "no hsm-import-key-nojvm.sh at $IMPORT" >&2; exit 1; }

. "$(cd "$HERE/../../.." && pwd)/tools/ceremony-python.sh" 2>/dev/null || true
if ! ceremony_python_require cryptography 2>/dev/null; then
  printf '  (skipping: no interpreter here can import `cryptography`, which the encoder needs)\n'
  exit 0
fi

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# A real secp256r1 PKCS#12 and a real DKEK share, built the way the ceremony builds them.
printf 'p12pass' > "$T/p12.pw"; printf 'dkekpass' > "$T/dkek.pw"; printf '648219' > "$T/pin.txt"
python3 - "$T" <<'PY'
import sys, datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
T = sys.argv[1]
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "drill")])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(datetime.datetime(2020,1,1)).not_valid_after(datetime.datetime(2040,1,1))
        .sign(key, hashes.SHA256()))
open(f"{T}/funding.p12","wb").write(
    pkcs12.serialize_key_and_certificates(b"drill", key, cert, None,
                                          BestAvailableEncryption(b"p12pass")))
from cryptography.hazmat.primitives.serialization import Encoding
open(f"{T}/funding.crt","wb").write(cert.public_bytes(Encoding.PEM))
PY
[ -s "$T/funding.p12" ] || { echo "could not build the PKCS#12 fixture" >&2; exit 1; }
# A DKEK share in sc-hsm-tool's format: Salted__ || salt(8) || AES-256-CBC(3x10M-MD5 KDF) of a
# 32-byte DKEK whose plaintext tail is 16 x 0x10.
python3 - "$T" <<'PY'
import sys, os, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
T = sys.argv[1]
salt = os.urandom(8); pw = b"dkekpass"
d = b""; out = b""
for _ in range(3):
    d = d + pw + salt
    for _ in range(10_000_000):
        d = hashlib.md5(d).digest()
    out += d
key, iv = out[:32], out[32:48]
body = os.urandom(32) + bytes([0x10])*16
enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
open(f"{T}/dkek.pbe","wb").write(b"Salted__" + salt + enc.update(body) + enc.finalize())
PY
[ -s "$T/dkek.pbe" ] || { echo "could not build the DKEK share fixture" >&2; exit 1; }

# The card: record every APDU, answer 9000 to all four.
BIN="$T/bin"; mkdir -p "$BIN"
# pkcs11-tool: record the certificate write, and enumerate both objects afterwards.
# A FAITHFUL LISTING CARRIES IDs. The first version of this stub printed object headers and
# labels and no ID lines at all, so it could not tell a caller that checks the key and its
# certificate share an id from one that does not look.
cat > "$BIN/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_P11:?}"
case "$*" in
  *--write-object*)
    # Remember the id the certificate was written with, so the listing can report it.
    prev=""; for a in "$@"; do [ "$prev" = "--id" ] && printf '%s' "$a" > "${STUB_P11%.txt}.certid"; prev="$a"; done
    exit 0;;
  *--list-objects*)
    certid="$(cat "${STUB_P11%.txt}.certid" 2>/dev/null || echo 1f)"
    # The KEY's id is the one the unwrap used: key reference 31 decimal is 0x1f. The stub is told
    # which to claim through STUB_KEY_ID so a row can model the mismatched state.
    printf 'Private Key Object; EC\n  label:      akash-funding\n  ID:         %s\n' "${STUB_KEY_ID:-$certid}"
    printf 'Certificate Object; type = X.509 cert\n  label:      akash-funding\n  ID:         %s\n' "$certid"
    exit 0;;
esac
exit 0
STUB
chmod +x "$BIN/pkcs11-tool"
export STUB_P11="$T/p11.txt"; : > "$STUB_P11"

cat > "$BIN/opensc-explorer" <<'STUB'
#!/usr/bin/env bash
cat >> "${STUB_STDIN:?}"
for sw in 9000 9000 9000 9000; do printf 'Received (SW1=0x%s, SW2=0x%s)\n' "${sw:0:2}" "${sw:2:2}"; done
STUB
chmod +x "$BIN/opensc-explorer"
# The only java/scriptrunner on PATH: running either records it and fails.
for j in java scriptrunner scsh; do
  printf '#!/usr/bin/env bash\nprintf "%%s %%s\\n" "'"$j"'" "$*" >> "${JVM_TRIPWIRE:?}"\nexit 127\n' > "$BIN/$j"
  chmod +x "$BIN/$j"
done
export JVM_TRIPWIRE="$T/jvm-tripwire"
export PATH="$BIN:$PATH"
: > "$T/stdin.txt"

hdr "the whole path runs with no Java on PATH"
mkdir -p "$T/tmp"
out="$(STUB_STDIN="$T/stdin.txt" TMPDIR="$T/tmp" bash "$IMPORT" --p12 "$T/funding.p12" --pw-file "$T/p12.pw" \
        --id 3 --label akash-funding --dkek "$T/dkek.pbe" --dkek-pw "$T/dkek.pw" \
        --pin-file "$T/pin.txt" --reader 0 --cert "$T/funding.crt" \
        --module /dev/null 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && P "it succeeds end to end (exit 0)" || F "exit $rc: $(tail -4 <<<"$out")"
grep -q 'IMPORT-OK' <<<"$out" && P "…and reports IMPORT-OK, the token the callers grep for" \
  || F "no IMPORT-OK in the output"
# A TRIPWIRE, NOT A GREP OF THE PROSE. Searching the output for "scsh" failed on this script's own
# sentence explaining what the scsh path used to do — a test that reads explanations rather than
# behaviour. These stubs are the only `java` and `scriptrunner` on PATH and they record being run.
[ -s "$T/jvm-tripwire" ] && F "a JVM tool was executed: $(cat "$T/jvm-tripwire")" \
  || P "…having executed no java and no scriptrunner (tripwire stubs on PATH, never touched)"

hdr "the blob that was built is the blob that reached the card"
apdu3="$(grep -oE '^apdu [0-9A-Fa-f]+' "$T/stdin.txt" | awk '{print $2}' | sed -n 3p | tr 'a-f' 'A-F')"
case "$apdu3" in
  807403930*) P "UNWRAP KEY is 80 74 03 93 — the key id the caller asked for, extended Lc";;
  *) F "the UNWRAP APDU is wrong: $(cut -c1-24 <<<"$apdu3")";;
esac
# 363 bytes for a 256-bit EC key: the length in the extended Lc must match what the encoder made.
grep -q '0016B' <<<"$apdu3" && P "…carrying 363 bytes, the size the encoder reports for a 256-bit EC key" \
  || F "the blob length in the APDU is not 363 bytes: $(cut -c1-24 <<<"$apdu3")"
apdu4="$(grep -oE '^apdu [0-9A-Fa-f]+' "$T/stdin.txt" | awk '{print $2}' | sed -n 4p | tr 'a-f' 'A-F')"
case "$apdu4" in
  00D7C403*) P "the PrKD is written to EF C403 — the same id";;
  *) F "the PrKD does not target EF C403: $(cut -c1-16 <<<"$apdu4")";;
esac
grep -q '0C0D616B6173682D66756E64696E67' <<<"$apdu4" \
  && P "…carrying the label the caller asked for" || F "the label is not in the PrKD"
grep -q '02020100' <<<"$apdu4" \
  && P "…and the key size the ENCODER measured (256), not one this script assumed" \
  || F "the PrKD key size is not 256: $apdu4"

hdr "the key and its certificate land on the SAME id, in one base"
# --key-id is a SmartCard-HSM key reference (DECIMAL 1..255); `pkcs11-tool --id` takes HEX. Passing
# the same string to both gave a key at 0x1f and its certificate at 0x31 for --id 31, measured on
# ESP41D722E2. A certificate that does not share the key's CKA_ID is not associated with it — and
# an UNPAIRED certificate is what a device-identity probe treats as the DEVICE's (regalia-kms#17).
# Every earlier import used 1, 2, 3 or 5, which are the same in both bases, so nothing showed it.
: > "$T/stdin.txt"; : > "$STUB_P11"
out7="$(STUB_STDIN="$T/stdin.txt" TMPDIR="$T/tmp" bash "$IMPORT" --p12 "$T/funding.p12" \
        --pw-file "$T/p12.pw" --id 31 --label akash-funding --dkek "$T/dkek.pbe" \
        --dkek-pw "$T/dkek.pw" --pin-file "$T/pin.txt" --reader 0 \
        --cert "$T/funding.crt" --module /dev/null 2>&1)"
# key reference 31 decimal is 0x1F: the PrKD goes to EF C41F and the certificate must be written
# with --id 1f, not --id 31.
apdu_prkd="$(grep -oE '^apdu [0-9A-Fa-f]+' "$T/stdin.txt" | awk '{print $2}' | grep -i '^00D7C4' | head -1 | tr 'a-f' 'A-F')"
case "$apdu_prkd" in
  00D7C41F*) P "the PrKD goes to EF C41F — --id 31 is the DECIMAL key reference";;
  *) F "the PrKD did not target EF C41F: $apdu_prkd";;
esac
grep -qE -- '--type cert .*--id 1f|--id 1f .*--type cert' "$STUB_P11" \
  && P "…and the certificate is written with --id 1f, the same id in hex" \
  || F "the certificate id does not match the key's: $(grep -- '--write-object' "$STUB_P11" | head -1)"
grep -qE -- '--id 31' "$STUB_P11" \
  && F "the certificate was written with --id 31, which pkcs11-tool reads as hex 0x31" \
  || P "…and 31 is never passed to pkcs11-tool, where it would mean 0x31"

hdr "present-but-unpaired is caught, not reported as success"
# The state the base confusion produced looks identical to success in a plain object listing.
: > "$T/stdin.txt"; : > "$STUB_P11"
out8="$(STUB_KEY_ID=aa STUB_STDIN="$T/stdin.txt" TMPDIR="$T/tmp" bash "$IMPORT" --p12 "$T/funding.p12" \
        --pw-file "$T/p12.pw" --id 31 --label akash-funding --dkek "$T/dkek.pbe" \
        --dkek-pw "$T/dkek.pw" --pin-file "$T/pin.txt" --reader 0 \
        --cert "$T/funding.crt" --module /dev/null 2>&1)"; rc8=$?
[ "$rc8" -ne 0 ] && P "a key and certificate on different ids is a FAILURE" \
  || F "it reported success with the certificate on a different id than the key"
# Either half of the pair can be the one that does not match, and the message names whichever it
# noticed — with the ids it actually found, which is what an operator needs to see.
grep -qE 'no private key with id|did not land on id' <<<"$out8" \
  && P "…naming the id that does not match" || F "the failure does not name it: $(tail -2 <<<"$out8")"
grep -q 'found: key aa cert 1f' <<<"$out8" \
  && P "…and listing what it did find, so the mismatch is visible" \
  || F "the failure does not show the ids it found: $(tail -2 <<<"$out8")"
grep -q 'IMPORT-OK' <<<"$out8" && F "it printed IMPORT-OK anyway" || P "…and does not print IMPORT-OK"
cat > "$BIN/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_P11:?}"
case "$*" in
  *--write-object*) exit 0;;
  *--list-objects*) printf 'Private Key Object; EC\n  ID:         1f\nCertificate Object; type = X.509 cert\n  ID:         1f\n'; exit 0;;
esac
exit 0
STUB
chmod +x "$BIN/pkcs11-tool"

hdr "a listing with no parseable ID is refused, not read as agreement"
# An empty parse satisfies any "they agree" test trivially — the silent-instrument shape, where
# the check reports clean precisely when it is blind. This is the listing the FIRST version of
# this suite's own stub produced: object headers, labels, and no ID lines at all.
cat > "$BIN/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
printf '%s
' "$*" >> "${STUB_P11:?}"
case "$*" in
  *--list-objects*) printf 'Private Key Object; EC
  label:      akash-funding
Certificate Object; type = X.509 cert
  label:      akash-funding
'; exit 0;;
esac
exit 0
STUB
chmod +x "$BIN/pkcs11-tool"
: > "$T/stdin.txt"; : > "$STUB_P11"
out9="$(STUB_STDIN="$T/stdin.txt" TMPDIR="$T/tmp" bash "$IMPORT" --p12 "$T/funding.p12" \
        --pw-file "$T/p12.pw" --id 31 --label akash-funding --dkek "$T/dkek.pbe" \
        --dkek-pw "$T/dkek.pw" --pin-file "$T/pin.txt" --reader 0 \
        --cert "$T/funding.crt" --module /dev/null 2>&1)"; rc9=$?
[ "$rc9" -ne 0 ] && P "an unreadable listing is a FAILURE" \
  || F "it reported success from a listing with no object IDs in it"
grep -q 'no object IDs could be read back' <<<"$out9" \
  && P "…saying the pair could not be shown, rather than claiming it was" \
  || F "the refusal does not say why: $(tail -2 <<<"$out9")"
grep -q 'IMPORT-OK' <<<"$out9" && F "it printed IMPORT-OK on an unreadable listing" || P "…and prints no IMPORT-OK"

hdr "the certificate — without which most of the stack cannot see the key"
grep -q -- '--write-object' "$STUB_P11" && P "a certificate is written with pkcs11-tool (no JVM needed for it either)" \
  || F "no certificate was written — gpg and ssh would not see this key"
grep -q -- '--type cert' "$STUB_P11" && P "…as a cert object, with the key's id and label" \
  || F "the write-object call does not say --type cert"
grep -q -- '--list-objects' "$STUB_P11" \
  && P "…and both objects are ENUMERATED afterwards, not assumed" \
  || F "nothing verified that the key and certificate landed"
grep -q 'verified: key and certificate both present' <<<"$out" \
  && P "…with the verification reported" || F "the verification result is not reported"

# A CARD THAT TAKES THE WRITE AND DOES NOT SHOW THE OBJECT. CKR_GENERAL_ERROR on this card has
# meant an exhausted object store; a write that "succeeds" into a full store leaves the key
# invisible to gpg and ssh, which is the failure the certificate exists to prevent. The check must
# be the ENUMERATION, not the write's exit status.
cat > "$BIN/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_P11:?}"
case "$*" in
  *--list-objects*) printf 'Private Key Object; EC\n  label:      akash-funding\n  ID:         1f\n'; exit 0;;
esac
exit 0
STUB
chmod +x "$BIN/pkcs11-tool"
: > "$T/stdin.txt"
out2="$(STUB_STDIN="$T/stdin.txt" TMPDIR="$T/tmp" bash "$IMPORT" --p12 "$T/funding.p12" \
        --pw-file "$T/p12.pw" --id 3 --label akash-funding --dkek "$T/dkek.pbe" \
        --dkek-pw "$T/dkek.pw" --pin-file "$T/pin.txt" --reader 0 --cert "$T/funding.crt" \
        --module /dev/null 2>&1)"; rc2=$?
[ "$rc2" -ne 0 ] && P "a card that does not enumerate the certificate is a FAILURE, not an IMPORT-OK" \
  || F "it reported success though no certificate enumerated"
grep -q 'no certificate enumerates' <<<"$out2" \
  && P "…and says exactly that" || F "the failure does not name it: $(tail -2 <<<"$out2")"
grep -q 'IMPORT-OK' <<<"$out2" && F "it printed IMPORT-OK anyway" || P "…and does not print IMPORT-OK"

hdr "the blob does not outlive the import"
# TMPDIR WAS POINTED INTO THE FIXTURE for the successful run above, so the script's own work
# directory is somewhere this can see. Without that this searched $T while the blob sat in /tmp,
# and the assertion passed no matter what the script did — a test that measured nothing.
#
# NO PIPE INTO grep -q. Under pipefail, grep -q exits on its first match, find takes SIGPIPE, and
# the pipeline status is 141 — so the branch is NOT taken and a leftover blob reads as clean. The
# producer finishes into a variable first. (tools/hsm-lint-predicates.sh flags exactly this shape.)
leftovers="$(find "$T/tmp" -type f 2>/dev/null)"
[ -n "$leftovers" ] && F "the work directory was left behind: $leftovers" \
  || P "the work directory is gone, blob with it"

# THE HEALTHY CARD STUB IS BACK. The row above deliberately installed one that takes the
# certificate write and then does not enumerate it; leaving that in place would fail every row
# after it for a reason that has nothing to do with what those rows test.
# A FAITHFUL LISTING CARRIES IDs. The first version of this stub printed object headers and
# labels and no ID lines at all, so it could not tell a caller that checks the key and its
# certificate share an id from one that does not look.
cat > "$BIN/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_P11:?}"
case "$*" in
  *--write-object*)
    # Remember the id the certificate was written with, so the listing can report it.
    prev=""; for a in "$@"; do [ "$prev" = "--id" ] && printf '%s' "$a" > "${STUB_P11%.txt}.certid"; prev="$a"; done
    exit 0;;
  *--list-objects*)
    certid="$(cat "${STUB_P11%.txt}.certid" 2>/dev/null || echo 1f)"
    # The KEY's id is the one the unwrap used: key reference 31 decimal is 0x1f. The stub is told
    # which to claim through STUB_KEY_ID so a row can model the mismatched state.
    printf 'Private Key Object; EC\n  label:      akash-funding\n  ID:         %s\n' "${STUB_KEY_ID:-$certid}"
    printf 'Certificate Object; type = X.509 cert\n  label:      akash-funding\n  ID:         %s\n' "$certid"
    exit 0;;
esac
exit 0
STUB
chmod +x "$BIN/pkcs11-tool"

hdr "a ceremony's DKEK has no typed password — the shares are the password"
# `--create-dkek-share --pwd-shares-threshold/-total` generates 8 random bytes, splits them with
# Shamir over a 64-bit prime, prints only the shares, and never writes the password anywhere.
# Every real ceremony uses that path, so an importer that can only take --dkek-pw serves the drill
# and not the ceremony. The prime and shares here are REAL output from sc-hsm-tool on 2026-09-21.
cat > "$T/shares.txt" <<'X'
Prime       : e2:8c:4e:2a:93:cc:a8:77
Share ID    : 1
Share value : be:d9:2a:f6:96:43:c4:41
Prime       : e2:8c:4e:2a:93:cc:a8:77
Share ID    : 2
Share value : 8d:d4:9d:69:82:04:8a:5b
Prime       : e2:8c:4e:2a:93:cc:a8:77
Share ID    : 3
Share value : 08:3e:cb:ce:3e:4a:d6:b6
Prime       : e2:8c:4e:2a:93:cc:a8:77
Share ID    : 4
Share value : 84:5d:7a:40:86:3e:4c:32
X
# A share file whose password (2792fe8453ad89ff) encrypts a known DKEK, built here so the import
# can be driven end to end without a card.
python3 - "$T" <<'PY'
import sys, os, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
T = sys.argv[1]
salt = os.urandom(8); pw = bytes.fromhex("2792fe8453ad89ff")
d = b""; out = b""
for _ in range(3):
    d = d + pw + salt
    for _ in range(10_000_000):
        d = hashlib.md5(d).digest()
    out += d
body = os.urandom(32) + bytes([0x10]) * 16
enc = Cipher(algorithms.AES(out[:32]), modes.CBC(out[32:48])).encryptor()
open(f"{T}/dkek-shares.pbe", "wb").write(b"Salted__" + salt + enc.update(body) + enc.finalize())
PY
: > "$T/stdin.txt"
out5="$(STUB_STDIN="$T/stdin.txt" TMPDIR="$T/tmp" bash "$IMPORT" --p12 "$T/funding.p12" \
        --pw-file "$T/p12.pw" --id 4 --label akash-funding --dkek "$T/dkek-shares.pbe" \
        --dkek-shares "$T/shares.txt" --pin-file "$T/pin.txt" --reader 0 \
        --cert "$T/funding.crt" --module /dev/null 2>&1)"; rc5=$?
[ "$rc5" -eq 0 ] && P "a shares-only DKEK imports: the password is reconstructed, never typed" \
  || F "the shares path failed (exit $rc5): $(tail -4 <<<"$out5")"
grep -q 'IMPORT-OK' <<<"$out5" && P "…reporting IMPORT-OK like the password path" || F "no IMPORT-OK"

hdr "the certificate comes out of the container when none is given"
# A PKCS#12 IS a key and a certificate. Demanding a separate --cert adds a way to hand over a
# certificate belonging to a different key, and a way to fail for no reason.
: > "$T/stdin.txt"; : > "$STUB_P11"
out6="$(STUB_STDIN="$T/stdin.txt" TMPDIR="$T/tmp" bash "$IMPORT" --p12 "$T/funding.p12" \
        --pw-file "$T/p12.pw" --id 5 --label akash-funding --dkek "$T/dkek-shares.pbe" \
        --dkek-shares "$T/shares.txt" --pin-file "$T/pin.txt" --reader 0 --module /dev/null 2>&1)"; rc6=$?
[ "$rc6" -eq 0 ] && P "no --cert is not an error: the certificate is lifted from the PKCS#12" \
  || F "it required --cert (exit $rc6): $(tail -3 <<<"$out6")"
grep -q -- '--write-object' "$STUB_P11" \
  && P "…and that certificate is still written to the card" || F "no certificate was written"

hdr "refusals"
out="$(bash "$IMPORT" --p12 "$T/funding.p12" --pw-file "$T/p12.pw" --id 3 --label x \
        --cert "$T/funding.crt" --module /dev/null \
        --dkek "$T/dkek.pbe" --dkek-pw "$T/p12.pw" --pin-file "$T/pin.txt" --reader 0 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "a wrong DKEK password is a failure, not a blob under the wrong key" \
  || F "it built a blob with the wrong DKEK password"
grep -qi 'could not build the key blob' <<<"$out" \
  && P "…and says the blob could not be built, naming the step" || F "the failure does not name the step: $(tail -2 <<<"$out")"
out="$(bash "$IMPORT" --p12 "$T/nope.p12" --pw-file "$T/p12.pw" --id 3 --label x \
        --cert "$T/funding.crt" --module /dev/null \
        --dkek "$T/dkek.pbe" --dkek-pw "$T/dkek.pw" --pin-file "$T/pin.txt" --reader 0 2>&1)"
grep -q 'not readable' <<<"$out" && P "a missing PKCS#12 is refused before anything runs" \
  || F "a missing PKCS#12 was not refused: $(tail -2 <<<"$out")"
out="$(bash "$IMPORT" --p12 "$T/funding.p12" --pw-file "$T/p12.pw" --id 3 --label x \
        --cert "$T/funding.crt" --module /dev/null --dkek "$T/dkek.pbe" \
        --dkek-pw "$T/dkek.pw" --dkek-shares "$T/shares.txt" \
        --pin-file "$T/pin.txt" --reader 0 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'not both' <<<"$out" \
  && P "--dkek-pw and --dkek-shares together are refused (a reconstructed password is never also typed)" \
  || F "both DKEK sources were accepted at once: $(tail -2 <<<"$out")"
out="$(bash "$IMPORT" --p12 "$T/funding.p12" --pw-file "$T/p12.pw" --id 3 --label x \
        --cert "$T/funding.crt" --module /dev/null --dkek "$T/dkek.pbe" \
        --pin-file "$T/pin.txt" --reader 0 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'missing --dkek-pw or --dkek-shares' <<<"$out" \
  && P "neither DKEK source is refused, naming both options" \
  || F "it ran with no DKEK source: $(tail -2 <<<"$out")"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
