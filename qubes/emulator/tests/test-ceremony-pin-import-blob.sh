#!/usr/bin/env bash
# test-ceremony-pin-import-blob.sh — step 0 can write each HSM's PIN as a TPM import blob for its KMS
# host (ADR-0002 D21), so the PIN is never typed at the site or carried in clear. pin_blob_for:
#   - refuses unless the TYPED fingerprint prefix matches the public key (a substituted key would
#     receive the PIN), and leaves no blob when it refuses (not even an earlier attempt's);
#   - refuses a key that is not ECC P-256 (an RSA-3072 import key from before regalia-kms#671), saying so;
#   - is offered after step 0 loads the PINs, from any source (generated, chosen, hand-edited file);
#   - takes the PIN on file descriptor 3, never argv, and leaves no PIN file behind;
#   - writes a v2 blob (regalia-kms PIN-IMPORT-DESIGN.md): a TPM2 duplication of a sealed object
#     holding the PIN, made offline with tpm2_duplicate --tcti none, which a TPM-resident P-256 key
#     opens with TPM2_Import + TPM2_Load + TPM2_Unseal (proven here with swtpm when tpm2-tools and swtpm
#     are installed, as regalia-kms seal-hsm-pin.sh --from-blob does), and no other TPM does;
#   - builds the parent's public area from its own pinned template, byte for byte the TPM's.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
skip_dep(){ # a missing dependency: a skip by hand, a failure where REQUIRE_EMULATOR_DEPS=1 (CI), so a test that never ran is never green (#166)
  if [ "${REQUIRE_EMULATOR_DEPS:-0}" = 1 ]; then echo "  FAIL: $1, and REQUIRE_EMULATOR_DEPS=1: this test must run here, not skip"; exit 1; fi
  echo "  SKIP: $1 (REQUIRE_EMULATOR_DEPS=1 makes this a failure)"; exit 0
}
command -v openssl >/dev/null || { skip_dep "openssl not installed"; }
command -v tpm2_duplicate >/dev/null || { skip_dep "tpm2_duplicate (tpm2-tools) not installed: step 0 wraps PINs with it, offline"; }
T="$(mktemp -d)"
TESTS="$HERE"     # ceremony.sh sets HERE to its own directory
# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
# shellcheck source=pin-import-tpm.sh
. "$TESTS/pin-import-tpm.sh"
# After sourcing: ceremony.sh installs its own EXIT trap, which would replace this one.
trap 'pit_stop; rm -rf "$T"' EXIT
WORK="$T/work"; mkdir -p "$WORK"; chmod 700 "$WORK"
PIN="7310048261"
hexof(){ printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

# A test-only P-256 key pair standing in for a host's import key where there is no TPM (generated here, never committed).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/host.key" 2>/dev/null
openssl pkey -in "$T/host.key" -pubout -out "$T/host.pub.pem"
FP="$(openssl pkey -pubin -in "$T/host.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"

hdr "the right fingerprint: a v2 blob"
pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/a.blob" 3< <(printf '%s' "$PIN") >/dev/null 2>&1 && [ -s "$T/a.blob" ] \
  && P "blob written ($(wc -c < "$T/a.blob") bytes)" || F "no blob for the right fingerprint"
[ "$(head -c 113 "$T/a.blob")" = "regalia-pin-blob v2 tpm2-import nist-p256 sha256=$FP" ] \
  && [ "$(head -c 114 "$T/a.blob" | tail -c 1 | od -An -tx1 | tr -d ' \n')" = 0a ] && P "the v2 header names the key's full fingerprint" || F "header: $(head -c 114 "$T/a.blob" | tr -c '[:print:]' '?')"
sizes="$(python3 -I -c '
import sys; b=open(sys.argv[1],"rb").read()[114:]; o=0; out=[]
for _ in range(3):
    s=int.from_bytes(b[o:o+2],"big"); out.append(s); o+=2+s
print(" ".join(map(str,out)), "rest", len(b)-o)' "$T/a.blob")"
[[ "$sizes" =~ ^[0-9]+\ [0-9]+\ 68\ rest\ 0$ ]] && P "then exactly three TPM2B parts, the seed a P-256 point ($sizes)" || F "parts: $sizes"
grep -qF "$PIN" "$T/a.blob" && F "the PIN is visible in the blob" || P "the PIN is not visible in the blob"
python3 -I -c 'import sys,hashlib; b=open(sys.argv[1],"rb").read(); sys.exit(hashlib.sha256(sys.argv[2].encode()).digest() in b)' "$T/a.blob" "$PIN" \
  && P "the blob does not carry sha256(PIN) (a 10-digit PIN would not survive it)" || F "sha256(PIN) is in the blob"
pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/a2.blob" 3< <(printf '%s' "$PIN") >/dev/null 2>&1
cmp -s "$T/a.blob" "$T/a2.blob" && F "two blobs of one PIN are identical" || P "two blobs of one PIN differ (fresh seed and seedValue each time)"
[ -z "$(ls -A "$WORK")" ] && P "nothing is left in the RAM workdir (no PIN file, no key copy)" || F "left in the workdir: $(ls -A "$WORK")"
pin_blob_for "$T/host.pub.pem" "$(tr a-f A-F <<< "${FP:0:8}"):${FP:8:8}" "$T/b.blob" 3< <(printf '%s' "$PIN") >/dev/null 2>&1 \
  && P "the typed prefix may be upper case or grouped with colons" || F "a formatted prefix was refused"

hdr "refusals write nothing"
# a valid hex prefix that differs from the real one in its first character
if [ "${FP:0:1}" = 0 ]; then other="1${FP:1:15}"; else other="0${FP:1:15}"; fi
out="$(pin_blob_for "$T/host.pub.pem" "$other" "$T/c.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'fingerprint MISMATCH' <<< "$out" && [ ! -e "$T/c.blob" ] && P "a wrong fingerprint is refused; no blob" || F "wrong fingerprint accepted (rc=$rc)"
out="$(pin_blob_for "$T/host.pub.pem" "${FP:0:8}" "$T/d.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && [ ! -e "$T/d.blob" ] && P "fewer than 16 hex characters are refused" || F "a short prefix was accepted"
printf 'not a key\n' > "$T/junk.pem"
out="$(pin_blob_for "$T/junk.pem" "${FP:0:16}" "$T/e.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && [ ! -e "$T/e.blob" ] && P "a file that is not a public key is refused" || F "junk accepted as a key"
printf 'blob from an earlier attempt' > "$T/f.blob"
out="$(pin_blob_for "$T/host.pub.pem" "$other" "$T/f.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && [ ! -e "$T/f.blob" ] && P "a refusal also removes an earlier attempt's blob at that name" || F "a stale blob survived a refusal"
# an import key from before regalia-kms#671 (RSA-3072), with its RIGHT fingerprint typed: refused by its type
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$T/rsa.key" 2>/dev/null
openssl pkey -in "$T/rsa.key" -pubout -out "$T/rsa.pub.pem"
RFP="$(openssl pkey -pubin -in "$T/rsa.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"
out="$(pin_blob_for "$T/rsa.pub.pem" "${RFP:0:16}" "$T/g.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'not an ECC P-256 public key' <<< "$out" && grep -q 'regalia-kms#671' <<< "$out" && grep -q -- '--replace-import-key' <<< "$out" \
  && [ ! -e "$T/g.blob" ] && P "an RSA-3072 import key (before #671) is refused, saying what to do; no blob" || F "RSA key: rc=$rc $out"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$T/p384.key" 2>/dev/null
openssl pkey -in "$T/p384.key" -pubout -out "$T/p384.pub.pem"
PFP="$(openssl pkey -pubin -in "$T/p384.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"
out="$(pin_blob_for "$T/p384.pub.pem" "${PFP:0:16}" "$T/h.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'not an ECC P-256 public key' <<< "$out" && [ ! -e "$T/h.blob" ] && P "a P-384 key is refused; no blob" || F "P-384 key: rc=$rc"
[ -z "$(ls -A "$WORK")" ] && P "no refusal leaves anything in the RAM workdir" || F "left in the workdir: $(ls -A "$WORK")"

hdr "the RAM workdir, the PIN's form, and what tpm2_duplicate says"
out="$(WORK="" pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/w.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'RAM workdir (WORK) is not set up' <<< "$out" && [ ! -e "$T/w.blob" ] && P "WORK unset: refused, no fallback to /tmp" || F "WORK unset: rc=$rc $out"
out="$(WORK="$T/not-there" pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/w.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'RAM workdir (WORK) is not set up' <<< "$out" && [ ! -e "$T/not-there" ] && P "WORK not a directory: refused" || F "WORK missing: rc=$rc $out"
# $'...' keeps the newlines (a $(...) would strip a trailing one), and printf '%s' passes them on as they are:
# a good first line with more after it, and a good PIN with a trailing newline, are refused by the
# no-newline rule alone (grep -x accepts the first line of each)
for bad in "" "12345" "73100482610000000" "7310a48261" " 7310048261" $'7310048261\nx' $'7310048261\n'; do
  out="$(pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/p.blob" 3< <(printf '%s' "$bad") 2>&1)"; rc=$?
  first="${bad%%$'\n'*}"     # grep -F takes each line of its pattern as a pattern: look for the digits' line
  [ "$rc" != 0 ] && grep -q 'empty or not 6-16 digits' <<< "$out" && [ ! -e "$T/p.blob" ] && ! grep -qF "${first:-@@none@@}" <<< "$out" \
    && P "PIN '$(printf '%s' "$bad" | tr '0-9' '#' | tr '\n' '~')' refused before wrapping; not echoed" || F "PIN of form $(printf '%s' "$bad" | od -An -c | tr -s ' '): rc=$rc $out"
done
out="$(pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/p.blob" 3< <(printf '%s\n' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'empty or not 6-16 digits' <<< "$out" && P "a PIN with a trailing newline is refused (the blob must hold exactly the PIN)" || F "PIN+newline: rc=$rc"
mkdir -p "$T/stubbin"
cat > "$T/stubbin/tpm2_duplicate" <<'STUB'
#!/bin/sh
# a failing tpm2_duplicate that also tries to print the PIN it was given
while [ $# -gt 0 ]; do [ "$1" = -k ] && k="$2"; shift; done
echo "ERROR: simulated failure for the test" >&2
printf 'leak: %s\n' "$(cat "$k")" >&2
exit 3
STUB
chmod +x "$T/stubbin/tpm2_duplicate"
out="$(PATH="$T/stubbin:$PATH" pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/s.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'tpm2_duplicate exit 3' <<< "$out" && grep -q 'tpm2_duplicate: ERROR: simulated failure for the test' <<< "$out" && [ ! -e "$T/s.blob" ] \
  && P "a tpm2_duplicate failure shows its exit status and its stderr" || F "stderr not shown: rc=$rc $out"
! grep -qF "$PIN" <<< "$out" && ! grep -q 'leak:' <<< "$out" && P "a stderr line holding the PIN is dropped, never shown" || F "the PIN reached the terminal: $out"
[ -z "$(ls -A "$WORK")" ] && P "and nothing is left in the RAM workdir after the failure" || F "left in the workdir: $(ls -A "$WORK")"
# TSS2_LOG at trace makes the TSS log marshalled buffers (the PIN, in hex), past the whole-PIN filter:
# set in the caller, neither it nor TSS2_LOGFILE may reach tpm2_duplicate. A stub records what it gets;
# a control variable shows the record is the caller's environment
mkdir -p "$T/envbin"
cat > "$T/envbin/tpm2_duplicate" <<STUB
#!/bin/sh
env | grep -E '^(TSS2_|PIT_ENV_MARK=)' > "$T/dup.env"
exit 3
STUB
chmod +x "$T/envbin/tpm2_duplicate"; rm -f "$T/dup.env"
out="$(export TSS2_LOG='all+trace' TSS2_LOGFILE="$T/tss.log" PIT_ENV_MARK=1; PATH="$T/envbin:$PATH" \
  pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/e.blob" 3< <(printf '%s' "$PIN") 2>&1)"; rc=$?
[ "$rc" != 0 ] && [ -f "$T/dup.env" ] && grep -qx 'PIT_ENV_MARK=1' "$T/dup.env" && ! grep -qE '^TSS2_LOG(FILE)?=' "$T/dup.env" \
  && P "TSS2_LOG and TSS2_LOGFILE set by the caller do not reach tpm2_duplicate" \
  || F "the TSS logging settings reached tpm2_duplicate: rc=$rc env: $(cat "$T/dup.env" 2>/dev/null)"
out="$( (unset CEREMONY_SIMULATE; PATH="$T/stubbin:$PATH" guard_no_stubs) 2>&1)"; rc=$?
case "$T" in /tmp/*|/private/tmp/*|/var/folders/*|*/.cache/*|*/T/tmp.*)
  [ "$rc" != 0 ] && grep -q "'tpm2_duplicate' resolves to $T/stubbin/tpm2_duplicate" <<< "$out" \
    && P "guard_no_stubs refuses a real ceremony whose tpm2_duplicate is a stub under a temp dir" || F "guard_no_stubs let a stub tpm2_duplicate through: rc=$rc $out" ;;
  *) echo "  (skipping the guard case: this test's temp dir $T is not under a path guard_no_stubs treats as a stub)" ;;
esac
# The offer comes after step 0 has LOADED the PINs, so the hand-edited (e) file gets it too, not only
# generated or chosen PINs.
body="$(declare -f step_set_pins)"
grep -q 'offer_pin_blobs' <<< "$body" && ! declare -f generate_pins | grep -q 'offer_pin_blobs' \
  && [ "$(grep -n 'done < "$pfile"' <<< "$body" | cut -d: -f1)" -lt "$(grep -n 'offer_pin_blobs' <<< "$body" | cut -d: -f1)" ] \
  && P "blobs are offered after the PIN file is loaded, whatever its source" || F "the blob offer is not after the PIN load in step_set_pins"
grep -q 'cat <&3 > "$d/pin"' "$SCRIPTS/ceremony.sh" && grep -q 'pin_blob_for "$pub" "$typed" "$dir/$file" 3< <(printf' "$SCRIPTS/ceremony.sh" \
  && fn="$(declare -f pin_blob_for)" && ! grep -qE 'tpm2_duplicate[^|]*\$PIN|printf[^|]*\$PIN' <<< "$fn" \
  && P "the PIN reaches tpm2_duplicate through a 0600 file in the RAM workdir, never argv" || F "the PIN may be on argv"

hdr "a TPM-resident key opens the ceremony's blob (swtpm, as at the host)"
if pit_available; then
  if pit_start "$T/host-tpm"; then
    TFP="$(openssl pkey -pubin -in "$PIT_DIR/host.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"
    # the parent's public area as step 0 rebuilds it (from its pinned template and the verified point)
    hex="$(openssl pkey -pubin -in "$PIT_DIR/host.pub.pem" -outform der | od -An -tx1 -v | tr -d ' \n')"
    printf '%b' "$(sed 's/../\\x&/g' <<< "${PIN_IMPORT_PARENT_TEMPLATE}0020${hex:54:64}0020${hex:118:64}")" > "$T/rebuilt"
    cmp -s "$T/rebuilt" "$PIT_DIR/host.tpm2b" && P "step 0's pinned template is the TPM's own public area, byte for byte" || F "the pinned template differs from the TPM's"
    pin_blob_for "$PIT_DIR/host.pub.pem" "${TFP:0:16}" "$T/t.blob" 3< <(printf '%s' "$PIN") >/dev/null 2>&1
    [ "$(pit_open "$T/t.blob")" = "$(hexof "$PIN")" ] && P "TPM2_Import + Load + Unseal inside the (software) TPM recovers exactly the PIN's bytes" || F "the TPM gave bytes $(pit_open "$T/t.blob")"
    [ -z "$(pit_open "$T/a.blob")" ] && P "a blob made for another key is refused by this TPM" || F "a blob for another key opened here"
    python3 -I -c 'import sys; b=bytearray(open(sys.argv[1],"rb").read()); b[200]^=0xFF; open(sys.argv[2],"wb").write(b)' "$T/t.blob" "$T/bad.blob"
    [ -z "$(pit_open "$T/bad.blob")" ] && P "an altered blob is refused by the TPM" || F "an altered blob opened"
  else
    F "the software TPM or its import key could not be set up"
  fi
  pit_stop
elif [ "${REQUIRE_TPM_SIM:-0}" = 1 ]; then
  F "REQUIRE_TPM_SIM=1 but swtpm or tpm2-tools is missing: the TPM case must run here, not skip"
else
  echo "  (skipping the TPM case: swtpm and tpm2-tools not installed; CI sets REQUIRE_TPM_SIM=1)"
fi

echo; echo "pin-import-blob: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
