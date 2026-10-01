#!/usr/bin/env bash
# test-ceremony-pin-import-blob.sh — step 0 can write each HSM's PIN as a TPM import blob for its KMS
# host (ADR-0002 D21), so the PIN is never typed at the site or carried in clear. pin_blob_for:
#   - refuses unless the TYPED fingerprint prefix matches the public key (a substituted key would
#     receive the PIN), and writes nothing when it refuses;
#   - takes the PIN on file descriptor 3, never argv;
#   - writes RSA-OAEP SHA-256, which a TPM-resident key opens with tpm2_rsadecrypt (proven here with
#     swtpm when tpm2-tools and swtpm are installed, as regalia-kms seal-hsm-pin.sh --from-blob does).
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
command -v openssl >/dev/null || { echo "  (skipping: openssl not installed)"; exit 0; }
T="$(mktemp -d)"
# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
# After sourcing: ceremony.sh installs its own EXIT trap, which would replace this one.
stop_tpm(){ [ -f "$T.pid" ] && kill "$(cat "$T.pid")" 2>/dev/null; rm -f "$T.pid"; }
trap 'stop_tpm; rm -rf "$T"' EXIT
PIN="7310048261"

# A test-only RSA-3072 key pair standing in for a host's import key (generated here, never committed).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$T/host.key" 2>/dev/null
openssl pkey -in "$T/host.key" -pubout -out "$T/host.pub.pem"
FP="$(openssl pkey -pubin -in "$T/host.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"

hdr "the right fingerprint: a blob that only the host key opens"
pin_blob_for "$T/host.pub.pem" "${FP:0:16}" "$T/a.blob" 3< <(printf '%s' "$PIN") >/dev/null 2>&1 && [ -s "$T/a.blob" ] \
  && P "blob written ($(wc -c < "$T/a.blob") bytes)" || F "no blob for the right fingerprint"
got="$(openssl pkeyutl -decrypt -inkey "$T/host.key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256 -in "$T/a.blob" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
[ "$got" = "$(printf '%s' "$PIN" | od -An -tx1 | tr -d ' \n')" ] && P "it decrypts (RSA-OAEP SHA-256) to exactly the PIN's bytes, no newline" || F "decrypted bytes $got"
grep -qF "$PIN" "$T/a.blob" && F "the PIN is visible in the blob" || P "the PIN is not visible in the blob"
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
grep -q -- '-in /dev/fd/3' "$SCRIPTS/ceremony.sh" && grep -q 'pin_blob_for "$pub" "$typed" "$dir/$file" 3< <(printf' "$SCRIPTS/ceremony.sh" \
  && P "the PIN reaches openssl on a file descriptor, never argv" || F "the PIN may be on argv"

hdr "a TPM-resident key opens the ceremony's blob (swtpm, as at the host)"
if command -v swtpm >/dev/null && command -v tpm2_rsadecrypt >/dev/null; then
  mkdir -p "$T/tpm"; port=$((24000 + RANDOM % 2000))
  swtpm socket --tpm2 --tpmstate "dir=$T/tpm" --server "type=tcp,port=$port" --ctrl "type=tcp,port=$((port+1))" \
    --flags not-need-init,startup-clear --daemon --pid "file=$T.pid"; sleep 1
  export TPM2TOOLS_TCTI="swtpm:port=$port"
  fl(){ tpm2_flushcontext -t >/dev/null 2>&1; tpm2_flushcontext -s >/dev/null 2>&1; }
  # the same template as regalia-kms seal-hsm-pin.sh --init-import-key
  fl; tpm2_createprimary -Q -C o -g sha256 -G ecc256:aes128cfb -c "$T/p.ctx" \
  && tpm2_create -Q -C "$T/p.ctx" -G rsa3072 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt' -u "$T/k.pub" -r "$T/k.priv" \
  && fl && tpm2_load -Q -C "$T/p.ctx" -u "$T/k.pub" -r "$T/k.priv" -c "$T/k.ctx" \
  && tpm2_evictcontrol -Q -C o -c "$T/k.ctx" 0x81000101 >/dev/null && fl \
  && tpm2_readpublic -Q -c 0x81000101 -f pem -o "$T/tpm.pub.pem"
  TFP="$(openssl pkey -pubin -in "$T/tpm.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"
  pin_blob_for "$T/tpm.pub.pem" "${TFP:0:16}" "$T/t.blob" 3< <(printf '%s' "$PIN") >/dev/null 2>&1
  got="$(tpm2_rsadecrypt -c 0x81000101 -s oaep -o /dev/stdout "$T/t.blob" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  [ "$got" = "$(printf '%s' "$PIN" | od -An -tx1 | tr -d ' \n')" ] && P "tpm2_rsadecrypt inside the (software) TPM recovers exactly the PIN's bytes" || F "the TPM gave bytes $got"
  stop_tpm
elif [ "${REQUIRE_TPM_SIM:-0}" = 1 ]; then
  F "REQUIRE_TPM_SIM=1 but swtpm or tpm2-tools is missing: the TPM case must run here, not skip"
else
  echo "  (skipping the TPM case: swtpm and tpm2-tools not installed; CI sets REQUIRE_TPM_SIM=1)"
fi

echo; echo "pin-import-blob: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
