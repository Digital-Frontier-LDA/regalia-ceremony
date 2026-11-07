# shellcheck shell=bash
# pin-import-tpm.sh — sourced by the step-0 PIN-blob tests: a software TPM (swtpm) standing in for a
# KMS host's TPM, with the import key regalia-kms seal-hsm-pin.sh --init-import-key makes (#671: an ECC
# P-256 storage key at 0x81000101), and the host's half of --from-blob (TPM2_Import, TPM2_Load,
# TPM2_Unseal), so a test can show that a blob step 0 wrote opens to exactly the PIN, in a TPM.
#
#   pit_available                  true when swtpm and tpm2-tools are installed
#   pit_start <dir>                start the TPM, make the import key; its public key is <dir>/host.pub.pem
#   pit_open <blob>                print the unsealed bytes as hex (empty when the TPM refuses the blob)
#   pit_stop                       stop the TPM
PIT_DIR=""
pit_available(){ local t; for t in swtpm tpm2_createprimary tpm2_create tpm2_load tpm2_evictcontrol tpm2_import tpm2_unseal \
  tpm2_readpublic tpm2_flushcontext python3; do command -v "$t" >/dev/null 2>&1 || return 1; done; }
pit_flush(){ tpm2_flushcontext -t >/dev/null 2>&1; tpm2_flushcontext -s >/dev/null 2>&1; }
pit_start(){
  PIT_DIR="$1"; mkdir -p "$PIT_DIR/tpm"
  local port=$((24000 + RANDOM % 2000))
  swtpm socket --tpm2 --tpmstate "dir=$PIT_DIR/tpm" --server "type=tcp,port=$port" --ctrl "type=tcp,port=$((port+1))" \
    --flags not-need-init,startup-clear --daemon --pid "file=$PIT_DIR/tpm.pid" || return 1
  export TPM2TOOLS_TCTI="swtpm:port=$port"
  local _; for _ in $(seq 1 30); do tpm2_getcap properties-fixed >/dev/null 2>&1 && break; sleep 0.1; done
  # the template of regalia-kms seal-hsm-pin.sh --init-import-key (#671), exactly
  pit_flush; tpm2_createprimary -Q -C o -g sha256 -G ecc256:aes128cfb \
      -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' -c "$PIT_DIR/p.ctx" \
    && tpm2_create -Q -C "$PIT_DIR/p.ctx" -G ecc256:aes128cfb \
      -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda' -u "$PIT_DIR/k.pub" -r "$PIT_DIR/k.priv" \
    && pit_flush && tpm2_load -Q -C "$PIT_DIR/p.ctx" -u "$PIT_DIR/k.pub" -r "$PIT_DIR/k.priv" -c "$PIT_DIR/k.ctx" \
    && tpm2_evictcontrol -Q -C o -c "$PIT_DIR/k.ctx" 0x81000101 >/dev/null && pit_flush \
    && tpm2_readpublic -Q -c 0x81000101 -f pem -o "$PIT_DIR/host.pub.pem" \
    && tpm2_readpublic -Q -c 0x81000101 -f tss -o "$PIT_DIR/host.tpm2b"
}
pit_open(){
  local d="$PIT_DIR/open"; rm -rf "$d"; mkdir -p "$d"
  # the v2 layout: a header line, then TPM2B_PUBLIC | TPM2B_PRIVATE | TPM2B_ENCRYPTED_SECRET
  python3 -I -c '
import sys
b = open(sys.argv[1], "rb").read()
b = b[b.index(b"\n") + 1:]; o = 0
for n in ("pub", "dpriv", "seed"):
    s = int.from_bytes(b[o:o + 2], "big"); open(sys.argv[2] + "/" + n, "wb").write(b[o:o + 2 + s]); o += 2 + s
assert o == len(b), "trailing bytes"' "$1" "$d" 2>/dev/null || return 0
  tpm2_import -Q -C 0x81000101 -u "$d/pub" -i "$d/dpriv" -s "$d/seed" -r "$d/priv" 2>/dev/null && pit_flush \
    && tpm2_load -Q -C 0x81000101 -u "$d/pub" -r "$d/priv" -c "$d/o.ctx" 2>/dev/null \
    && tpm2_unseal -c "$d/o.ctx" 2>/dev/null | od -An -tx1 | tr -d ' \n'
  pit_flush; rm -rf "$d"
}
pit_stop(){ [ -n "$PIT_DIR" ] && [ -f "$PIT_DIR/tpm.pid" ] && kill "$(cat "$PIT_DIR/tpm.pid")" 2>/dev/null; rm -f "$PIT_DIR/tpm.pid"; }
