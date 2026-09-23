#!/usr/bin/env bash
# test-operation-proof.sh — operation-proof.sh, the device side of regalia#28 criterion 3, on emulators.
#
# test_ceremony_manifest.py proves what `record` accepts and refuses; test-ceremony-manifest.sh proves
# the wizard runs the proof right after generation. This proves the SCRIPT: that it finds the token by
# serial and not by position, signs on the token with every algorithm the ceremony provisions, takes
# the PIN only from the keyboard or a file descriptor — never argv — spends at most one PIN retry, and
# refuses by name, writing nothing, whenever the token does not produce a signature that verifies.
#
# The tokens are the pkcs11-tool shim's token model (../bin/pkcs11-tool): YubiKeys through a module
# named libykcs11*, backed by the ykman shim's per-serial keys; Nitrokeys under EMU_P11_TOKENS. Real
# openssl keys throughout. EMU_PKCS11_REAL is a tripwire: anything that would reach the real OpenSC
# binary — and through it a card attached to this machine — fails the suite instead.
set -uo pipefail
TESTS="$(cd "$(dirname "$0")" && pwd)"
OP="${CEREMONY_SCRIPTS:-$TESTS/../../scripts}/operation-proof.sh"
ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
export PATH="$TESTS/../bin:$PATH" TMPDIR="$ROOT"
export EMU_YKMAN_STATE="$ROOT/yk" EMU_P11_TOKENS="$ROOT/nk" EMU_P11_ARGV_LOG="$ROOT/argv.log"
PIN="Zq81pinX"; export EMU_P11_PIN="$PIN"
YK="$ROOT/lib/libykcs11.so.2" NK="$ROOT/lib/opensc-pkcs11.so"
mkdir -p "$ROOT/lib" "$EMU_P11_TOKENS"; : > "$YK"; : > "$NK"
printf '#!/bin/sh\necho "$*" >> "%s"\nexit 99\n' "$ROOT/real.log" > "$ROOT/lib/real"; chmod +x "$ROOT/lib/real"
export EMU_PKCS11_REAL="$ROOT/lib/real"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
# $1 = stdin (the PIN the operator types), rest = operation-proof.sh arguments. Sets $out and $rc.
op(){ local input="$1"; shift; out="$("$OP" "$@" <<< "$input" 2>&1)"; rc=$?; }
refused(){ # $1 = description, $2 = fragment, $3 = the file that must not exist
  if [ "$rc" != 0 ] && grep -qF -- "$2" <<< "$out" && { [ -z "${3:-}" ] || [ ! -e "$3" ]; }; then P "$1"
  else F "$1 (rc=$rc): $out"; fi
}

gen(){ ykman --device "$1" piv keys generate --algorithm "$2" --pin-policy ONCE --touch-policy NEVER "$3" "$ROOT/gen.pem" >/dev/null; }
gen 11110001 ECCP256 9c; gen 11110002 ECCP384 9a; gen 11110003 RSA2048 9d; gen 11110001 ECCP256 82
mkdir -p "$EMU_P11_TOKENS/AAAA0000001" "$EMU_P11_TOKENS/DENK0404144"
NKPIN="$PIN" pkcs11-tool --module "$NK" --slot 0x4 --login --pin env:NKPIN --keypairgen --key-type EC:secp256k1 --id 01 >/dev/null
NKPIN="$PIN" pkcs11-tool --module "$NK" --slot 0x0 --login --pin env:NKPIN --keypairgen --key-type EC:prime256v1 --id 01 >/dev/null
# ADR-0002's KEKs on the Nitrokey: an RSA envelope KEK (0b) and EC key-agreement keys (0c P-256, 0d P-384).
for kg in "0b rsa:2048" "0c EC:prime256v1" "0d EC:secp384r1"; do
  set -- $kg
  NKPIN="$PIN" pkcs11-tool --module "$NK" --slot 0x4 --login --pin env:NKPIN --keypairgen --key-type "$2" --id "$1" >/dev/null
done

# =================================================================================================
hdr "Every provisioned algorithm signs on the token and verifies"
for spec in "11110001 9c p256" "11110002 9a p384" "11110003 9d rsa2048" "11110001 82 p256"; do
  set -- $spec
  op "$PIN" --operation sign --backend yubikey-piv --serial "$1" --object-id "$2" --module "$YK" --out "$ROOT/yk-$1-$2.json"
  { [ "$rc" = 0 ] && grep -q "OPERATION PROOF .* object=$2 $3 signed a fresh 32-byte challenge" <<< "$out"; } \
    && P "YubiKey $1 slot $2 ($3)" || F "YubiKey $1 slot $2 ($3) did not prove (rc=$rc): $out"
done
op "$PIN" --operation sign --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 01 --module "$NK" --out "$ROOT/nk.json"
{ [ "$rc" = 0 ] && grep -q "object=01 secp256k1" <<< "$out"; } \
  && P "Nitrokey DENK0404144 id 01 (secp256k1), found by serial at slot 0x4 past a decoy at 0x0" \
  || F "the Nitrokey proof failed (rc=$rc): $out"
want="sha256:$(openssl pkey -in "$EMU_P11_TOKENS/DENK0404144/01/key.pem" -pubout -outform DER | sha256sum | awk '{print $1}')"
grep -qF "public_key_sha256=$want" <<< "$out" && P "…and it is the DENK0404144 key, not the decoy's" \
  || F "the proof is over the wrong card's key"
out="$(python3 - "$ROOT/nk.json" <<'PY'
import json, sys
print(sorted(json.load(open(sys.argv[1]))))
PY
)"
[ "$out" = "['backend', 'challenge_b64', 'class', 'device_serial', 'evidence', 'object_id', 'operation', 'public_key_der_b64', 'signature_b64']" ] \
  && P "the proof carries the challenge, the signature and the key — and no verdict" || F "unexpected proof fields: $out"

# =================================================================================================
hdr "Decrypt and key-agreement keys: a live round trip, labelled as such, with no plaintext kept"
fields(){ python3 -c 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1])))))' "$1"; }
rt_ok(){ # $1 description, $2 file, $3 operation, $4 algorithm
  if [ "$rc" = 0 ] && grep -q "object=.* $4 completed a live $3 round trip" <<< "$out" \
     && grep -q "ATTESTED AT CEREMONY TIME, not re-verifiable afterwards" <<< "$out" \
     && grep -q '"class": "live-round-trip"' "$2" && ! grep -q 'challenge_b64' "$2"; then P "$1"
  else F "$1 (rc=$rc): $out"; fi
}
op "$PIN" --operation decrypt --backend yubikey-piv --serial 11110003 --object-id 9d --module "$YK" --out "$ROOT/yk-kek.json"
rt_ok "YubiKey slot 9d (rsa2048 KEK): RSA-OAEP decrypt round trip through ykcs11" "$ROOT/yk-kek.json" decrypt rsa2048
op "$PIN" --operation decrypt --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0b --module "$NK" --out "$ROOT/nk-kek.json"
rt_ok "Nitrokey 0b (rsa2048 envelope KEK): RSA-OAEP decrypt round trip" "$ROOT/nk-kek.json" decrypt rsa2048
[ "$(fields "$ROOT/nk-kek.json")" = "backend challenge_sha256 ciphertext_b64 class device_serial evidence object_id operation public_key_der_b64" ] \
  && P "…the decrypt proof carries the ciphertext and the challenge's hash — no plaintext, no verdict" \
  || F "unexpected decrypt proof fields: $(fields "$ROOT/nk-kek.json")"
op "$PIN" --operation key-agreement --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0c --module "$NK" --out "$ROOT/nk-ka.json"
rt_ok "Nitrokey 0c (p256): ephemeral ECDH round trip" "$ROOT/nk-ka.json" key-agreement p256
op "$PIN" --operation key-agreement --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0d --module "$NK" --out "$ROOT/nk-ka384.json"
rt_ok "Nitrokey 0d (p384): ephemeral ECDH round trip" "$ROOT/nk-ka384.json" key-agreement p384
grep -q -- "--decrypt --mechanism RSA-PKCS-OAEP --hash-algorithm SHA-1 --mgf MGF1-SHA1" "$EMU_P11_ARGV_LOG" \
  && P "…the token decrypted with the daemon's OAEP parameters (SHA-1, MGF1-SHA1)" || F "the decrypt did not name the daemon's OAEP parameters"
grep -q -- "--derive --mechanism ECDH1-DERIVE" "$EMU_P11_ARGV_LOG" && P "…and derived with ECDH1-DERIVE" \
  || F "the key agreement did not use ECDH1-DERIVE"
out="$(EMU_P11_BAD_RESULT=1 "$OP" --operation decrypt --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0b \
        --module "$NK" --out "$ROOT/bad-kek.json" <<< "$PIN" 2>&1)"; rc=$?
refused "a wrong decryption on the token is refused at ceremony time" "the token's decryption does not match" "$ROOT/bad-kek.json"
out="$(EMU_P11_BAD_RESULT=1 "$OP" --operation key-agreement --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0c \
        --module "$NK" --out "$ROOT/bad-ka.json" <<< "$PIN" 2>&1)"; rc=$?
refused "a wrong ECDH secret on the token is refused at ceremony time" "the token's ECDH shared secret does not match" "$ROOT/bad-ka.json"
op "$PIN" --operation decrypt --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0c --module "$NK" --out "$ROOT/x.json"
refused "a decrypt round trip on an EC key is refused before the PIN is asked" "a decrypt round trip needs an RSA key, not p256" "$ROOT/x.json"
op "$PIN" --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0b --module "$NK" --out "$ROOT/x.json"
refused "--operation is never guessed" "--operation, --backend, --serial, --object-id and --out are all required" "$ROOT/x.json"
op "$PIN" --operation verify --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0b --module "$NK" --out "$ROOT/x.json"
refused "…and must be one the ceremony knows" "--operation must be sign, decrypt or key-agreement" "$ROOT/x.json"

# DRIFT BETWEEN THE SCRIPT AND THE TOOL: operation-proof.sh checks the mechanism proof-prepare names is
# one its --operation can use. A copy of the script beside a ceremony-manifest.py that answers a decrypt
# with a SIGNING mechanism must refuse before the PIN is asked, not sign where it was meant to decrypt.
mkdir -p "$ROOT/drift"; cp "$OP" "$ROOT/drift/operation-proof.sh"
printf '#!/usr/bin/env python3\nimport sys\nprint("ECDSA")\n' > "$ROOT/drift/ceremony-manifest.py"
out="$("$ROOT/drift/operation-proof.sh" --operation decrypt --backend nitrokey-pkcs11 --serial DENK0404144 \
        --object-id 0b --module "$NK" --out "$ROOT/x.json" <<< "$PIN" 2>&1)"; rc=$?
refused "a mechanism that does not fit the operation is refused" "unexpected mechanism 'ECDSA' for --operation decrypt" "$ROOT/x.json"

# =================================================================================================
hdr "The PIN: from the keyboard or a file descriptor, never argv, one attempt"
op "" --operation sign --backend yubikey-piv --serial 11110001 --object-id 9c --module "$YK" --pin "$PIN" --out "$ROOT/x.json"
refused "a --pin argument is refused by name" "the PIN is never taken on the command line" "$ROOT/x.json"
op "" --operation sign --backend yubikey-piv --serial 11110001 --object-id 9c --module "$YK" --out "$ROOT/x.json"
refused "an empty PIN is refused before the token is asked" "an empty PIN was entered — nothing was sent to the token" "$ROOT/x.json"
[ "$(cat "$EMU_YKMAN_STATE/11110001/pin-tries" 2>/dev/null || echo 3)" = 3 ] \
  && P "…and it spent no retry" || F "an empty PIN spent a retry"
out="$("$OP" --operation sign --backend yubikey-piv --serial 11110001 --object-id 9c --module "$YK" --pin-fd 7 --out "$ROOT/fd.json" \
        7<<< "$PIN" < /dev/null 2>&1)"; rc=$?
[ "$rc" = 0 ] && [ -s "$ROOT/fd.json" ] && P "--pin-fd supplies the PIN without a terminal" || F "--pin-fd failed (rc=$rc): $out"
op "wrong-pin" --operation sign --backend yubikey-piv --serial 11110002 --object-id 9a --module "$YK" --out "$ROOT/x.json"
refused "a wrong PIN is refused by name and the operator told a retry is gone" "CKR_PIN_INCORRECT) — ONE RETRY WAS SPENT" "$ROOT/x.json"
[ "$(cat "$EMU_YKMAN_STATE/11110002/pin-tries")" = 2 ] && P "…exactly one retry, no second attempt" \
  || F "a wrong PIN cost $((3 - $(cat "$EMU_YKMAN_STATE/11110002/pin-tries"))) retries"
echo 0 > "$EMU_YKMAN_STATE/11110002/pin-tries"
op "$PIN" --operation sign --backend yubikey-piv --serial 11110002 --object-id 9a --module "$YK" --out "$ROOT/x.json"
refused "a locked PIN is named as locked" "PIN is LOCKED (CKR_PIN_LOCKED)" "$ROOT/x.json"
echo 3 > "$EMU_YKMAN_STATE/11110002/pin-tries"
{ grep -rqF -- "$PIN" "$EMU_P11_ARGV_LOG" "$ROOT"/*.json; } \
  && F "THE PIN APPEARS on a pkcs11-tool command line or in a proof file" \
  || P "the PIN is on no pkcs11-tool command line and in no proof file"
grep -q -- "--pin env:REGALIA_OPPROOF_PIN" "$EMU_P11_ARGV_LOG" && P "…pkcs11-tool got it as env:REGALIA_OPPROOF_PIN" \
  || F "pkcs11-tool never saw the env: reference"

# =================================================================================================
hdr "A token that does not produce a verifying signature is refused, and nothing is written"
out="$(EMU_P11_BAD_SIGNATURE=1 "$OP" --operation sign --backend yubikey-piv --serial 11110001 --object-id 9c --module "$YK" \
        --out "$ROOT/bad.json" <<< "$PIN" 2>&1)"; rc=$?
refused "a signature over other data" "the token's signature does not verify" "$ROOT/bad.json"
op "$PIN" --operation sign --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0e --module "$NK" --out "$ROOT/x.json"
refused "an object with no key" "no public key at object 0e" "$ROOT/x.json"

# =================================================================================================
hdr "The token is found by serial, or not at all"
op "$PIN" --operation sign --backend yubikey-piv --serial 99999999 --object-id 9c --module "$YK" --out "$ROOT/x.json"
refused "an absent serial is refused, not replaced by whatever token is present" "serial 99999999 matches 0 PKCS#11 tokens" "$ROOT/x.json"
op "$PIN" --operation sign --backend yubikey-piv --serial 11110001 --object-id f9 --module "$YK" --out "$ROOT/x.json"
refused "the attestation slot is not a key slot" "is not a PIV key slot" "$ROOT/x.json"
op "$PIN" --operation sign --backend yubikey-piv --serial 11110001 --object-id 9c --module "$ROOT/lib/nothing.so" --out "$ROOT/x.json"
refused "a module path to nothing is refused" "does not exist" "$ROOT/x.json"

# =================================================================================================
hdr "Nothing reached the real pkcs11-tool"
[ -e "$ROOT/real.log" ] && F "THE REAL pkcs11-tool WAS INVOKED: $(head -3 "$ROOT/real.log")" \
  || P "every call was served by the emulator's token model"

printf '\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
