#!/usr/bin/env bash
# test-hsm-signing-key.sh — hsm-signing-key.sh and hsm-signing-cert.py: a signing key generated ON a
# SmartCard-HSM, its certificate signed by the card, its DKEK-wrapped backup, and the restore on the spare
# (regalia#554, regalia-kms#57).
#
# Runs natively (bash, openssl, python3). pkcs11-tool and sc-hsm-tool are stubbed with a card model:
# each card is a directory holding its PIN, its retry count, its DKEK domain and its keys (real openssl
# RSA keys, so every signature and certificate here is real). A card is ATTACHED when it is linked into
# $ATTACHED, which is how the tests hold one card at a time or two at once. The model's wrapped blob
# carries the domain it was made under, and a card of another domain refuses it, as the real card
# refuses a foreign-DKEK blob; on success the model's unwrap exits 1 and lands the key at another id,
# the two quirks the drills measured on the real card.
#
# NOT MODELLED: the card's real key-reference assignment and blob format. The script has not run on a card.
set -uo pipefail
TESTS="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$TESTS/../../scripts}"
KEYTOOL="$SCRIPTS/hsm-signing-key.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
FAKE="$ROOT/bin"; CARDS="$ROOT/cards"; ATTACHED="$ROOT/attached"; mkdir -p "$FAKE" "$CARDS" "$ATTACHED"
export CARDS ATTACHED ARGV_LOG="$ROOT/argv.log" CEREMONY_PKCS11_MODULE="$ROOT/opensc-pkcs11.so" TMPDIR="$ROOT"
: > "$CEREMONY_PKCS11_MODULE"; : > "$ARGV_LOG"
export PATH="$FAKE:$PATH"
PIN_SIGNING="583120" PIN_SPARE="602447" PIN_KMS="711893"

# ---- the card model ------------------------------------------------------------------------------
cat > "$FAKE/card-lib.sh" <<'LIB'
# shared by the two stubs: the attached cards, the PIN rule, the argv log
printf '%s %s\n' "$(basename "$0")" "$*" >> "$ARGV_LOG"
attached(){ local c; for c in "$ATTACHED"/*; do [ -e "$c" ] && basename "$c"; done; }
pin_ok(){ # $1 = card dir, $2 = the --pin argument
  case "$2" in env:?*) ;; "") echo "error: no --pin (would prompt) [STUB]" >&2; return 3;;
    *) echo "A LITERAL PIN IS ON THE COMMAND LINE — refused [STUB]" >&2; return 3;; esac
  local var="${2#env:}" tries; tries="$(cat "$1/pin-tries")"
  [ "$tries" -gt 0 ] || { echo "error: PKCS11 function C_Login failed: rv = CKR_PIN_LOCKED (0xa4)" >&2; return 1; }
  if [ "${!var-}" != "$(cat "$1/pin")" ]; then
    echo $((tries - 1)) > "$1/pin-tries"; echo "error: PKCS11 function C_Login failed: rv = CKR_PIN_INCORRECT (0xa0)" >&2; return 1
  fi
  echo 3 > "$1/pin-tries"
}
LIB

cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
. "$(dirname "$0")/card-lib.sh"
list=0 login=0 objects=0 keygen=0 read=0 sign=0 delete=0 slot="" id="" label="" type="" out="" in="" mech="" keytype="" pin=""
while [ $# -gt 0 ]; do
  case "$1" in
    --module) shift 2;; --list-token-slots) list=1; shift;; --login) login=1; shift;; --list-objects) objects=1; shift;;
    --keypairgen) keygen=1; shift;; --read-object) read=1; shift;; --sign) sign=1; shift;; --delete-object) delete=1; shift;;
    --slot) slot="$2"; shift 2;; --id) id="$2"; shift 2;; --label) label="$2"; shift 2;; --type) type="$2"; shift 2;;
    --output-file) out="$2"; shift 2;; --input-file) in="$2"; shift 2;; --mechanism) mech="$2"; shift 2;;
    --key-type) keytype="$2"; shift 2;; --pin) pin="$2"; shift 2;;
    *) echo "pkcs11-tool [STUB]: unsupported $1" >&2; exit 2;;
  esac
done
mapfile -t cards < <(attached)
if [ "$list" = 1 ]; then
  echo "Available slots:"; i=0
  for c in ${cards[@]+"${cards[@]}"}; do
    printf 'Slot %d (0x%x): Nitrokey Nitrokey HSM (%s) 00 00\n  token label        : SmartCard-HSM (UserPIN)\n  serial num         : %s\n' $((i*4)) $((i*4)) "$c" "$c"
    i=$((i+1))
  done; exit 0
fi
card=""; i=0
for c in ${cards[@]+"${cards[@]}"}; do [ $((i*4)) -eq $((slot)) ] && card="$c"; i=$((i+1)); done
[ -n "$card" ] || { echo "error: no token in slot $slot [STUB]" >&2; exit 1; }
C="$CARDS/$card"
if [ "$login" = 1 ]; then pin_ok "$C" "$pin" || exit $?; fi
if [ "$objects" = 1 ]; then
  for k in "$C"/keys/*/; do [ -d "$k" ] || continue
    printf 'Public Key Object; RSA 2048 bits\n  label:      %s\n  ID:         %s\n' "$(cat "$k/label" 2>/dev/null)" "$(basename "$k")"
  done; exit 0
fi
if [ "$keygen" = 1 ]; then
  [ "$login" = 1 ] && [ "$keytype" = rsa:2048 ] || { echo "error: keypairgen [STUB]" >&2; exit 1; }
  [ ! -d "$C/keys/$id" ] || { echo "error: id in use [STUB]" >&2; exit 1; }
  mkdir -p "$C/keys/$id"; openssl genrsa -out "$C/keys/$id/key.pem" 2048 2>/dev/null; printf '%s' "$label" > "$C/keys/$id/label"
  # the card assigns the next free key reference itself, whatever the id
  r=1; while grep -q "^$r " "$C/refs" 2>/dev/null; do r=$((r+1)); done; echo "$r $id" >> "$C/refs"
  echo "Key pair generated:"; exit 0
fi
[ -f "$C/keys/$id/key.pem" ] || { echo "error: object $id not found [STUB]" >&2; exit 1; }
if [ "$delete" = 1 ]; then
  [ "$login" = 1 ] || exit 1
  [ "$type" = pubkey ] && { rm -rf "${C:?}/keys/$id"; sed -i "/ $id\$/d" "$C/refs"; }
  exit 0
fi
if [ "$read" = 1 ]; then openssl pkey -in "$C/keys/$id/key.pem" -pubout -outform DER -out "$out" 2>/dev/null; exit; fi
if [ "$sign" = 1 ]; then
  [ "$login" = 1 ] && [ "$mech" = SHA256-RSA-PKCS ] || { echo "error: sign [STUB]" >&2; exit 1; }
  data="$in"; [ "${STUB_SIGN_OTHER:-0}" = 1 ] && { data="$out.other"; { cat "$in"; printf 'x'; } > "$data"; }   # signs other data than asked
  openssl dgst -sha256 -sign "$C/keys/$id/key.pem" -out "$out" "$data"; rc=$?; rm -f "$out.other"; exit "$rc"
fi
echo "pkcs11-tool [STUB]: nothing to do" >&2; exit 2
STUB

cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
. "$(dirname "$0")/card-lib.sh"
mapfile -t cards < <(attached)
[ "${#cards[@]}" -eq 1 ] || { echo "sc-hsm-tool [STUB]: ${#cards[@]} readers with a card; the default reader is a guess" >&2; exit 9; }
C="$CARDS/${cards[0]}" wrap="" unwrap="" ref="" pin=""
while [ $# -gt 0 ]; do
  case "$1" in --wrap-key) wrap="$2"; shift 2;; --unwrap-key) unwrap="$2"; shift 2;; --key-reference) ref="$2"; shift 2;;
    --pin) pin="$2"; shift 2;; *) echo "sc-hsm-tool [STUB]: unsupported $1" >&2; exit 2;; esac
done
pin_ok "$C" "$pin" || exit $?
[ -s "$C/dkek" ] || { echo "sc-hsm-tool [STUB]: no DKEK on the card (SW 6A88)" >&2; exit 1; }
if [ -n "$wrap" ]; then
  id="$(sed -n "s/^$ref //p" "$C/refs" 2>/dev/null)"
  [ -n "$id" ] || { echo "sc-hsm-tool [STUB]: SW 6A82 File not found" >&2; exit 1; }
  { printf 'SCHSM-STUB-BLOB\nDOMAIN:%s\nKEY:' "$(cat "$C/dkek")"; base64 -w0 < "$C/keys/$id/key.pem"; printf '\n'; } > "$wrap"
  echo "Key wrapped"; exit 0
fi
dom="$(sed -n 's/^DOMAIN://p' "$unwrap")"
[ "$dom" = "$(cat "$C/dkek")" ] || { echo "Error unwrapping key: SW 6A80 (the DKEK is not the blob's)"; exit 1; }
! grep -q "^$ref " "$C/refs" 2>/dev/null || { echo "sc-hsm-tool [STUB]: key reference $ref in use" >&2; exit 1; }
id=31; while [ -d "$C/keys/$id" ]; do id=$((id+1)); done          # an unwrapped key lands at another id, with no label
mkdir -p "$C/keys/$id"; sed -n 's/^KEY://p' "$unwrap" | base64 -d > "$C/keys/$id/key.pem"; : > "$C/keys/$id/label"
echo "$ref $id" >> "$C/refs"
printf 'Wrapped key contains:\n  Key blob\n  Private Key Description (PRKD)\nKey successfully imported\n'
exit 1                                                                   # measured: exits 1 even on success
STUB
chmod +x "$FAKE/pkcs11-tool" "$FAKE/sc-hsm-tool"

card(){ # card SERIAL PIN DOMAIN
  mkdir -p "$CARDS/$1/keys"; printf '%s' "$2" > "$CARDS/$1/pin"; echo 3 > "$CARDS/$1/pin-tries"; printf '%s' "$3" > "$CARDS/$1/dkek"
}
attach(){ rm -f "$ATTACHED"/*; local c; for c in "$@"; do ln -s "$CARDS/$c" "$ATTACHED/$c"; done; }
card DENK0500001 "$PIN_SIGNING" signing-domain
card DENK0500002 "$PIN_SPARE" signing-domain
card DENK0400101 "$PIN_KMS" kms-domain
OUT="$ROOT/out"; mkdir -p "$OUT"
gen(){ # gen LABEL ID [PIN] [extra args…]: generate on the signing HSM, the PIN on fd 3
  local label="$1" id="$2" pin="${3:-$PIN_SIGNING}"; shift 3 2>/dev/null || shift $#
  bash "$KEYTOOL" generate --serial DENK0500001 --id "$id" --label "$label" --subject "TEST $label, not for production" --out "$OUT" --pin-fd 3 "$@" 3<<< "$pin"
}
restore(){ # restore SERIAL LABEL PIN
  bash "$KEYTOOL" restore --serial "$1" --blob "$OUT/$2.wrapped.bin" --certificate "$OUT/$2.crt.pem" --pin-fd 3 3<<< "$3"
}
field(){ python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

hdr "1  three keys generated on the signing HSM: certificate signed by the card, wrapped backup, record"
attach DENK0500001
n=0
for spec in pcr-initrd:11 pcr-system:12 secure-boot:13; do
  label="${spec%%:*}" id="${spec##*:}"; n=$((n+1))
  out="$(gen "$label" "$id" 2>&1)"; rc=$?
  if [ "$rc" = 0 ] && grep -q "^SIGNING-KEY $label card DENK0500001 id $id ref $n " <<< "$out"; then P "$label generated at id $id, key reference $n"
  else F "$label (rc=$rc): $out"; fi
done
for label in pcr-initrd pcr-system secure-boot; do
  E="$OUT/$label.evidence.json"
  [ -s "$OUT/$label.crt.pem" ] && [ -s "$OUT/$label.wrapped.bin" ] && [ -s "$E" ] || { F "$label: an output is missing"; continue; }
  id="$(field "$E" object_id)"
  openssl pkey -in "$CARDS/DENK0500001/keys/$id/key.pem" -pubout -outform DER 2>/dev/null | cmp -s - "$OUT/$label.pub.der" \
    && P "$label: the public key written is the card's" || F "$label: the public key is not the card's"
  openssl verify -check_ss_sig -partial_chain -CAfile "$OUT/$label.crt.pem" "$OUT/$label.crt.pem" >/dev/null 2>&1 \
    && openssl x509 -in "$OUT/$label.crt.pem" -noout -pubkey | openssl pkey -pubin -outform DER | cmp -s - "$OUT/$label.pub.der" \
    && P "$label: the certificate verifies under the card's own key (openssl)" || F "$label: certificate"
  [ "$(field "$E" evidence)" = regalia.hsm-signing-key/v1 ] && [ "$(field "$E" device_serial)" = DENK0500001 ] \
    && [ "$(field "$E" wrapped_blob_sha256)" = "$(sha256sum "$OUT/$label.wrapped.bin" | cut -d' ' -f1)" ] \
    && [ "$(field "$E" public_key_sha256)" = "$(sha256sum "$OUT/$label.pub.der" | cut -d' ' -f1)" ] \
    && P "$label: the record names the card, the key and the blob" || F "$label: record $(cat "$E")"
done
[ "$(sha256sum "$OUT"/*.pub.der | cut -d' ' -f1 | sort -u | wc -l)" = 3 ] && P "three different keys" || F "the keys are not three"
text="$(openssl x509 -in "$OUT/secure-boot.crt.pem" -noout -text 2>/dev/null)"
grep -q 'Digital Signature' <<< "$text" && grep -q 'CA:FALSE' <<< "$text" \
  && P "the certificate is an end-entity signing certificate (CA:FALSE, digitalSignature)" || F "certificate extensions"
! grep -qE "$PIN_SIGNING|$PIN_SPARE|$PIN_KMS" "$ARGV_LOG" && grep -q -- '--pin env:REGALIA_PIN' "$ARGV_LOG" \
  && P "no PIN on any command line (every card command took --pin env:REGALIA_PIN)" || F "a PIN reached a command line"

hdr "2  refusals before anything is written"
before="$(ls "$OUT" | wc -l)"
attach DENK0500001 DENK0400101
out="$(gen extra 14 2>&1)"; [ $? = 1 ] && grep -q "2 tokens are attached; attach ONLY card DENK0500001" <<< "$out" \
  && P "two cards attached: refused (sc-hsm-tool would address one of them by default)" || F "two cards: $out"
attach DENK0500001
tries_before="$(cat "$CARDS/DENK0500001/pin-tries")"; : > "$ARGV_LOG"
out="$(gen extra 14 000000 2>&1)"; rc=$?
[ "$rc" = 1 ] && grep -q "refused the PIN (CKR_PIN_INCORRECT) — ONE RETRY WAS SPENT" <<< "$out" \
  && [ "$(cat "$CARDS/DENK0500001/pin-tries")" = $((tries_before - 1)) ] && ! grep -q '^sc-hsm-tool' "$ARGV_LOG" \
  && P "a wrong PIN: refused after ONE try, before any key reference was probed" || F "wrong PIN (rc=$rc): $out; argv: $(cat "$ARGV_LOG")"
echo 3 > "$CARDS/DENK0500001/pin-tries"
out="$(gen extra 11 2>&1)"; [ $? = 1 ] && grep -q "object id 11 is already in use" <<< "$out" && P "an id in use: refused" || F "id in use: $out"
out="$(gen pcr-initrd 14 2>&1)"; [ $? = 1 ] && grep -q "already exists: nothing is overwritten" <<< "$out" && P "an existing output: refused" || F "existing output: $out"
out="$(bash "$KEYTOOL" generate --serial DENK0500001 --id 14 --label x --subject x --out "$OUT" --pin "$PIN_SIGNING" 2>&1)"
[ $? = 1 ] && grep -q "a PIN is never taken on the command line" <<< "$out" && P "--pin on the command line: refused by name" || F "--pin: $out"
for bad in "--id 1" "--id zz" "--label UPPER" "--serial a/b"; do
  # shellcheck disable=SC2086  # the case is two words on purpose
  out="$(bash "$KEYTOOL" generate --serial DENK0500001 --id 14 --label ok --subject x --out "$OUT" $bad --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"
  [ $? = 1 ] && grep -q REFUSED <<< "$out" && P "bad argument $bad: refused" || F "bad argument $bad: $out"
done
: > "$CARDS/DENK0500001/dkek"
out="$(gen nodkek 15 2>&1)"; [ $? = 1 ] && grep -q "expected exactly one new key reference\|wrap-key failed" <<< "$out" \
  && [ ! -e "$OUT/nodkek.evidence.json" ] && P "a card with no DKEK: refused, no record" || F "no DKEK: $out"
[ ! -d "$CARDS/DENK0500001/keys/15" ] && grep -q "the key generated at id 15 was DELETED from card DENK0500001" <<< "$out" \
  && P "the key generated before the refusal was deleted from the signing card" || F "the refused key is still on the card: $out"
printf 'signing-domain' > "$CARDS/DENK0500001/dkek"
STUB_SIGN_OTHER=1 gen badcert 15 >/dev/null 2>&1
[ ! -d "$CARDS/DENK0500001/keys/15" ] && [ ! -e "$OUT/badcert.evidence.json" ] \
  && P "a certificate that does not verify: refused, nothing recorded, the key deleted" || F "a bad certificate was accepted or left a key"
[ "$(ls "$OUT" | wc -l)" = "$before" ] && P "no refusal wrote a file" || F "a refusal wrote: $(ls "$OUT")"

hdr "3  the backup restores and signs on the spare; a card of the KMS hosts' domain refuses it"
attach DENK0500002
for label in pcr-initrd pcr-system secure-boot; do
  out="$(restore DENK0500002 "$label" "$PIN_SPARE" 2>&1)"; rc=$?
  [ "$rc" = 0 ] && grep -q "^RESTORED .* on card DENK0500002 at id 3[0-9] ref [0-9]*: it signs for the certificate key" <<< "$out" \
    && P "$label restored on the spare (at another id, found by its public key) and it signs" || F "$label restore (rc=$rc): $out"
done
attach DENK0400101
out="$(restore DENK0400101 secure-boot "$PIN_KMS" 2>&1)"; rc=$?
[ "$rc" = 1 ] && grep -q "did not unwrap the blob (a card whose DKEK is not the blob's refuses it)" <<< "$out" && [ ! -d "$CARDS/DENK0400101/keys/31" ] \
  && P "a card holding the KMS hosts' DKEK refuses an image-key blob: it can never reach an online host" || F "KMS-domain card (rc=$rc): $out"
attach DENK0500002
out="$(restore DENK0500002 secure-boot "$PIN_SPARE" 2>&1)"
[ $? = 1 ] && grep -q "already holds this key (id 3[0-9]): a restore onto it would prove nothing about the blob" <<< "$out" \
  && P "a card that already holds the key: refused (any blob would pass)" || F "already restored: $out"
# a fresh card of the signing domain for the two wrong restores
card DENK0500003 "$PIN_SPARE" signing-domain; attach DENK0500003
out="$(bash "$KEYTOOL" restore --serial DENK0500003 --blob "$OUT/pcr-initrd.wrapped.bin" --certificate "$OUT/secure-boot.crt.pem" --pin-fd 3 3<<< "$PIN_SPARE" 2>&1)"
[ $? = 1 ] && grep -q "after the unwrap no key on card DENK0500003 has the certificate's public key" <<< "$out" \
  && P "a blob that is not the certificate's key: refused" || F "mismatched blob: $out"
out="$(STUB_SIGN_OTHER=1 restore DENK0500003 pcr-system "$PIN_SPARE" 2>&1)"
[ $? = 1 ] && grep -q "did not sign a challenge that verifies" <<< "$out" && P "a restored key that signs other data than asked: refused" || F "wrong signature: $out"
printf 'not a certificate\n' > "$ROOT/junk.pem"
out="$(bash "$KEYTOOL" restore --serial DENK0500003 --blob "$OUT/secure-boot.wrapped.bin" --certificate "$ROOT/junk.pem" --pin-fd 3 3<<< "$PIN_SPARE" 2>&1)"
[ $? = 1 ] && grep -q "is not a certificate" <<< "$out" && P "something that is not a certificate: refused" || F "junk certificate: $out"

hdr "4  the certificate tool runs isolated: a planted module decides nothing"
attach DENK0500001
mkdir -p "$ROOT/planted" "$ROOT/out-planted"
printf 'def sha256(*a, **k):\n    raise SystemExit("PLANTED hashlib")\n' > "$ROOT/planted/hashlib.py"
printf 'def b64encode(*a, **k):\n    raise SystemExit("PLANTED base64")\n' > "$ROOT/planted/base64.py"
out="$(cd "$ROOT/planted" && PYTHONPATH="$ROOT/planted" bash "$KEYTOOL" generate --serial DENK0500001 --id 16 --label planted --subject "TEST planted" \
  --out "$ROOT/out-planted" --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"; rc=$?
[ "$rc" = 0 ] && ! grep -q PLANTED <<< "$out" && openssl verify -check_ss_sig -partial_chain -CAfile "$ROOT/out-planted/planted.crt.pem" "$ROOT/out-planted/planted.crt.pem" >/dev/null 2>&1 \
  && P "a hashlib.py and a base64.py in the working directory and on PYTHONPATH are not imported" || F "planted modules (rc=$rc): $out"
grep -q 'python3 -I "$CERT_TOOL"' "$KEYTOOL" && P "the script runs its Python with -I" || F "the Python is not run isolated"
python3 -I "$SCRIPTS/hsm-signing-cert.py" check --certificate "$OUT/secure-boot.crt.pem" --public-key "$OUT/pcr-initrd.pub.der" >/dev/null 2>&1 \
  && F "check accepted a certificate for another key" || P "check refuses a certificate for another key"

printf '\n  %d passed, %d failed\n' "$pass" "$fail"; [ "$fail" -eq 0 ]
