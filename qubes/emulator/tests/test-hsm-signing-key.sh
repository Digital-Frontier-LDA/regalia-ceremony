#!/usr/bin/env bash
# test-hsm-signing-key.sh — hsm-signing-key.sh and hsm-signing-cert.py: a signing key generated ON a
# SmartCard-HSM, its certificate signed by the card, its DKEK-wrapped backup, and the restore on the spare
# (regalia#554, regalia-kms#57).
#
# Runs natively (bash, openssl, python3). pkcs11-tool and sc-hsm-tool are stubbed with a card model:
# each card is a directory holding its PIN, its retry count, its DKEK domain and its keys (real openssl
# RSA keys, so every signature and certificate here is real). A key is two objects, private and public,
# deleted separately. A card is ATTACHED when it is linked into $ATTACHED, which is how the tests hold one
# card at a time or two at once. The model's wrapped blob carries the domain it was made under, and a card
# of another domain refuses it, as the real card refuses a foreign-DKEK blob; on success the model's unwrap
# exits 1 and lands the key at another id, the two quirks the drills measured on the real card.
# MEASURED ON DENK0404380 (2026-10-03) AND MODELLED: the blob is SEQUENCE { OCTET STRING { KCV(8) || … } }, with
# the KCV sc-hsm-tool prints as "DKEK key check value"; a card of another DKEK answers the unwrap with "…failed
# with Data object not found"; deleting a key leaves its EF CE<ref>, and the unwrap refuses a reference that
# still has one; an unwrapped blob brings its EF CE<ref> along.
#
# FAULTS. A line "TOOL PATTERN" in $FAULTS makes the next call of TOOL whose arguments contain PATTERN fail
# once (the line is consumed). STUB_KEYGEN_LIES=1 makes the card generate the key and the tool exit 1.
# STUB_HANG="TOOL PATTERN" makes that call sleep, so a signal can be sent while it runs.
#
# NOT MODELLED: the card's real key-reference assignment and the key blob's encryption.
set -uo pipefail
TESTS="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$TESTS/../../scripts}"
KEYTOOL="$SCRIPTS/hsm-signing-key.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
FAKE="$ROOT/bin"; CARDS="$ROOT/cards"; ATTACHED="$ROOT/attached"; WORKTMP="$ROOT/tmp"; mkdir -p "$FAKE" "$CARDS" "$ATTACHED" "$WORKTMP"
export CARDS ATTACHED ARGV_LOG="$ROOT/argv.log" ENV_LOG="$ROOT/env.log" FAULTS="$ROOT/faults" CEREMONY_PKCS11_MODULE="$ROOT/opensc-pkcs11.so"
export CEREMONY_SIGNING_TMP="$WORKTMP"
: > "$CEREMONY_PKCS11_MODULE"; : > "$ARGV_LOG"; : > "$ENV_LOG"; : > "$FAULTS"
export PATH="$FAKE:$PATH"
# NO REAL CARD CAN BE REACHED. The two card tools the script calls are the stubs above everything else on
# PATH, and the PC/SC socket is pointed at nothing, so even a tool that slipped past them finds no reader.
export PCSCLITE_CSOCK_NAME="$ROOT/no-pcscd.sock"
PIN_SIGNING="583120" PIN_SPARE="602447" PIN_KMS="711893"
ALL="$ROOT/all-output"; : > "$ALL"

# ---- the card model ------------------------------------------------------------------------------
cat > "$FAKE/card-lib.sh" <<'LIB'
# shared by the two stubs: the attached cards, the PIN rule, the argv log, the faults
TOOL="$(basename "$0")"
printf '%s %s\n' "$TOOL" "$*" >> "$ARGV_LOG"
# a PIN in a child's environment under any name but the one the card tools are given is a leak
[ -z "${PIN+x}" ] || printf '%s: PIN is in the environment\n' "$TOOL" >> "$ENV_LOG"
attached(){ local c; for c in "$ATTACHED"/*; do [ -e "$c" ] && basename "$c"; done; }
kcv_of(){ printf '%s' "$1" | sha256sum | cut -c1-16 | tr 'a-f' 'A-F'; }   # a domain's DKEK key check value
fault(){ # consumes the first matching line of $FAULTS; true when this call must fail
  local n=0 tool pattern
  while IFS=' ' read -r tool pattern; do
    n=$((n+1))
    if [ "$tool" = "$TOOL" ] && case " $ARGS " in *"$pattern"*) true;; *) false;; esac; then sed -i "${n}d" "$FAULTS"; return 0; fi
  done < "$FAULTS"
  return 1
}
hang(){ [ -n "${STUB_HANG:-}" ] && [ "${STUB_HANG%% *}" = "$TOOL" ] && case " $ARGS " in *"${STUB_HANG#* }"*) sleep 3;; esac; return 0; }
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
ARGS="$*"; . "$(dirname "$0")/card-lib.sh"
list=0 login=0 objects=0 keygen=0 read=0 sign=0 delete=0 slot="" id="" label="" type="" out="" in="" mech="" keytype="" pin="" sigfmt=""
while [ $# -gt 0 ]; do
  case "$1" in
    --module) shift 2;; --list-token-slots) list=1; shift;; --login) login=1; shift;; --list-objects) objects=1; shift;;
    --keypairgen) keygen=1; shift;; --read-object) read=1; shift;; --sign) sign=1; shift;; --delete-object) delete=1; shift;;
    --slot) slot="$2"; shift 2;; --id) id="$2"; shift 2;; --label) label="$2"; shift 2;; --type) type="$2"; shift 2;;
    --output-file) out="$2"; shift 2;; --input-file) in="$2"; shift 2;; --mechanism) mech="$2"; shift 2;;
    --key-type) keytype="$2"; shift 2;; --pin) pin="$2"; shift 2;; --signature-format) sigfmt="$2"; shift 2;;
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
fault && { echo "error: PKCS11 function failed: rv = CKR_DEVICE_ERROR (0x30) [STUB fault]" >&2; exit 1; }
hang
if [ "$objects" = 1 ]; then
  for k in "$C"/keys/*/; do
    if [ "$type" = privkey ]; then [ -f "$k/key.pem" ] || continue; else [ -f "$k/pub.der" ] || continue; fi
    printf 'Public Key Object; RSA 2048 bits\n  label:      %s\n  ID:         %s\n' "$(cat "$k/label" 2>/dev/null)" "$(basename "$k")"
  done; exit 0
fi
if [ "$keygen" = 1 ]; then
  [ "$login" = 1 ] && case "$keytype" in rsa:2048|EC:prime256v1) true;; *) false;; esac || { echo "error: keypairgen [STUB]" >&2; exit 1; }
  [ ! -d "$C/keys/$id" ] || { echo "error: id in use [STUB]" >&2; exit 1; }
  [ -n "${STUB_KEYGEN_TYPE:-}" ] && keytype="$STUB_KEYGEN_TYPE"     # a card that makes another type than asked
  mkdir -p "$C/keys/$id"
  if [ "$keytype" = rsa:2048 ]; then openssl genrsa -out "$C/keys/$id/key.pem" 2048 2>/dev/null
  else openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$C/keys/$id/key.pem" 2>/dev/null; fi
  printf '%s' "$label" > "$C/keys/$id/label"
  openssl pkey -in "$C/keys/$id/key.pem" -pubout -outform DER -out "$C/keys/$id/pub.der" 2>/dev/null
  # the card assigns the next free key reference itself, whatever the id
  r=1; while grep -q "^$r " "$C/refs" 2>/dev/null; do r=$((r+1)); done; echo "$r $id" >> "$C/refs"
  mkdir -p "$C/ce"; sha256sum < "$C/keys/$id/pub.der" | cut -c1-64 > "$C/ce/$r"   # EF CE<ref>: the attestation of THIS key
  [ "${STUB_KEYGEN_LIES:-0}" = 1 ] && { echo "error: the answer was lost [STUB]" >&2; exit 1; }
  echo "Key pair generated:"; exit 0
fi
if [ "$delete" = 1 ]; then
  [ "$login" = 1 ] || exit 1
  [ "${STUB_DELETE_FAILS:-0}" = 1 ] && { echo "error: C_DestroyObject failed [STUB]" >&2; exit 1; }
  case "$type" in
    privkey) rm -f "$C/keys/$id/key.pem"; sed -i "/ $id\$/d" "$C/refs" 2>/dev/null;;
    pubkey)  rm -f "$C/keys/$id/pub.der" "$C/keys/$id/label";;
  esac
  rmdir "$C/keys/$id" 2>/dev/null; exit 0
fi
if [ "$read" = 1 ]; then [ -f "$C/keys/$id/pub.der" ] || { echo "error: object $id not found [STUB]" >&2; exit 1; }; cp "$C/keys/$id/pub.der" "$out"; exit; fi
if [ "$sign" = 1 ]; then
  [ "$login" = 1 ] && [ -f "$C/keys/$id/key.pem" ] || { echo "error: sign [STUB]" >&2; exit 1; }
  # the mechanism must be the key's: SHA256-RSA-PKCS for RSA, ECDSA-SHA256 with the DER format for EC
  keytext="$(openssl pkey -in "$C/keys/$id/key.pem" -noout -text 2>/dev/null)"
  if grep -q "BEGIN PRIVATE KEY" "$C/keys/$id/key.pem" && grep -q "ASN1 OID: prime256v1" <<< "$keytext"; then
    [ "$mech" = ECDSA-SHA256 ] && [ "$sigfmt" = openssl ] || { echo "error: ECDSA key, mechanism $mech format $sigfmt [STUB]" >&2; exit 1; }
  else
    [ "$mech" = SHA256-RSA-PKCS ] || { echo "error: RSA key, mechanism $mech [STUB]" >&2; exit 1; }
  fi
  sha256sum "$in" | cut -d' ' -f1 >> "$ARGV_LOG.signed"
  data="$in"; [ "${STUB_SIGN_OTHER:-0}" = 1 ] && { data="$out.other"; { cat "$in"; printf 'x'; } > "$data"; }   # signs other data than asked
  openssl dgst -sha256 -sign "$C/keys/$id/key.pem" -out "$out" "$data"; rc=$?; rm -f "$out.other"; exit "$rc"
fi
echo "pkcs11-tool [STUB]: nothing to do" >&2; exit 2
STUB

cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
ARGS="$*"; . "$(dirname "$0")/card-lib.sh"
mapfile -t cards < <(attached)
wrap="" unwrap="" ref="" pin="" reader=""
while [ $# -gt 0 ]; do
  case "$1" in --wrap-key) wrap="$2"; shift 2;; --unwrap-key) unwrap="$2"; shift 2;; --key-reference) ref="$2"; shift 2;;
    --pin) pin="$2"; shift 2;; --reader) reader="$2"; shift 2;; *) echo "sc-hsm-tool [STUB]: unsupported $1" >&2; exit 2;; esac
done
# readers as the opensc-tool stub numbers them: 0 the laptop's empty reader, then one per attached card
case "$reader" in [1-9]) ;; *) echo "sc-hsm-tool [STUB]: no --reader: OpenSC's default reader is a guess" >&2; exit 9;; esac
[ "$reader" -le "${#cards[@]}" ] || { echo "sc-hsm-tool [STUB]: no card in reader $reader" >&2; exit 9; }
C="$CARDS/${cards[$((reader - 1))]}"
if [ -z "$wrap$unwrap" ]; then                          # the status, as the real tool prints it: no PIN
  fault && { echo "sc-hsm-tool [STUB fault]: SW 6F00" >&2; exit 1; }
  printf 'Using reader with a card: Nitrokey HSM (%s)\nVersion              : 4.1\nSO-PIN tries left    : 15\nUser PIN tries left  : %s\n' "$(basename "$C")" "$(cat "$C/pin-tries")"
  if [ -s "$C/dkek" ]; then
    echo "DKEK shares          : 1"
    if [ -e "$C/dkek-pending" ]; then echo "DKEK import pending, 1 share(s) still missing"
    else echo "DKEK key check value : $(kcv_of "$(cat "$C/dkek")")"; fi
  fi
  exit 0
fi
pin_ok "$C" "$pin" || exit $?
fault && { echo "sc-hsm-tool [STUB fault]: SW 6F00" >&2; exit 1; }
hang
[ -s "$C/dkek" ] || { echo "sc-hsm-tool [STUB]: no DKEK on the card (SW 6A88)" >&2; exit 1; }
if [ -n "$wrap" ]; then
  id="$(sed -n "s/^$ref //p" "$C/refs" 2>/dev/null)"
  [ -n "$id" ] && [ -f "$C/keys/$id/key.pem" ] || { echo "sc-hsm-tool [STUB]: SW 6A82 File not found" >&2; exit 1; }
  case "$wrap" in */wrapped.bin) [ "${STUB_WRAP_EMPTY:-0}" = 1 ] && { : > "$wrap"; echo "Key wrapped"; exit 0; };; esac
  kcv="$(kcv_of "$(cat "$C/dkek")")"; [ -n "${STUB_WRAP_KCV:-}" ] && kcv="$STUB_WRAP_KCV"
  python3 "$(dirname "$0")/blob.py" make "$kcv" "$C/keys/$id/key.pem" "$C/ce/$ref" "$wrap" || exit 1
  echo "Key wrapped"; exit 0
fi
printf 'Wrapped key contains:\n  Key blob\n  Private Key Description (PRKD)\n  Certificate\n'
if [ "$(python3 "$(dirname "$0")/blob.py" kcv "$unwrap")" != "$(kcv_of "$(cat "$C/dkek")")" ] && [ "${STUB_UNWRAP_ANY:-0}" != 1 ]; then
  echo "sc_card_ctl(*, SC_CARDCTL_SC_HSM_UNWRAP_KEY, *) failed with Data object not found"; exit 1
fi
[ ! -e "$C/ce/$ref" ] || { printf 'Found existing certificate in EF with fid ce%02x. Please remove certificate first, select unused key reference or use --force.\n' "$ref"; exit 1; }
! grep -q "^$ref " "$C/refs" 2>/dev/null || { echo "sc-hsm-tool [STUB]: key reference $ref in use" >&2; exit 1; }
id=31; while [ -d "$C/keys/$id" ]; do id=$((id+1)); done          # an unwrapped key lands at another id, with no label
[ -n "${STUB_UNWRAP_AT:-}" ] && id="$STUB_UNWRAP_AT"                # ... or on an id that holds a public object already
mkdir -p "$C/keys/$id" "$C/ce"; python3 "$(dirname "$0")/blob.py" key "$unwrap" > "$C/keys/$id/key.pem"; [ -e "$C/keys/$id/label" ] || : > "$C/keys/$id/label"
python3 "$(dirname "$0")/blob.py" ce "$unwrap" > "$C/ce/$ref"     # the blob brings its EF CE<ref> along
[ -n "${STUB_UNWRAP_AT:-}" ] || [ "${STUB_UNWRAP_NO_PUB:-0}" = 1 ] || openssl pkey -in "$C/keys/$id/key.pem" -pubout -outform DER -out "$C/keys/$id/pub.der" 2>/dev/null
echo "$ref $id" >> "$C/refs"
echo "Key successfully imported"
exit 1                                                                   # measured 2026-08-06: exits 1 even on success
STUB
# the model's blob: SEQUENCE { OCTET STRING { KCV(8) || key PEM }, OCTET STRING { EF CE<ref> } }, as DER
cat > "$FAKE/blob.py" <<'PY'
import sys
def tlv(tag, body):
    n = len(body)
    return bytes([tag]) + (bytes([n]) if n < 0x80 else bytes([0x82, n >> 8, n & 0xFF])) + body
def parts(blob):
    assert blob[0] == 0x30 and blob[1] == 0x82
    body, out, o = blob[4:], [], 0
    while o < len(body):
        n = body[o + 1] if body[o + 1] < 0x80 else int.from_bytes(body[o + 2:o + 4], "big")
        h = 2 if body[o + 1] < 0x80 else 4
        out.append(body[o + h:o + h + n]); o += h + n
    return out
cmd = sys.argv[1]
if cmd == "make":
    kcv, key, ce, out = sys.argv[2:]
    data = tlv(0x30, tlv(0x04, bytes.fromhex(kcv) + open(key, "rb").read()) + tlv(0x04, open(ce, "rb").read()))
    open(out, "wb").write(data)
elif cmd == "kcv":
    print(parts(open(sys.argv[2], "rb").read())[0][:8].hex().upper())
elif cmd == "key":
    sys.stdout.buffer.write(parts(open(sys.argv[2], "rb").read())[0][8:])
elif cmd == "ce":
    sys.stdout.buffer.write(parts(open(sys.argv[2], "rb").read())[1])
PY
# mv, with one fault: STUB_MV_FAIL=NAME makes the rename onto a path ending in NAME fail
REAL_MV="$(command -v mv)"
printf '#!/bin/sh\ncase "${STUB_MV_FAIL:-}" in "") ;; *) for a in "$@"; do case "$a" in *"$STUB_MV_FAIL") echo "mv [STUB fault]" >&2; exit 1;; esac; done;; esac\nexec %s "$@"\n' "$REAL_MV" > "$FAKE/mv"
chmod +x "$FAKE/pkcs11-tool" "$FAKE/sc-hsm-tool" "$FAKE/mv"
# openssl, with one fault: STUB_VERIFY_ANYTHING=1 makes every `dgst -verify` succeed, as a broken verifier would
REAL_OPENSSL="$(command -v openssl)"
printf '#!/bin/sh
if [ "${STUB_VERIFY_ANYTHING:-0}" = 1 ]; then case " $* " in *" dgst "*"-verify"*) echo "Verified OK"; exit 0;; esac; fi
exec %s "$@"
' "$REAL_OPENSSL" > "$FAKE/openssl"
chmod +x "$FAKE/openssl"
# Tripwires: the script calls no other card tool. If it ever does, the test fails here instead of
# reaching whatever is attached to the machine running it.
cat > "$FAKE/opensc-tool" <<'STUB'
#!/usr/bin/env bash
# only `--list-readers`: an empty laptop reader first (number 0), then one reader per attached card
[ "$*" = "--list-readers" ] || { echo "TRIPWIRE: opensc-tool $*" >&2; echo "opensc-tool $*" >> "$TRIPWIRE"; exit 99; }
echo "# Detected readers (pcsc)"; echo "Nr.  Card  Features  Name"; echo "0    No              Lenovo Integrated Smart Card Reader"
i=1; for c in "$ATTACHED"/*; do [ -e "$c" ] && { echo "$i    Yes             Nitrokey HSM ($(basename "$c")) 00 00"; i=$((i+1)); }; done
STUB
chmod +x "$FAKE/opensc-tool"; export TRIPWIRE="$ROOT/tripwire"
# The card's own evidence, modelled: C.DevAut names the card; the attestation of key reference R names the card
# and the SHA-256 of the key at R; the verifier accepts it when both match what it is given.
cat > "$FAKE/devaut-read.sh" <<'STUB'
#!/usr/bin/env bash
printf 'devaut-read %s\n' "$*" >> "$ARGV_LOG"
r="" s=""; while [ $# -gt 0 ]; do case "$1" in --reader) r="$2"; shift 2;; --expect-serial) s="$2"; shift 2;; *) shift;; esac; done
i=1; for c in "$ATTACHED"/*; do [ -e "$c" ] || continue; if [ "$i" = "$r" ]; then
  [ "$(basename "$c")" = "$s" ] || { echo "not the expected card" >&2; exit 2; }
  printf 'DEVAUT_HEX=%s
' "$(printf 'DEVAUT:%s' "$s" | od -An -tx1 | tr -d ' \n')"; exit 0; fi; i=$((i+1)); done
echo "no card in reader $r" >&2; exit 2
STUB
cat > "$FAKE/attest-read.sh" <<'STUB'
#!/usr/bin/env bash
printf 'attest-read %s\n' "$*" >> "$ARGV_LOG"
r="" s="" k=""; while [ $# -gt 0 ]; do case "$1" in --reader) r="$2"; shift 2;; --expect-serial) s="$2"; shift 2;; --key-ref) k="$2"; shift 2;; *) shift;; esac; done
[ "${STUB_ATTEST_MISSING:-0}" = 1 ] && { echo "hsm-key-attestation-read: SW 6A82: no attestation (an imported key)" >&2; exit 2; }
C="$CARDS/$s"
[ -s "$C/ce/$k" ] || { printf 'hsm-key-attestation-read: EF CE%02X does not exist (SW 6A82) — no attestation at key reference %s\n' "$k" "$k" >&2; exit 2; }
digest="$(cat "$C/ce/$k")"; [ "${STUB_ATTEST_OTHER_KEY:-0}" = 1 ] && digest="$(sha256sum < "$0" | cut -c1-64)"
printf 'ATTEST_HEX=%s
' "$(printf 'ATTEST:%s:%s' "$s" "$digest" | od -An -tx1 | tr -d ' \n')"
STUB
cat > "$FAKE/attest-verify.py" <<'STUB'
import hashlib, sys
a = dict(zip(sys.argv[1::2], sys.argv[2::2]))
devaut, att = open(a["--devaut"], "rb").read().decode(), open(a["--attestation"], "rb").read().decode()
spki = open(a["--expect-spki"], "rb").read()
_, serial, digest = att.split(":")
print("DEVAUT_CHAIN=verified" if devaut == "DEVAUT:" + serial else "DEVAUT_CHAIN=failed")
print("ATTEST_SIGNATURE=verified")
match = digest == hashlib.sha256(spki).hexdigest()
print("ATTESTED_KEY_MATCHES=" + ("yes" if match else "no"))
sys.exit(0 if match and devaut == "DEVAUT:" + serial else 1)
STUB
printf 'ceremony_python_find(){ dirname "$(command -v python3)"; }\n' > "$FAKE/ceremony-python.sh"
chmod +x "$FAKE/devaut-read.sh" "$FAKE/attest-read.sh"
export HSM_DEVAUT_READ_SH="$FAKE/devaut-read.sh" HSM_KEY_ATTEST_READ_SH="$FAKE/attest-read.sh" HSM_KEY_ATTEST_VERIFY_PY="$FAKE/attest-verify.py"
export HSM_TRUST_DIR="$ROOT" HSM_CEREMONY_PYTHON_SH="$FAKE/ceremony-python.sh"
for t in opensc-explorer pkcs15-tool pkcs15-init scsh3 ykman; do
  printf '#!/bin/sh\necho "TRIPWIRE: %s was called" >&2; echo "%s $*" >> "%s"; exit 99\n' "$t" "$t" "$ROOT/tripwire" > "$FAKE/$t"; chmod +x "$FAKE/$t"
done

card(){ # card SERIAL PIN DOMAIN
  mkdir -p "$CARDS/$1/keys" "$CARDS/$1/ce"; printf '%s' "$2" > "$CARDS/$1/pin"; echo 3 > "$CARDS/$1/pin-tries"; printf '%s' "$3" > "$CARDS/$1/dkek"; : > "$CARDS/$1/refs"
}
attach(){ rm -f "$ATTACHED"/*; local c; for c in "$@"; do ln -s "$CARDS/$c" "$ATTACHED/$c"; done; }
keys_on(){ ls "$CARDS/$1/keys" | tr '\n' ' '; }
kcv(){ printf '%s' "$1" | sha256sum | cut -c1-16 | tr 'a-f' 'A-F'; }     # the KCV the ceremony record gives a domain
kcv_card(){ kcv "$(cat "$CARDS/$1/dkek")"; }
K_SIGN="$(kcv signing-domain)" K_KMS="$(kcv kms-domain)" K_ROOT="$(kcv root-domain)"
card DENK0500001 "$PIN_SIGNING" signing-domain
card DENK0500002 "$PIN_SPARE" signing-domain
card DENK0400101 "$PIN_KMS" kms-domain
OUT="$ROOT/out"; mkdir -p "$OUT"
gen(){ # gen LABEL ID [PIN] [extra args…]: generate on the signing HSM, the PIN on fd 3. Everything it prints is kept.
  local label="$1" id="$2" pin="${3:-$PIN_SIGNING}"; shift 3 2>/dev/null || shift $#
  bash "$KEYTOOL" generate --serial DENK0500001 --id "$id" --label "$label" --subject "TEST $label, not for production" --out "$OUT" --expect-kcv "$K_SIGN" --pin-fd 3 "$@" 3<<< "$pin" 2>&1 | tee -a "$ALL"
  return "${PIPESTATUS[0]}"
}
restore(){ # restore SERIAL LABEL PIN [CERT LABEL]: --expect-kcv is the card's own domain, as the ceremony record names it
  bash "$KEYTOOL" restore --serial "$1" --expect-kcv "$(kcv_card "$1")" --blob "$OUT/$2.wrapped.bin" --certificate "$OUT/${4:-$2}.crt.pem" --pin-fd 3 3<<< "$3" 2>&1 | tee -a "$ALL"
  return "${PIPESTATUS[0]}"
}
field(){ python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

hdr "1  three keys generated on the signing HSM: certificate signed by the card, wrapped backup, record"
attach DENK0500001
n=0
for spec in pcr-initrd:11 pcr-system:12 secure-boot:13; do
  label="${spec%%:*}" id="${spec##*:}"; n=$((n+1))
  out="$(gen "$label" "$id")"; rc=$?
  if [ "$rc" = 0 ] && grep -q "^SIGNING-KEY $label card DENK0500001 id $id ref $n " <<< "$out"; then P "$label generated at id $id, key reference $n"
  else F "$label (rc=$rc): $out"; fi
done
for spec in pcr-initrd:11:1 pcr-system:12:2 secure-boot:13:3; do
  IFS=: read -r label id ref <<< "$spec"
  E="$OUT/$label.evidence.json"
  [ -s "$OUT/$label.crt.pem" ] && [ -s "$OUT/$label.wrapped.bin" ] && [ -s "$E" ] || { F "$label: an output is missing"; continue; }
  cmp -s "$CARDS/DENK0500001/keys/$id/pub.der" "$OUT/$label.pub.der" && P "$label: the public key written is the card's" || F "$label: the public key is not the card's"
  openssl verify -check_ss_sig -partial_chain -CAfile "$OUT/$label.crt.pem" "$OUT/$label.crt.pem" >/dev/null 2>&1 \
    && openssl x509 -in "$OUT/$label.crt.pem" -noout -pubkey | openssl pkey -pubin -outform DER | cmp -s - "$OUT/$label.pub.der" \
    && P "$label: the certificate verifies under the card's own key (openssl)" || F "$label: certificate"
  [ "$(field "$E" evidence)" = regalia.hsm-signing-key/v2 ] && [ "$(field "$E" device_serial)" = DENK0500001 ] \
    && [ "$(field "$E" key_type)" = rsa:2048 ] && [ -n "$(field "$E" attestation_sha256)" ] && [ -n "$(field "$E" devaut_sha256)" ] \
    && [ "$(field "$E" object_id)" = "$id" ] && [ "$(field "$E" key_reference)" = "$ref" ] && [ "$(field "$E" label)" = "$label" ] \
    && [ "$(field "$E" wrapped_blob_sha256)" = "$(sha256sum "$OUT/$label.wrapped.bin" | cut -d' ' -f1)" ] \
    && [ "$(field "$E" public_key_sha256)" = "$(sha256sum "$OUT/$label.pub.der" | cut -d' ' -f1)" ] \
    && P "$label: the record names the card, the id, the key reference, the key and the blob" || F "$label: record $(cat "$E")"
  python3 "$FAKE/blob.py" key "$OUT/$label.wrapped.bin" | cmp -s - "$CARDS/DENK0500001/keys/$id/key.pem" \
    && [ "$(field "$E" dkek_kcv)" = "$K_SIGN" ] && [ "$(python3 -I "$SCRIPTS/hsm-signing-cert.py" blob-kcv --blob "$OUT/$label.wrapped.bin")" = "$K_SIGN" ] && P "$label: the blob is this key's, under the signing domain's DKEK, and the record names that KCV" || F "$label: the blob holds another key, or another KCV"
done
[ "$(sha256sum "$OUT"/*.pub.der | cut -d' ' -f1 | sort -u | wc -l)" = 3 ] && P "three different keys" || F "the keys are not three"
[ "$(for c in "$OUT"/*.crt.pem; do openssl x509 -in "$c" -noout -serial; done | sort -u | wc -l)" = 3 ] && P "three different certificate serials" || F "a constant certificate serial"
text="$(openssl x509 -in "$OUT/secure-boot.crt.pem" -noout -text 2>/dev/null)"
grep -q 'Digital Signature' <<< "$text" && grep -q 'CA:FALSE' <<< "$text" \
  && P "the certificate is an end-entity signing certificate (CA:FALSE, digitalSignature)" || F "certificate extensions"
[ -z "$(ls -A "$WORKTMP")" ] && P "no work directory is left behind" || F "left in the work area: $(ls -A "$WORKTMP")"

hdr "2  refusals: nothing is written, and no key stays on the signing card"
before="$(ls -A "$OUT" | wc -l)"; keys_before="$(keys_on DENK0500001)"
attach DENK0500001 DENK0400101
out="$(gen extra 14)"; [ $? = 1 ] && grep -q "2 tokens are attached; attach ONLY card DENK0500001" <<< "$out" \
  && P "two cards attached: refused (sc-hsm-tool would address one of them by default)" || F "two cards: $out"
attach DENK0500001
tries_before="$(cat "$CARDS/DENK0500001/pin-tries")"; : > "$ARGV_LOG"
out="$(gen extra 14 000000)"; rc=$?
[ "$rc" = 1 ] && grep -q "refused the PIN (CKR_PIN_INCORRECT) — ONE RETRY WAS SPENT" <<< "$out" \
  && [ "$(cat "$CARDS/DENK0500001/pin-tries")" = $((tries_before - 1)) ] && ! grep -q '^sc-hsm-tool .*--key-reference' "$ARGV_LOG" \
  && P "a wrong PIN: refused after ONE try, before any key reference was probed" || F "wrong PIN (rc=$rc): $out; argv: $(cat "$ARGV_LOG")"
echo 3 > "$CARDS/DENK0500001/pin-tries"
out="$(gen extra 11)"; [ $? = 1 ] && grep -q "object id 11 is already in use" <<< "$out" && P "an id in use: refused" || F "id in use: $out"
out="$(gen pcr-initrd 14)"; [ $? = 1 ] && grep -q "already exists: nothing is overwritten" <<< "$out" && P "an existing output: refused" || F "existing output: $out"
ln -s "$ROOT/nowhere" "$OUT/dangling.evidence.json"
out="$(gen dangling 14)"; [ $? = 1 ] && grep -q "dangling.evidence.json already exists" <<< "$out" && P "a dangling link where an output would go: refused before anything is generated" || F "dangling link: $out"
rm -f "$OUT/dangling.evidence.json"
mkdir "$ROOT/readonly"; chmod 555 "$ROOT/readonly"
if [ "$(id -u)" != 0 ]; then
  out="$(bash "$KEYTOOL" generate --serial DENK0500001 --id 14 --label ro --subject x --out "$ROOT/readonly" --expect-kcv "$K_SIGN" --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"
  [ $? = 1 ] && grep -q "is not writable (found before anything is generated)" <<< "$out" && P "an unwritable --out: refused before anything is generated" || F "unwritable --out: $out"
else echo "  SKIP an unwritable --out (running as root)"; fi
out="$(bash "$KEYTOOL" generate --serial DENK0500001 --id 14 --label x --subject x --out "$OUT" --pin "$PIN_SIGNING" 2>&1)"
[ $? = 1 ] && grep -q "a PIN is never taken on the command line" <<< "$out" && P "--pin on the command line: refused by name" || F "--pin: $out"
for bad in "--id 1" "--id zz" "--label UPPER" "--serial a/b"; do
  # shellcheck disable=SC2086  # the case is two words on purpose
  out="$(bash "$KEYTOOL" generate --serial DENK0500001 --id 14 --label ok --subject x --out "$OUT" --expect-kcv "$K_SIGN" $bad --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"
  [ $? = 1 ] && grep -q REFUSED <<< "$out" && P "bad argument $bad: refused" || F "bad argument $bad: $out"
done
echo "pkcs11-tool --list-objects --type pubkey" > "$FAULTS"
out="$(gen extra 14)"; [ $? = 1 ] && grep -q "did not list its public keys: whether id 14 is free is not known" <<< "$out" \
  && P "a listing that fails is not an empty card: refused" || F "failed listing: $out"
: > "$FAULTS"
# every step after the key was asked for: refused, the key deleted and that said, no file kept
refuse_after_keygen(){ # refuse_after_keygen WHAT REASON [env assignments…]
  local what="$1" reason="$2" out rc; shift 2
  out="$(env "$@" bash -c 'gen(){ :; }; exec bash "$0" generate --serial DENK0500001 --id 15 --label refused --subject "TEST refused" --out "$1" --expect-kcv "$3" --pin-fd 3 3<<< "$2"' \
          "$KEYTOOL" "$OUT" "$PIN_SIGNING" "$K_SIGN" 2>&1 | tee -a "$ALL")"; rc=$?
  if grep -q -- "$reason" <<< "$out" && grep -q "the key generated at id 15 was DELETED from card DENK0500001" <<< "$out" \
     && [ ! -d "$CARDS/DENK0500001/keys/15" ] && ! grep -q refused <<< "$(ls "$OUT")" && ! grep -q '^\.' <<< "$(ls -A "$OUT")"; then P "$what: refused, the key deleted and announced, no file kept"
  else F "$what: $out; card keys: $(keys_on DENK0500001); out: $(ls -A "$OUT")"; fi
  : > "$FAULTS"
}
: > "$CARDS/DENK0500001/dkek"
: > "$ARGV_LOG"; out="$(gen nodkek 15)"; rc=$?
[ "$rc" = 1 ] && grep -q "card DENK0500001 holds no complete DKEK" <<< "$out" && ! grep -q '^pkcs11-tool .*--login' "$ARGV_LOG" \
  && [ ! -d "$CARDS/DENK0500001/keys/15" ] && P "a card with no DKEK: refused before the PIN and before anything is generated" || F "no DKEK (rc=$rc): $out"
printf 'signing-domain' > "$CARDS/DENK0500001/dkek"
touch "$CARDS/DENK0500001/dkek-pending"
out="$(gen pending 15)"; rc=$?
[ "$rc" = 1 ] && grep -q "holds no complete DKEK (no key check value; an import may be pending)" <<< "$out" && [ ! -d "$CARDS/DENK0500001/keys/15" ] \
  && P "a DKEK whose import is still pending: refused (it has no key check value yet)" || F "pending DKEK (rc=$rc): $out"
rm -f "$CARDS/DENK0500001/dkek-pending"
out="$(bash "$KEYTOOL" generate --serial DENK0500001 --id 15 --label x --subject x --out "$OUT" --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"
[ $? = 1 ] && grep -q -- "--expect-kcv is required" <<< "$out" && P "no --expect-kcv: refused (the domain is named, never taken from the card)" || F "no --expect-kcv: $out"
out="$(gen otherdomain 15 "$PIN_SIGNING" --expect-kcv "$K_KMS")"; rc=$?
[ "$rc" = 1 ] && grep -q "card DENK0500001 holds DKEK $K_SIGN, not $K_KMS, the domain --expect-kcv names" <<< "$out" && [ ! -d "$CARDS/DENK0500001/keys/15" ] \
  && P "a card whose DKEK is not the domain the record names: refused before anything is generated" || F "wrong domain (rc=$rc): $out"
for bad in 12AB "$K_SIGN"00 "${K_SIGN%?}G"; do
  out="$(bash "$KEYTOOL" generate --serial DENK0500001 --id 15 --label x --subject x --out "$OUT" --expect-kcv "$bad" --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"
  [ $? = 1 ] && grep -q -- "--expect-kcv is sixteen hex digits" <<< "$out" && P "--expect-kcv $bad: refused" || F "--expect-kcv $bad: $out"
done
refuse_after_keygen "the card generates the key and the tool's answer is lost" "did not report a generated key" STUB_KEYGEN_LIES=1
refuse_after_keygen "a certificate that does not verify" "does not verify" STUB_SIGN_OTHER=1
refuse_after_keygen "an empty wrapped blob" "wrap-key failed for key reference" STUB_WRAP_EMPTY=1
refuse_after_keygen "a blob that names another DKEK than the card's" "the blob does not name DKEK $K_SIGN" STUB_WRAP_KCV=0011223344556677
refuse_after_keygen "the last file cannot be put in place (the blob was already there)" "cannot put .*refused.evidence.json in place" STUB_MV_FAIL=/refused.evidence.json
refuse_after_keygen "the third file cannot be put in place" "cannot put .*refused.wrapped.bin in place" STUB_MV_FAIL=/refused.wrapped.bin
echo "pkcs11-tool --read-object" > "$FAULTS"
refuse_after_keygen "the public key cannot be read" "cannot read the public key of id 15"
echo "pkcs11-tool tbs.der" > "$FAULTS"
refuse_after_keygen "the card does not sign the certificate" "the card did not sign the certificate"
# a key that did not wrap before generating (both probes failed alike) and does after: TWO new references,
# and which is the new key's cannot be told. Refused.
printf 'sc-hsm-tool --key-reference 1 --pin\nsc-hsm-tool --key-reference 1 --pin\n' > "$FAULTS"
out="$(gen tworefs 15)"; rc=$?
[ "$rc" = 1 ] && grep -q "2 key references wrap but the card lists 3 private keys" <<< "$out" && [ ! -d "$CARDS/DENK0500001/keys/15" ] \
  && P "a key reference that fails both probes: refused before generating (references counted against private keys)" || F "two new references (rc=$rc): $out"
# N2: the same key's reference failing both probes BEFORE, and the new key's both probes AFTER: without the count,
# the old key's reference would be taken for the new one and its blob recorded
printf 'sc-hsm-tool --key-reference 1 --pin\nsc-hsm-tool --key-reference 1 --pin\n' > "$FAULTS"
out="$(gen fourfaults 15)"; rc=$?
[ "$rc" = 1 ] && ! grep -q SIGNING-KEY <<< "$out" && [ ! -e "$OUT/fourfaults.evidence.json" ] && [ ! -d "$CARDS/DENK0500001/keys/15" ] \
  && P "an existing key's reference unseen before generating: refused, no record names it" || F "four faults (rc=$rc): $out"

: > "$FAULTS"
# one probe of an EXISTING key fails before generating, and one of the new key after: without the second
# probe the old key's reference would be taken for the new one, and its blob recorded as the new key's
printf 'sc-hsm-tool --key-reference 1 \n' > "$FAULTS"
refuse_after_keygen_or_before(){ :; }
out="$(gen twofaults 15)"; rc=$?
[ "$rc" = 1 ] && grep -q "two different answers about which key references wrap" <<< "$out" && [ ! -d "$CARDS/DENK0500001/keys/15" ] \
  && P "a probe that fails once: refused (the answers are compared), nothing generated" || F "one probe fault (rc=$rc): $out; keys $(keys_on DENK0500001)"
: > "$FAULTS"
# a delete that fails is said, loudly, and where the operator sees it
out="$(STUB_SIGN_OTHER=1 STUB_DELETE_FAILS=1 gen stuck 15)"
grep -q "THE KEY GENERATED AT id 15 IS STILL ON CARD DENK0500001 and nothing recorded it: delete it" <<< "$out" && [ -d "$CARDS/DENK0500001/keys/15" ] \
  && P "a key that could not be deleted is announced as STILL ON CARD" || F "failed delete: $out"
rm -rf "$CARDS/DENK0500001/keys/15"; sed -i '/ 15$/d' "$CARDS/DENK0500001/refs"
# a signal while a card command runs with its output discarded: the trap's message still reaches the operator
for sig in TERM INT HUP; do
  : > "$ARGV_LOG"
  # a background job starts with SIGINT ignored, which bash cannot undo: python restores the default first
  STUB_HANG="sc-hsm-tool wrapped.bin" python3 -c 'import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execvp("bash", ["bash"] + sys.argv[1:])' \
    "$KEYTOOL" generate --serial DENK0500001 --id 15 --label signal --subject "TEST signal" --out "$OUT" --expect-kcv "$K_SIGN" --pin-fd 3 3<<< "$PIN_SIGNING" > "$ROOT/sig.out" 2>&1 &
  bg=$!
  for _ in $(seq 1 150); do grep -q 'wrapped.bin --key-reference' "$ARGV_LOG" && break; sleep 0.1; done
  kill -"$sig" "$bg" 2>/dev/null; wait "$bg" 2>/dev/null
  cat "$ROOT/sig.out" >> "$ALL"
  grep -q "the key generated at id 15 was DELETED from card DENK0500001" "$ROOT/sig.out" && [ ! -d "$CARDS/DENK0500001/keys/15" ] && ! grep -q signal <<< "$(ls -A "$OUT")" \
    && P "SIG$sig during the final wrap: the key is deleted and the operator is told" || F "SIG$sig: $(cat "$ROOT/sig.out"); keys $(keys_on DENK0500001)"
  : > "$ARGV_LOG"
done
[ "$(ls -A "$OUT" | wc -l)" = "$before" ] && [ "$(keys_on DENK0500001)" = "$keys_before" ] \
  && P "after every refusal: the same files in --out and the same keys on the card as before" || F "left behind: $(ls -A "$OUT") / $(keys_on DENK0500001)"
[ -z "$(ls -A "$WORKTMP")" ] && P "no work directory is left behind by a refusal or a signal" || F "left in the work area: $(ls -A "$WORKTMP")"

hdr "3  the backup restores and signs on the spare; a card of the KMS hosts' domain refuses it"
attach DENK0500002
for label in pcr-initrd pcr-system secure-boot; do
  out="$(restore DENK0500002 "$label" "$PIN_SPARE")"; rc=$?
  [ "$rc" = 0 ] && grep -q "^RESTORED .* on card DENK0500002 at id 3[0-9] ref [0-9]*: it signs for the certificate key" <<< "$out" \
    && P "$label restored on the spare (at another id, found by its public key) and it signs" || F "$label restore (rc=$rc): $out"
done
attach DENK0400101
: > "$ARGV_LOG"; out="$(restore DENK0400101 secure-boot "$PIN_KMS")"; rc=$?
[ "$rc" = 1 ] && grep -q "the blob was wrapped under DKEK $K_SIGN and card DENK0400101 holds $K_KMS: it cannot restore here" <<< "$out" \
  && [ -z "$(keys_on DENK0400101)" ] && ! grep -q -- '--unwrap-key' "$ARGV_LOG" \
  && P "a card holding the KMS hosts' DKEK: refused by the blob's KCV, before any unwrap" || F "KMS-domain card (rc=$rc): $out"
out="$(python3 "$FAKE/blob.py" kcv "$OUT/secure-boot.wrapped.bin")"
[ "$out" = "$K_SIGN" ] && P "the blob's header names the signing domain's KCV" || F "blob KCV: $out"
# a reference whose key was deleted keeps its EF CE<ref>: restore skips it rather than fail on it
card DENK0500004 "$PIN_SPARE" signing-domain; echo stale > "$CARDS/DENK0500004/ce/1"; attach DENK0500004
out="$(restore DENK0500004 pcr-initrd "$PIN_SPARE")"; rc=$?
[ "$rc" = 0 ] && grep -q "^RESTORED .* on card DENK0500004 at id 3[0-9] ref 2: it signs" <<< "$out" && [ "$(cat "$CARDS/DENK0500004/ce/1")" = stale ] \
  && P "a left-over EF CE01 of a deleted key: the restore goes to reference 2 and leaves CE01 alone" || F "left-over CE file (rc=$rc): $out"
attach DENK0500002
out="$(restore DENK0500002 secure-boot "$PIN_SPARE")"
[ $? = 1 ] && grep -q "already holds this key (id 3[0-9]): a restore onto it would prove nothing about the blob" <<< "$out" \
  && P "a card that already holds the key: refused (any blob would pass)" || F "already restored: $out"
# THE CASE THE READ FOUND: the spare already holds key A; the listing (or one read) fails once; a blob of key B
# is offered with A's certificate. It must not come back as "restored".
spare_keys="$(keys_on DENK0500002)"
for fault in "pkcs11-tool --list-objects --type pubkey" "pkcs11-tool --read-object"; do
  echo "$fault" > "$FAULTS"
  out="$(restore DENK0500002 pcr-initrd "$PIN_SPARE" secure-boot)"; rc=$?
  [ "$rc" = 1 ] && grep -q "is not known" <<< "$out" && ! grep -q RESTORED <<< "$out" && [ "$(keys_on DENK0500002)" = "$spare_keys" ] \
    && P "another key's blob after one failed ${fault##*--}: refused, nothing unwrapped" || F "wrong blob after a fault (rc=$rc): $out; keys $(keys_on DENK0500002)"
  : > "$FAULTS"
done
# a fresh card of the signing domain for the wrong restores: each is refused AND leaves no key on the card
# Each refused restore below leaves its EF CE<ref> behind, as the real card does, so each next one goes one
# key reference further: 1, 2, 3, then 4 once reference 3's undeletable key is cleared by hand.
card DENK0500003 "$PIN_SPARE" signing-domain; attach DENK0500003
out="$(restore DENK0500003 pcr-initrd "$PIN_SPARE" secure-boot)"
[ $? = 1 ] && grep -q "after the unwrap no NEW key on card DENK0500003 has the certificate's public key: the blob is not that key's" <<< "$out" \
  && grep -q "the key the refused restore had unwrapped (key reference 1, id 31) was DELETED from card DENK0500003" <<< "$out" && [ -z "$(keys_on DENK0500003)" ] \
  && P "a blob that is not the certificate's key: refused, and the key it unwrapped is deleted and announced" || F "mismatched blob: $out; keys $(keys_on DENK0500003)"
out="$(STUB_SIGN_OTHER=1 restore DENK0500003 pcr-system "$PIN_SPARE")"
[ $? = 1 ] && grep -q "did not sign a challenge that verifies" <<< "$out" && grep -q "was DELETED from card DENK0500003" <<< "$out" && [ -z "$(keys_on DENK0500003)" ] \
  && P "a restored key that signs other data than asked: refused, and deleted" || F "wrong signature: $out; keys $(keys_on DENK0500003)"
out="$(STUB_SIGN_OTHER=1 STUB_DELETE_FAILS=1 restore DENK0500003 pcr-system "$PIN_SPARE")"
grep -q "A KEY IS STILL AT KEY REFERENCE 3 ON CARD DENK0500003 after a refused restore (deleting id 31 did not remove it)" <<< "$out" \
  && P "a refused restore whose key cannot be deleted says the key is still there" || F "refused restore, failed delete: $out"
rm -rf "$CARDS/DENK0500003/keys/31"; : > "$CARDS/DENK0500003/refs"
out="$(STUB_UNWRAP_NO_PUB=1 restore DENK0500003 pcr-initrd "$PIN_SPARE" secure-boot)"
[ $? = 1 ] && grep -q "the key the refused restore had unwrapped (key reference 4, id 31) was DELETED" <<< "$out" && [ -z "$(keys_on DENK0500003)" ] \
  && P "an unwrapped key with NO public object is still found and deleted after a refusal" || F "unwrap without a public object: $out; keys $(keys_on DENK0500003)"
mkdir -p "$CARDS/DENK0500003/keys/40"; cp "$OUT/pcr-system.pub.der" "$CARDS/DENK0500003/keys/40/pub.der"     # an unrelated public object, no private key
out="$(STUB_UNWRAP_AT=40 restore DENK0500003 pcr-initrd "$PIN_SPARE" secure-boot)"
[ $? = 1 ] && grep -q "was DELETED" <<< "$out" && [ ! -f "$CARDS/DENK0500003/keys/40/key.pem" ] && [ -f "$CARDS/DENK0500003/keys/40/pub.der" ] \
  && ! grep -q "^1 " "$CARDS/DENK0500003/refs" \
  && P "a key unwrapped onto an id holding an unrelated public object: the private key is deleted, the public object kept" || F "unwrap onto an existing id: $out; $(ls "$CARDS/DENK0500003/keys/40")"
rm -rf "$CARDS/DENK0500003/keys/40"; : > "$CARDS/DENK0500003/refs"
python3 -I "$SCRIPTS/hsm-signing-cert.py" tbs --public-key "$OUT/secure-boot.pub.der" --subject "TEST forged" --days 30 --serial-hex 1234567890abcdef12 --out "$ROOT/forged.tbs"
openssl genrsa -out "$ROOT/other.key" 2048 2>/dev/null; openssl dgst -sha256 -sign "$ROOT/other.key" -out "$ROOT/forged.sig" "$ROOT/forged.tbs"
python3 -I "$SCRIPTS/hsm-signing-cert.py" assemble --tbs "$ROOT/forged.tbs" --signature "$ROOT/forged.sig" --out "$OUT/forged.crt.pem"
out="$(bash "$KEYTOOL" restore --serial DENK0500003 --expect-kcv "$K_SIGN" --blob "$OUT/secure-boot.wrapped.bin" --certificate "$OUT/forged.crt.pem" --pin-fd 3 3<<< "$PIN_SPARE" 2>&1)"
[ $? = 1 ] && grep -q "does not verify under its own key" <<< "$out" && [ -z "$(keys_on DENK0500003)" ] \
  && P "a certificate for the right key that its key did not sign: refused before anything is unwrapped" || F "forged certificate: $out"
rm -f "$OUT/forged.crt.pem"
out="$(STUB_VERIFY_ANYTHING=1 STUB_SIGN_OTHER=1 restore DENK0500003 pcr-system "$PIN_SPARE")"
[ $? = 1 ] && grep -q "the signature check accepted other data: the check proves nothing" <<< "$out" && [ -z "$(keys_on DENK0500003)" ] \
  && P "a verifier that accepts any signature is caught by the wrong-data control" || F "broken verifier: $out; keys $(keys_on DENK0500003)"
: > "$ARGV_LOG.signed"
for _ in 1 2; do restore DENK0500003 pcr-system "$PIN_SPARE" >/dev/null; rm -rf "$CARDS/DENK0500003/keys/"*; : > "$CARDS/DENK0500003/refs"; done
[ "$(wc -l < "$ARGV_LOG.signed")" = 2 ] && [ "$(sort -u "$ARGV_LOG.signed" | wc -l)" = 2 ] \
  && P "each restore signs a fresh challenge (two restores, two different challenges)" || F "the challenge is not fresh: $(cat "$ARGV_LOG.signed")"
printf 'not a certificate\n' > "$OUT/junk.crt.pem"
out="$(restore DENK0500003 secure-boot "$PIN_SPARE" junk)"
[ $? = 1 ] && grep -q "is not a certificate" <<< "$out" && P "something that is not a certificate: refused" || F "junk certificate: $out"
rm -f "$OUT/junk.crt.pem"

hdr "4  the PIN and the environment"
! grep -qE "$PIN_SIGNING|$PIN_SPARE|$PIN_KMS" "$ARGV_LOG" "$ALL" && P "no PIN on any command line, and none in anything the script printed" || F "a PIN was printed or reached a command line"
: > "$ARGV_LOG"; : > "$ENV_LOG"; attach DENK0500001
out="$(PIN=inherited REGALIA_PIN=inherited gen envpin 16)"; rc=$?
[ "$rc" = 0 ] && [ ! -s "$ENV_LOG" ] && grep -q -- '--pin env:REGALIA_PIN' "$ARGV_LOG" \
  && P "a caller's exported PIN variable does not make the script export the real one to its children" || F "PIN in a child's environment (rc=$rc): $(sort -u "$ENV_LOG")"
! grep -rqE "$PIN_SIGNING|$PIN_SPARE" "$OUT" "$WORKTMP" 2>/dev/null && P "no PIN in any file the script wrote" || F "a PIN is in a file"
grep -q '^unset PIN REGALIA_PIN OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES$' "$KEYTOOL" && ! grep -qE '^[[:space:]]*export[[:space:]].*\bPIN\b' "$KEYTOOL" \
  && P "the script drops an inherited PIN and OPENSSL_CONF, and exports no PIN" || F "the environment is not cleaned"
printf 'openssl_conf = nope\n' > "$ROOT/hostile.cnf"
out="$(OPENSSL_CONF="$ROOT/hostile.cnf" gen conf 17)"; [ $? = 0 ] && P "a caller's OPENSSL_CONF is not inherited by the script's openssl" || F "OPENSSL_CONF: $out"

modes="$(stat -c '%a' "$OUT"/*.crt.pem "$OUT"/*.pub.der "$OUT"/*.wrapped.bin "$OUT"/*.evidence.json | sort -u | tr '\n' ' ')"
[ "$modes" = "600 " ] && P "every file the script wrote is 0600 (umask 077)" || F "file modes: $modes"
[ "$(grep -cE '^(p11|p11_pin|schsm_pin)\(\)\{ .*timeout 60 ' "$KEYTOOL")" = 3 ] && P "every card command is bounded by timeout 60" || F "a card command is not bounded"

hdr "5  the certificate tool runs isolated and accepts only its own kind of certificate"
mkdir -p "$ROOT/planted" "$ROOT/out-planted"
printf 'def sha256(*a, **k):\n    raise SystemExit("PLANTED hashlib")\n' > "$ROOT/planted/hashlib.py"
printf 'def b64encode(*a, **k):\n    raise SystemExit("PLANTED base64")\n' > "$ROOT/planted/base64.py"
out="$(cd "$ROOT/planted" && PYTHONPATH="$ROOT/planted" bash "$KEYTOOL" generate --serial DENK0500001 --id 18 --label planted --subject "TEST planted" --expect-kcv "$K_SIGN" \
  --out "$ROOT/out-planted" --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"; rc=$?
[ "$rc" = 0 ] && ! grep -q PLANTED <<< "$out" && openssl verify -check_ss_sig -partial_chain -CAfile "$ROOT/out-planted/planted.crt.pem" "$ROOT/out-planted/planted.crt.pem" >/dev/null 2>&1 \
  && P "a hashlib.py and a base64.py in the working directory and on PYTHONPATH are not imported" || F "planted modules (rc=$rc): $out"
# every Python the script runs: its own tool under -I, and the attestation verifier under -Es with the
# interpreter that has pycvc (the one line that names "$py_bin/python3")
grep -q 'python3 -I "$CERT_TOOL"' "$KEYTOOL" && [ "$(grep -c 'python3' "$KEYTOOL")" = "$(grep -c 'python3 -I "$CERT_TOOL"\|for t in pkcs11-tool\|"$py_bin/python3" -Es "$ATTEST_PY"\|\[ -x "$py_bin/python3" \]' "$KEYTOOL")" ] \
  && P "every Python the script runs is python3 -I on its own tool, or -Es on the attestation verifier" || F "a Python call that is not isolated"
CT=(python3 -I "$SCRIPTS/hsm-signing-cert.py")
"${CT[@]}" check --certificate "$OUT/secure-boot.crt.pem" --public-key "$OUT/pcr-initrd.pub.der" >/dev/null 2>&1 \
  && F "check accepted a certificate for another key" || P "check refuses a certificate for another key"
python3 - "$SCRIPTS/hsm-signing-cert.py" "$OUT/secure-boot.crt.pem" "$OUT/secure-boot.pub.der" "$ROOT" <<'EOF' && P "check refuses what is not this tool's certificate: wrong tags, another inner algorithm, RSA-1024, a 2041-bit modulus" || F "the certificate check accepted a crafted structure"
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("cert", sys.argv[1]); c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
tbs, spki, sig = c.certificate_parts(c.unpem(open(sys.argv[2]).read()))
assert spki == open(sys.argv[3], "rb").read()
_, body, _ = c.read_tlv(tbs)
fields, off = [], 0
while off < len(body):
    _, _, nxt = c.read_tlv(body, off); fields.append(body[off:nxt]); off = nxt
def refused(parts, why):
    der = c.seq(c.seq(*parts), c.seq(c.SHA256_WITH_RSA), c.tlv(0x03, b"\0" + sig))
    try:
        c.certificate_parts(der)
    except c.Refused as e:
        assert why in str(e), (why, str(e)); return
    raise SystemExit("accepted: " + why)
refused([c.tlv(0x04, f) for f in fields], "not the ones this tool writes")                    # eight OCTET STRINGs
refused(fields[1:] + [fields[6]], "not the ones this tool writes")                             # no version, a second key in seventh place
sha1 = c.seq(bytes.fromhex("06092a864886f70d0101050500"))
refused(fields[:2] + [sha1] + fields[3:], "another signature algorithm inside than outside")
other = c.seq(c.tlv(0x31, c.seq(c.tlv(0x06, bytes.fromhex("550403")), c.tlv(0x0C, b"someone else"))))
refused(fields[:3] + [other] + fields[4:], "not self-signed")
def rsa(bits):
    der = subprocess.run(["openssl", "genrsa", str(bits)], capture_output=True, check=True).stdout
    return subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=der, capture_output=True, check=True).stdout
refused(fields[:6] + [rsa(1024)] + fields[7:], "not RSA-2048")
assert c.rsa_public_key(rsa(2048)) == 2048
# a modulus of 2041 bits in 256 bytes is not RSA-2048
_, sb, _ = c.read_tlv(spki); _, alg, o = c.read_tlv(sb); _, bits, _ = c.read_tlv(sb, o); _, key, _ = c.read_tlv(bits[1:]); _, mod, o2 = c.read_tlv(key)
short = bytes([0, 0x01]) + mod.lstrip(b"\0")[1:]
forged = c.seq(c.seq(alg), c.tlv(0x03, b"\0" + c.seq(c.tlv(0x02, short), key[o2:])))
assert c.rsa_public_key(forged) == 2041, c.rsa_public_key(forged)
refused(fields[:6] + [forged] + fields[7:], "not RSA-2048")
EOF
# A PATH stub does not see a card reached through a LIBRARY: pyscard's `smartcard`, python-pkcs11, or a
# PKCS#11 module loaded by openssl through an engine or a provider. Neither file loads any of them: the
# Python imports the standard library only (the list below is all of it), and every openssl call here works
# on files with no engine, under an environment the script cleared of OPENSSL_CONF.
imports="$(grep -oE '^[[:space:]]*(import|from)[[:space:]]+[A-Za-z0-9_.]+' "$SCRIPTS/hsm-signing-cert.py" | awk '{print $2}' | sort -u | tr '\n' ' ')"
[ "$imports" = "argparse base64 datetime hashlib json os re subprocess sys tempfile " ] && ! grep -qE '__import__|importlib|-engine|-provider|python3 -I -c|python3 -c' "$KEYTOOL" "$SCRIPTS/hsm-signing-cert.py" \
  && P "the Python imports exactly ten standard modules and nothing is loaded by name; no openssl engine or provider" || F "imports: $imports"
hdr "6  an ECDSA P-256 key (the root's type under regalia-kms#156, before D28): the card's own attestation, and a separate DKEK domain"
card DENK0600001 "$PIN_SIGNING" root-domain
card DENK0600002 "$PIN_SPARE" root-domain
attach DENK0600001
groot(){ # groot LABEL ID [extra]: generate on the root HSM
  local label="$1" id="$2"; shift 2
  bash "$KEYTOOL" generate --serial DENK0600001 --id "$id" --label "$label" --subject "TEST $label, not for production" --out "$OUT" --expect-kcv "$K_ROOT" \
    --key-type ec:prime256v1 --pin-fd 3 "$@" 3<<< "$PIN_SIGNING" 2>&1 | tee -a "$ALL"
  return "${PIPESTATUS[0]}"
}
out="$(groot root 20)"; rc=$?
E="$OUT/root.evidence.json"
if [ "$rc" = 0 ] && [ -s "$E" ]; then
  certtext="$(openssl x509 -in "$OUT/root.crt.pem" -noout -text 2>/dev/null)"
  grep -q "Signature Algorithm: ecdsa-with-SHA256" <<< "$certtext" && grep -q "ASN1 OID: prime256v1" <<< "$certtext" \
    && openssl verify -check_ss_sig -partial_chain -CAfile "$OUT/root.crt.pem" "$OUT/root.crt.pem" >/dev/null 2>&1 \
    && P "a P-256 key generated on the card; its certificate is ecdsa-with-SHA256 and verifies under the card's key" || F "P-256 certificate: $out"
  [ "$(field "$E" key_type)" = ec:prime256v1 ] && grep -q "the card attests it generated THIS key" <<< "$out" \
    && [ "$(field "$E" attestation_sha256)" = "$(python3 -c 'import base64,hashlib,json,sys; print(hashlib.sha256(base64.b64decode(json.load(open(sys.argv[1]))["attestation_b64"])).hexdigest())' "$E")" ] \
    && P "the record carries the key type, C.DevAut and the attestation that this key was generated on the card" || F "root record: $(cat "$E")"
  grep -q "ECDSA-SHA256" "$ARGV_LOG" && grep -q -- "--signature-format openssl" "$ARGV_LOG" \
    && P "the card signed with ECDSA-SHA256, in DER (--signature-format openssl)" || F "the EC mechanism was not used"
else F "generating the P-256 root failed (rc=$rc): $out"; fi
# the reader: the laptop's own empty reader is number 0, the card's is found by its serial
grep -q "^attest-read --reader 1 --expect-serial DENK0600001 --key-ref " "$ARGV_LOG" && ! grep -q "^attest-read --reader 0 " "$ARGV_LOG" \
  && P "the attestation is read from the reader that holds the card, found by serial (not the laptop's reader 0)" || F "attestation reader: $(grep -E '^(attest|devaut)-read' "$ARGV_LOG" | tail -3)"
# restore on the spare: the EC challenge, with its wrong-data control
attach DENK0600002
out="$(bash "$KEYTOOL" restore --serial DENK0600002 --expect-kcv "$K_ROOT" --blob "$OUT/root.wrapped.bin" --certificate "$OUT/root.crt.pem" --pin-fd 3 3<<< "$PIN_SPARE" 2>&1)"; rc=$?
[ "$rc" = 0 ] && grep -q "^RESTORED .* it signs for the certificate key" <<< "$out" && P "the root's blob restores on its spare and signs (ECDSA) for the certificate's key" || F "root restore (rc=$rc): $out"
# refuse: a card of ANOTHER domain (the image-signing pair's, the KMS hosts') must not unwrap it
for other in DENK0500002:"$PIN_SPARE" DENK0400101:"$PIN_KMS"; do
  s="${other%%:*}" pin="${other#*:}"; attach "$s"; before="$(keys_on "$s")"
  out="$(bash "$KEYTOOL" refuse --serial "$s" --expect-kcv "$(kcv_card "$s")" --blob "$OUT/root.wrapped.bin" --certificate "$OUT/root.crt.pem" --pin-fd 3 3<<< "$pin" 2>&1)"; rc=$?
  [ "$rc" = 0 ] && grep -q "^REFUSED-AS-REQUIRED card $s" <<< "$out" && [ "$(keys_on "$s")" = "$before" ] \
    && P "card $s, of another DKEK domain, refuses the root's blob, and nothing was added to it" || F "refuse on $s (rc=$rc): $out"
done
# a card of the SAME domain is not "another domain": refused before anything is tried
card DENK0600003 "$PIN_SPARE" root-domain; attach DENK0600003; : > "$ARGV_LOG"
out="$(bash "$KEYTOOL" refuse --serial DENK0600003 --expect-kcv "$K_ROOT" --blob "$OUT/root.wrapped.bin" --certificate "$OUT/root.crt.pem" --pin-fd 3 3<<< "$PIN_SPARE" 2>&1)"; rc=$?
[ "$rc" = 1 ] && grep -q "holds DKEK $K_ROOT, the blob's own: it is the key's domain, not another one" <<< "$out" && ! grep -q -- '--unwrap-key' "$ARGV_LOG" \
  && P "refuse on a card of the blob's own domain: refused before any unwrap" || F "same-domain refuse (rc=$rc): $out"
# ... a card of another KCV that unwraps it anyway is a failure, loudly, and the key it took is deleted again
attach DENK0500002; before="$(keys_on DENK0500002)"
out="$(STUB_UNWRAP_ANY=1 bash "$KEYTOOL" refuse --serial DENK0500002 --expect-kcv "$K_SIGN" --blob "$OUT/root.wrapped.bin" --certificate "$OUT/root.crt.pem" --pin-fd 3 3<<< "$PIN_SPARE" 2>&1)"; rc=$?
[ "$rc" = 1 ] && grep -q "UNWRAPPED THE BLOB" <<< "$out" && [ "$(keys_on DENK0500002)" = "$before" ] \
  && P "a card that DOES unwrap it is a failure, and the key it took is deleted" || F "unwrapping refuse (rc=$rc): $out"
# ... and a card that says no for ANOTHER reason proves nothing: a fault, or a left-over EF CE<ref>
echo "sc-hsm-tool --unwrap-key" > "$FAULTS"
out="$(bash "$KEYTOOL" refuse --serial DENK0500002 --expect-kcv "$K_SIGN" --blob "$OUT/root.wrapped.bin" --certificate "$OUT/root.crt.pem" --pin-fd 3 3<<< "$PIN_SPARE" 2>&1)"; rc=$?
[ "$rc" = 1 ] && grep -q "not with the answer a card of another DKEK gives, so this proves nothing about the domain" <<< "$out" && ! grep -q REFUSED-AS-REQUIRED <<< "$out" \
  && P "an unwrap that failed for another reason (SW 6F00) is not taken as the domain's refusal" || F "refuse on a fault (rc=$rc): $out"
: > "$FAULTS"
# the attestation is required: an imported-looking key (no EF CExx), or one for ANOTHER key, is refused, and the key deleted
attach DENK0600001
for fault in STUB_ATTEST_MISSING STUB_ATTEST_OTHER_KEY; do
  rm -f "$OUT"/root2.*
  out="$(env "$fault=1" bash "$KEYTOOL" generate --serial DENK0600001 --id 21 --label root2 --subject "TEST root2" --out "$OUT" --expect-kcv "$K_ROOT" \
          --key-type ec:prime256v1 --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"; rc=$?
  [ "$rc" = 1 ] && grep -q "REFUSED" <<< "$out" && [ ! -e "$CARDS/DENK0600001/keys/21" ] && ! ls "$OUT"/root2.* >/dev/null 2>&1 \
    && P "$fault: refused, no record written, and the key generated for it was deleted" || F "$fault (rc=$rc): $out"
done
# a card that generates another type than asked
out="$(env STUB_KEYGEN_TYPE=rsa:2048 bash "$KEYTOOL" generate --serial DENK0600001 --id 22 --label root3 --subject "TEST root3" --out "$OUT" --expect-kcv "$K_ROOT" \
        --key-type ec:prime256v1 --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"; rc=$?
[ "$rc" = 1 ] && grep -q "generated a rsa:2048 key at id 22, not the ec:prime256v1 asked for" <<< "$out" && [ ! -e "$CARDS/DENK0600001/keys/22" ] \
  && P "a key of another type than asked for is refused and deleted" || F "type mismatch (rc=$rc): $out"
out="$(bash "$KEYTOOL" generate --serial DENK0600001 --id 23 --label x --subject x --out "$OUT" --expect-kcv "$K_ROOT" --key-type ec:secp384r1 --pin-fd 3 3<<< "$PIN_SIGNING" 2>&1)"
grep -q -- "--key-type is rsa:2048 or ec:prime256v1" <<< "$out" && P "an unknown key type is refused before the card is touched" || F "unknown key type: $out"

[ ! -e "$ROOT/tripwire" ] && P "no other card tool was called by any run above" || F "another card tool was called: $(cat "$ROOT/tripwire")"
calls="$(grep -E '^sc-hsm-tool ' "$ARGV_LOG")"
! grep -qv -- '--reader [1-9]' <<< "$calls" && grep -q '^sc-hsm-tool --reader 1 ' <<< "$calls" \
  && P "every sc-hsm-tool call names the reader found by the card's serial" || F "an sc-hsm-tool call without --reader: $(grep '^sc-hsm-tool' "$ARGV_LOG" | grep -v -- '--reader' | head -2)"

printf '\n  %d passed, %d failed\n' "$pass" "$fail"; [ "$fail" -eq 0 ]
