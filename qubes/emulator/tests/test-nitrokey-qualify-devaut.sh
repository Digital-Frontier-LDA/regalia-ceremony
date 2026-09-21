#!/usr/bin/env bash
# test-nitrokey-qualify-devaut.sh — #448 asks whether the DEVICE certificate is a PKCS#11 object.
#
# WHAT WENT WRONG. The check counted every CKO_CERTIFICATE and concluded from one that the daemon's
# identity probe "CAN read it here". Every commissioned card carries a certificate beside its key,
# so the check could never fail in the field — and on DENK0404144 (2026-09-21) it reported exactly
# that while the only certificate present was CN=cosmos-staging-qual, written beside an imported
# key minutes earlier. The answer was the opposite of the truth.
#
# A SmartCard-HSM's device-authentication certificate is a CVC in EF 2F02 and is never exposed
# through PKCS#11 — which is why qubes/scripts/hsm-devaut-read.sh exists. What tells the two apart
# is that a key's certificate shares its CKA_ID with a key object.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
QUAL="$SCRIPTS/nitrokey-qualify.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ -r "$QUAL" ] || { echo "no nitrokey-qualify.sh at $QUAL" >&2; exit 1; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
BIN="$T/bin"; mkdir -p "$BIN"; export PATH="$BIN:$PATH"
# A pkcs11-tool that answers from fixture files, so the whole #448 decision is exercised.
cat > "$BIN/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *-L*)            cat "${FIX:?}/slots.txt";;
  *"--type cert"*) cat "${FIX:?}/certs.txt";;
  *"--type pubkey"*) cat "${FIX:?}/pubkeys.txt";;
  *"--type privkey"*) cat "${FIX:?}/privkeys.txt" 2>/dev/null || true;;
esac
exit 0
STUB
chmod +x "$BIN/pkcs11-tool"
export FIX="$T"
: > "$T/privkeys.txt"
cat > "$T/slots.txt" <<'X'
Slot 0 (0x0): Nitrokey Nitrokey HSM
  serial num         : DENK0404144
X
run(){ HSM_PKCS11_MODULE="$T/fake.so" bash "$QUAL" --module "$T/fake.so" --serial DENK0404144 2>&1; }
: > "$T/fake.so"

hdr "a key's certificate must NOT be reported as the device certificate"
cat > "$T/certs.txt" <<'X'
Certificate Object; type = X.509 cert
  label:      cosmos-qual
  ID:         02
X
cat > "$T/pubkeys.txt" <<'X'
Public Key Object; EC
  label:      cosmos-qual
  ID:         02
  Access:     none
X
out="$(run)"
grep -q '#448 device certificate: none exposed' <<<"$out" \
  && P "a certificate sharing its id with a key is a KEY certificate, and #448 says none exposed" \
  || F "a key certificate was reported as the device certificate: $(grep '#448' <<<"$out")"
grep -q 'all paired with a key' <<<"$out" \
  && P "…and the line says why, rather than just reporting zero" \
  || F "the reason is not given: $(grep '#448' <<<"$out")"
grep -q 'hsm-devaut-read.sh' <<<"$out" \
  && P "…and names the fallback that CAN read it (EF 2F02)" || F "the EF 2F02 fallback is not named"

hdr "an UNPAIRED certificate is the one that would answer #448 yes"
cat > "$T/certs.txt" <<'X'
Certificate Object; type = X.509 cert
  label:      C.DevAut
  ID:         ff
Certificate Object; type = X.509 cert
  label:      cosmos-qual
  ID:         02
X
out="$(run)"
grep -q 'NOT paired with a key -- the daemon identity probe CAN read one here' <<<"$out" \
  && P "a certificate with no matching key id is reported as readable by the identity probe" \
  || F "an unpaired certificate was not recognised: $(grep '#448' <<<"$out")"
grep -qE '#448 device certificate: 2 CKO_CERTIFICATE object\(s\) present, 1 of them NOT paired' <<<"$out" \
  && P "…and both counts are reported, so a reader can tell what was seen" \
  || F "the counts are wrong: $(grep '#448' <<<"$out")"

hdr "no certificates at all"
: > "$T/certs.txt"
out="$(run)"
grep -q '#448 device certificate: none exposed' <<<"$out" \
  && P "an empty token reports none exposed" || F "an empty token did not: $(grep '#448' <<<"$out")"
grep -q 'certificate object(s) are present' <<<"$out" \
  && F "it claims certificates are present on an empty token" \
  || P "…without claiming certificates are present"

hdr "ID case does not decide the answer"
cat > "$T/certs.txt" <<'X'
Certificate Object; type = X.509 cert
  ID:         AB
X
cat > "$T/pubkeys.txt" <<'X'
Public Key Object; EC
  ID:         ab
  Access:     none
X
out="$(run)"
grep -q '#448 device certificate: none exposed' <<<"$out" \
  && P "ID AB and id ab are the same id — the pairing is case-insensitive" \
  || F "a case difference made a key certificate look like a device certificate"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
