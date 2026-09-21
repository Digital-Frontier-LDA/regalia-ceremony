#!/usr/bin/env bash
# test-hsm-import-step.sh — adversarial tests for ceremony.sh step_hsm_import, the SUPPORTED
# REQUIREMENTS B2 — the card must hold the SEED's key and refuse a different one — that IS always-import.
# custody path: derive the funding key from the seed, package it as PKCS#12, import it into the
# HSM, and prove the card ended up holding exactly that key.
#
# THE FAILURE THAT COSTS MONEY: an import that lands a DIFFERENT key. The card reports a
# perfectly valid address, signing works, everything looks right — and the funds go to a key
# nobody can reconstruct from the shares. Only comparing the card's address against the seed's
# derivation catches it, so that comparison is tested hardest here.
#
# The second failure is subtler: the address matches (the PUBLIC key arrived) but the card
# cannot USE the private half. A read-back alone would call that a success.
#
# Runs natively. pkcs11-tool is stubbed with a model that can be told to hold the right key, a
# wrong key, or a key it cannot sign with. Real openssl + the real derivation are used.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
# The step is gated until the import is proven on real hardware for secp256k1; the suite opts in
# explicitly, which also regression-checks that the gate exists.
export CEREMONY_ALLOW_HSM_IMPORT=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

command -v openssl >/dev/null || { echo "  (skipping: openssl not installed)"; exit 0; }

FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
STATE="$(mktemp -d)"; export STATE
trap 'rm -rf "$FAKE" "$STATE" "${WORK:-}"' EXIT

# pkcs11-tool model: serves whatever public key $STATE/oncard.der holds, and signs with the
# matching private key unless told it cannot. Real secp256k1 math via the ceremony's verifier.
cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
S="${STATE:?}"
case "$*" in
  *--list-objects*)
    # A blank card enumerates SUCCESSFULLY with empty output; an unreadable one exits NON-ZERO.
    # The wipe guard must tell them apart — treating a read error as "blank" would erase a key.
    if [ "${STUB_ENUM_FAIL:-0}" = 1 ]; then echo "C_FindObjects failed" >&2; exit 1; fi
    if [ "${STUB_OCCUPIED:-0}" = 1 ]; then
      echo "Public Key Object; EC"; echo "  label:      akash-funding"
    fi
    exit 0;;
  *--read-object*)
    out=""; prev=""
    for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
    if [ "${STUB_READ_FAIL:-0}" = 1 ]; then exit 1; fi
    [ -s "$S/oncard.der" ] || exit 1
    [ -n "$out" ] && cp "$S/oncard.der" "$out"
    exit 0;;
  *--sign*)
    if [ "${STUB_SIGN_FAIL:-0}" = 1 ]; then echo "signing failed" >&2; exit 1; fi
    inp=""; out=""; prev=""
    for a in "$@"; do
      [ "$prev" = "-i" ] && inp="$a"; [ "$prev" = "-o" ] && out="$a"; prev="$a"
    done
    [ -s "$S/oncard.key" ] || { echo "no private key" >&2; exit 1; }
    STATE="$S" SIGN_IN="$inp" SIGN_OUT="$out" python3 - "$EMU_VERIFY" <<'PY'
import importlib.machinery, importlib.util, os, secrets, sys
V=sys.argv[1]; ldr=importlib.machinery.SourceFileLoader("v",V)
spec=importlib.util.spec_from_loader("v",ldr); v=importlib.util.module_from_spec(spec); ldr.exec_module(v)
S=os.environ["STATE"]
d=int(open(S+"/oncard.key").read().strip(),16)
z=int.from_bytes(open(os.environ["SIGN_IN"],"rb").read(),"big")
k=secrets.randbelow(v.N-1)+1
R=v.scalar_mul(k,v.G); r=R[0]%v.N
s=(v.inv_mod(k,v.N)*(z+r*d))%v.N
open(os.environ["SIGN_OUT"],"wb").write(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
PY
    exit 0;;
esac
exit 0
STUB
chmod +x "$FAKE/pkcs11-tool"

# opensc-tool stub: the ATR is the device fingerprint the destructive-step guard checks.
# $STUB_ATR selects which device is "in the reader"; empty models a reader that answers nothing.
cat > "$FAKE/opensc-tool" <<'ATRSTUB'
#!/usr/bin/env bash
case "$*" in
  *--atr*)
    [ -n "${STUB_ATR-unset}" ] || exit 1
    printf '%s\n' "${STUB_ATR:-3bde96ff8191fe1fc38031815448534d3173802140810792}"
    exit 0;;
esac
exit 0
ATRSTUB
chmod +x "$FAKE/opensc-tool"
export STUB_ATR="3bde96ff8191fe1fc38031815448534d3173802140810792"

export EMU_VERIFY="$SCRIPTS/verify-hsm-control.py"

# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
pause(){ :; }
# shellcheck disable=SC2034
PRINTER=""
init_work
show(){ :; }
ask(){ return 0; }

MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
OTHER="legal winner thank year wave sausage worth useful legal winner thank yellow"

# Put the key derived from $1 onto the modelled card (public DER + private scalar).
place_on_card() {
  printf '%s' "$1" > "$STATE/m.txt"
  STATE="$STATE" MN="$1" DERIVER="$SCRIPTS/derive-akash-address.py" python3 - <<'PY'
import importlib.machinery, importlib.util, os
V=os.environ["DERIVER"]; ldr=importlib.machinery.SourceFileLoader("d",V)
spec=importlib.util.spec_from_loader("d",ldr); d=importlib.util.module_from_spec(spec); ldr.exec_module(d)
S=os.environ["STATE"]; mn=os.environ["MN"]
k,chain=d._bip32_master(d._bip39_seed(mn,""))
for i in d._parse_hd_path(d.DEFAULT_HD_PATH): k,chain=d._ckd_priv(k,chain,i)
x,y=d._scalar_mult(k,(d.SECP256K1_GX,d.SECP256K1_GY))
pt=b"\x04"+x.to_bytes(32,"big")+y.to_bytes(32,"big")
bit=b"\x03"+bytes([len(pt)+1])+b"\x00"+pt
algid=b"\x30\x10"+bytes.fromhex("06072a8648ce3d0201")+bytes.fromhex("06052b8104000a")
body=algid+bit
open(S+"/oncard.der","wb").write(b"\x30"+bytes([len(body)])+body)
open(S+"/oncard.key","w").write(hex(k))
PY
}
# THE IMPORT IS MODELLED, LIKE THE CARD. This suite places a key on a modelled card out of band
# and tests the guards and the proofs around it; the step itself now performs a real import
# (regalia#486 — no Smart Card Shell), which needs a DKEK and a card. The stub stands in for that
# one action and RECORDS its arguments, so these rows can assert the step actually attempted an
# import. Before the step drove the import, nothing here could tell whether one had happened.
export HSM_IMPORTER="$STATE/import-stub.sh"
export IMPORT_STUB_LOG="$STATE/import-args.txt"
cat > "$HSM_IMPORTER" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${IMPORT_STUB_LOG:?}"
[ "${STUB_IMPORT_FAIL:-0}" = 1 ] && { echo "import stub: refusing on purpose" >&2; exit 1; }
exit 0
STUB
chmod +x "$HSM_IMPORTER"

reset(){ rm -f "$WORK/funding.p12" "$WORK/p12.pw" "$WORK/imported-pub.der" "$STATE"/oncard.* \
               "$IMPORT_STUB_LOG"; \
         printf '%s' "$MNEMONIC" > "$WORK/funding.mnemonic"
         # The DKEK and its share file are the step's inputs, not its outputs: it refuses without
         # them because there would be nothing to wrap the key under.
         printf 'Salted__01234567' > "$WORK/dkek.pbe"
         printf 'Prime       : e2:8c:4e:2a:93:cc:a8:77\nShare ID    : 1\nShare value : be:d9:2a:f6:96:43:c4:41\n' \
           > "$WORK/dkek-shares.txt"
         printf '648219' > "$WORK/hsm-user.pin"; }

# =====================================================================================
hdr "HAPPY PATH: container built, card holds the seed's key, address matches, signing proven"
reset; place_on_card "$MNEMONIC"
out="$(step_hsm_import 2>&1)"
[ -s "$WORK/funding.p12" ] && P "PKCS#12 container built from the seed" || F "no container produced"
[ -s "$IMPORT_STUB_LOG" ] && P "the step ATTEMPTED an import — it no longer hands the card work to an operator" \
  || F "no import was attempted; the step only built a container"
grep -q -- '--dkek-shares' "$IMPORT_STUB_LOG" 2>/dev/null \
  && P "…passing the DKEK share file, so the password is reconstructed and never typed" \
  || F "the importer was called without --dkek-shares: $(cat "$IMPORT_STUB_LOG" 2>/dev/null)"
grep -q -- '--pin-file' "$IMPORT_STUB_LOG" 2>/dev/null \
  && P "…and the PIN as a FILE, never in argv where ps would see it" \
  || F "the PIN was not passed as a file"
grep -qi "ADDRESS MATCH" <<< "$out" && P "card address matches the seed derivation" \
                                       || F "address-match proof did not run or failed"
grep -qi "SIGN PROOF PASSED" <<< "$out" && P "card proven able to SIGN with the imported key" \
                                           || F "sign proof did not pass"
grep -qi "IMPORT COMPLETE AND PROVEN" <<< "$out" && P "import declared complete only after both proofs" \
                                                    || F "import not declared complete on the happy path"

# =====================================================================================
hdr "THE MONEY-LOSING CASE: card holds a DIFFERENT key -> must refuse, loudly"
# An import that lands the wrong key yields a valid-looking address that signs fine. Only the
# comparison against the seed's own derivation catches it.
reset; place_on_card "$OTHER"
out="$(step_hsm_import 2>&1)"
grep -qi "ADDRESS MISMATCH" <<< "$(echo "$out")" \
  && P "detects that the card holds a different key than the seed derives" \
  || F "BUG: a wrong imported key passed unnoticed — funds would go to an unrecoverable address"
grep -qi "do NOT fund" <<< "$out" && P "tells the operator not to fund" || F "no do-not-fund warning"
grep -qi "IMPORT COMPLETE AND PROVEN" <<< "$(echo "$out")" \
  && F "BUG: declared the import proven despite an address mismatch" \
  || P "did not declare success on a mismatch"
grep -qi "SIGN PROOF PASSED" <<< "$(echo "$out")" \
  && F "BUG: continued to the sign proof after a mismatch instead of aborting" \
  || P "aborted at the mismatch rather than continuing"

# =====================================================================================
hdr "PUBLIC KEY ARRIVED BUT CARD CANNOT SIGN -> must not be called a success"
reset; place_on_card "$MNEMONIC"
out="$(STUB_SIGN_FAIL=1 step_hsm_import 2>&1)"
grep -qi "ADDRESS MATCH" <<< "$out" && P "address match still detected (public half is fine)" \
                                       || F "address match failed unexpectedly"
grep -qi "SIGN PROOF FAILED" <<< "$(echo "$out")" \
  && P "detects an object that reads back correctly but cannot sign" \
  || F "BUG: an unusable imported key was accepted on the strength of a read-back"
grep -qi "IMPORT COMPLETE AND PROVEN" <<< "$(echo "$out")" \
  && F "BUG: declared success for a key the card cannot use" \
  || P "refused to declare success without a working signature"

# =====================================================================================
hdr "UNREADABLE CARD: fail closed rather than assume the import worked"
reset; place_on_card "$MNEMONIC"
out="$(STUB_READ_FAIL=1 step_hsm_import 2>&1)"
grep -qiE "could not read the imported public key|import unproven" <<< "$out" \
  && P "fails closed when the card's public key cannot be read" \
  || F "BUG: an unreadable card did not stop the step"
grep -qi "IMPORT COMPLETE AND PROVEN" <<< "$(echo "$out")" \
  && F "BUG: declared success without reading the card" || P "no success claim on an unreadable card"

# =====================================================================================
hdr "MISSING MNEMONIC: refuse rather than build an empty container"
reset; rm -f "$WORK/funding.mnemonic"
out="$(step_hsm_import 2>&1)"
[ ! -s "$WORK/funding.p12" ] && P "no container built without a mnemonic" || F "built a container from nothing"
grep -qi "never argv" <<< "$out" && P "reminds the operator the mnemonic is read from a file" \
                                    || F "no off-argv guidance"

# =====================================================================================
hdr "GATE: the step is shut until the import is proven on hardware"
reset; place_on_card "$MNEMONIC"
out="$(CEREMONY_ALLOW_HSM_IMPORT=0 step_hsm_import 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "refuses to run without an explicit opt-in" || F "BUG: unproven path ran by default"
grep -qi "THROWAWAY key" <<< "$out" && P "tells the operator how to prove it safely first" \
                                       || F "no guidance on proving the path"

# =====================================================================================
hdr "SECRETS never reach the terminal"
reset; place_on_card "$MNEMONIC"
out="$(step_hsm_import 2>&1)"
grep -qF "abandon abandon" <<< "$out" && F "LEAKED the mnemonic to the terminal" \
                                         || P "mnemonic never printed"
if [ -s "$WORK/p12.pw" ] && grep -qF "$(cat "$WORK/p12.pw")" <<< "$out"; then
  F "LEAKED the PKCS#12 password to the terminal"
else
  P "container password never printed"
fi

# =====================================================================================
hdr "The container really carries the SEED's key (not some other key)"
reset; place_on_card "$MNEMONIC"
step_hsm_import >/dev/null 2>&1
# Compare via the AUDITED deriver rather than by hex substring: the card exports an
# UNCOMPRESSED point and openssl was asked for a COMPRESSED one, so the encodings differ by
# prefix even for an identical key. The address each yields is the semantically meaningful
# comparison, and it is the same check the step itself makes.
openssl pkcs12 -in "$WORK/funding.p12" -nocerts -nodes -passin "file:$WORK/p12.pw" 2>/dev/null \
  | openssl ec -pubout -outform DER 2>/dev/null > "$WORK/p12-pub.der"
if [ -s "$WORK/p12-pub.der" ]; then
  a_p12="$(python3 "$SCRIPTS/derive-akash-address.py" --der "$WORK/p12-pub.der" 2>/dev/null || true)"
  a_card="$(python3 "$SCRIPTS/derive-akash-address.py" --der "$STATE/oncard.der" 2>/dev/null || true)"
  if [ -n "$a_p12" ] && [ "$a_p12" = "$a_card" ]; then
    P "container key and card key derive the SAME address ($a_p12)"
  else
    F "container key != card key (container: ${a_p12:-unreadable}, card: ${a_card:-unreadable})"
  fi
else
  F "could not extract the public key from the container"
fi

# =====================================================================================
hdr "DESTRUCTIVE-PROCEDURE GUARD: never hand off a card that already holds a funding key"
# Nitrokey's documented import flow INITIALISES (erases) the target. Pointed at an in-service
# card — the off-site clone, say — following the instructions destroys a working key.
reset; place_on_card "$MNEMONIC"
out="$(STUB_OCCUPIED=1 step_hsm_import 2>&1)"
grep -qi "would ERASE it" <<< "$(echo "$out")" \
  && P "refuses to hand off to scsh when the target already holds a funding key" \
  || F "BUG: would have sent the operator to wipe a card holding a live key"
grep -qi "IMPORT COMPLETE AND PROVEN" <<< "$(echo "$out")" \
  && F "BUG: declared success after refusing the hand-off" || P "no success claim after refusal"

hdr "A FAILED IMPORT STOPS THE STEP — the proofs must not run against a stale card"
# The card is modelled, so its state does not change when the import fails. If the step carried on
# it would read the key that was already there and print ADDRESS MATCH and SIGN PROOF PASSED for
# an import that did not happen — the most convincing possible false pass.
reset; place_on_card "$MNEMONIC"
out="$(STUB_IMPORT_FAIL=1 step_hsm_import 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "a failed import is a failed step (exit $rc)" || F "the step returned 0 after a failed import"
grep -qi 'the import failed' <<<"$out" && P "…saying so" || F "the failure is not reported: $(tail -2 <<<"$out")"
grep -qi 'ADDRESS MATCH' <<<"$out" \
  && F "it printed ADDRESS MATCH after a failed import — proving a card state it did not create" \
  || P "…and does NOT print the proofs, which would describe the card as it was before"

hdr "MISSING DKEK: the step refuses rather than importing under nothing"
reset; place_on_card "$MNEMONIC"; rm -f "$WORK/dkek.pbe"
out="$(step_hsm_import 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && grep -qi 'dkek' <<<"$out" \
  && P "no DKEK is a refusal that names it" || F "ran with no DKEK: $(tail -2 <<<"$out")"

hdr "DESTRUCTIVE-PROCEDURE GUARD: an unreadable target is not treated as blank"
reset; place_on_card "$MNEMONIC"
out="$(STUB_ENUM_FAIL=1 step_hsm_import 2>&1)"
grep -qiE "could NOT enumerate|refusing to" <<< "$out" \
  && P "fails closed when the target cannot be enumerated" \
  || F "BUG: an unreadable card was treated as safe to erase"

hdr "The operator is warned the procedure ERASES the target"
reset; place_on_card "$MNEMONIC"
out="$(step_hsm_import 2>&1)"
grep -qiE "INITIALISES \(ERASES\)|will be erased" <<< "$out" \
  && P "states plainly that the documented procedure erases the device" \
  || F "no erase warning — an operator could wipe an in-service card unawares"

# =====================================================================================
hdr "DEVICE-IDENTITY GUARD: a non-SmartCard-HSM in the reader must be refused"
# Once a Pico HSM lives permanently on the same machine as the real Nitrokey, reader INDEX
# stops being evidence of anything — it is assigned in attach order. The ATR check detects a
# SmartCard-HSM-PROTOCOL device: ASCII 'THSM1' in the ATR means the card speaks the
# SmartCard-HSM protocol, NOT that it is a specific make. A Pico HSM carries THSM1 exactly
# like a genuine SmartCard-HSM (measured 2026-07-29 — the ATR is NOT a make discriminator),
# so this check refuses non-protocol cards (a random test board, a JavaCard in the wrong
# reader); telling the Pico apart from the Nitrokey is what CEREMONY_EXPECT_ATR pinning,
# tested below, is for.
reset; place_on_card "$MNEMONIC"
out="$(STUB_ATR=3b8d800180310080318065b0850300ef120fff829100 step_hsm_import 2>&1)"
grep -qi "does NOT look like a SmartCard-HSM" <<< "$(echo "$out")" \
  && P "refuses a device whose ATR lacks the SmartCard-HSM marker" \
  || F "BUG: would have run a destructive step against a device that does not speak the SmartCard-HSM protocol"
grep -qi "IMPORT COMPLETE AND PROVEN" <<< "$(echo "$out")" \
  && F "BUG: declared success against an unidentified device" || P "no success claim on a wrong device"

hdr "DEVICE-IDENTITY GUARD: an unreadable reader is not assumed to be the right device"
reset; place_on_card "$MNEMONIC"
# shellcheck disable=SC1007  # DELIBERATE: STUB_ATR is set to EMPTY for this one call, which is
# the case under test — a reader that reports no ATR at all. It is not a missing assignment.
out="$(STUB_ATR='' step_hsm_import 2>&1)"
grep -qiE "no ATR from the reader|unidentified card" <<< "$out" \
  && P "fails closed when no ATR can be read" \
  || F "BUG: proceeded without identifying the card"

hdr "DEVICE-IDENTITY GUARD: CEREMONY_EXPECT_ATR pins one SPECIFIC device, not just a model"
# Two Nitrokeys both carry THSM1, so the model marker cannot tell the primary from the clone.
# Pinning the exact ATR is what distinguishes them.
reset; place_on_card "$MNEMONIC"
out="$(CEREMONY_EXPECT_ATR=3bde96ff8191fe1fc38031815448534d3173802140810792 step_hsm_import 2>&1)"
grep -qi "ATR matches the pinned device" <<< "$(echo "$out")" \
  && P "accepts the pinned device" || F "rejected the correctly pinned device"
out="$(CEREMONY_EXPECT_ATR=3bffffffffffffffffffffffffffffffffffffffffffffff step_hsm_import 2>&1)"
grep -qi "ATR MISMATCH" <<< "$(echo "$out")" \
  && P "refuses a different device of the SAME model when one is pinned" \
  || F "BUG: a pinned ATR did not stop a different device"

# =====================================================================================
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
