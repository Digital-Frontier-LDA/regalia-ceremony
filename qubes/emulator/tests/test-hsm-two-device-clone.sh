#!/usr/bin/env bash
# test-hsm-two-device-clone.sh — adversarial tests for the ceremony's TWO-DEVICE clone path
# (step_hsm_funding, step 6 with HSM_B_* set).
#
# WHY THIS PATH EXISTS: a same-card unwrap into a scratch slot only proves the wrapped blob
# decrypts under a DKEK that is ALREADY RESIDENT on that card. It cannot prove the real
# disaster-recovery path, where a DIFFERENT device must rebuild the same DKEK from dkek.pbe
# before the blob means anything. Cloning onto a second blank SmartCard-HSM exercises that
# path end-to-end and leaves the off-site failover device provisioned in the same operation.
#
# WHAT MUST NEVER HAPPEN: --initialize aimed at the WRONG reader would WIPE the primary card,
# destroying a non-exportable funding key that has no plaintext copy. The blank-card guard has
# to target the device about to be erased — not the default reader — and must fail CLOSED when
# that device cannot be enumerated at all.
#
# Runs natively (bash only). sc-hsm-tool / pkcs11-tool are stubbed with a two-device state
# model: each "device" is its own state dir, a DKEK domain is identified by the key check value
# derived from the imported share file, and a wrapped blob carries the domain it was made under
# so a foreign-DKEK unwrap fails exactly as the real card fails. No SoftHSM2 / OpenSC needed.
set -uo pipefail

# THE CLONE PATH IS NOW OPT-IN (PLAN.md 3.2 / decision D1). It rebuilds the SAME DKEK domain on
# device B, which moves a DKEK share between sites — and PIN + DKEK together export every key on a
# token. Under Option B each device imports from the seed under its OWN DKEK, so nothing travels.
#
# The procedure is still CORRECT for an Option-A fleet, which is why it is gated rather than
# deleted, and why this suite still covers it — it just has to say so now.
export CEREMONY_ALLOW_CLONE_PATH=1
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
# step_hsm_funding is UNSUPPORTED and gated off by default (a born-in-HSM key is not
# reconstructible from the Shamir shares). These suites deliberately exercise that path,
# so they opt in explicitly — which is also a regression check that the gate exists.
export CEREMONY_ALLOW_BORN_IN_HSM=1
HERE="$(cd "$(dirname "$0")" && pwd)"
TEST_HERE="$HERE"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
export EMU_VERIFY="$SCRIPTS/verify-hsm-control.py"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# ---- two-device state model + stubbed hardware tools --------------------------------
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
ROOT="$(mktemp -d)"
export SCHSM_A="$ROOT/devA" SCHSM_B="$ROOT/devB"
mkdir -p "$SCHSM_A" "$SCHSM_B"
# Unless a command is prefixed with SCHSM_STATE=… (which is how the wizard addresses the
# second device under the emulator), tools act on device A — the primary card.
export SCHSM_STATE="$SCHSM_A"
trap 'rm -rf "$FAKE" "$ROOT" "${WORK:-}"' EXIT

cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
S="${SCHSM_STATE:?}"
mkdir -p "$S"
case "${1:-}" in
  --create-dkek-share)
    # A DKEK share file's IDENTITY is what matters here: importing the same file on two cards
    # must yield the same domain, a different file a different domain. Model that with content.
    printf 'SCHSMDKEK1 %s\n' "${DKEK_ID:-domain-default}" > "$2"
    echo "DKEK share written to $2"
    # Six shares in OpenSC's print format, so the wizard's capture-and-feed round trip (#464)
    # has something to read. Placeholders, not key material.
    [ "${FAKE_NO_SHARES:-0}" = 1 ] || for i in 1 2 3 4 5 6; do
      printf '\nShare %s of 6\n\nPrime       : 7f:00:00:00:00:00:00:6b\nShare ID    : %s\nShare value : 0%s:0%s:0%s:0%s\n' \
        "$i" "$i" "$i" "$i" "$i" "$i"
    done
    exit 0;;
  --initialize)
    : > "$S/dkek_domain"; rm -f "$S/dkek_kcv" "$S/key_generated" "$S/restored_pub.der"
    echo "SmartCard-HSM initialised (MODEL)"; exit 0;;
  --import-dkek-share)
    [ -f "$S/dkek_domain" ] || { echo "card not initialised" >&2; exit 1; }
    [ -s "$2" ] || { echo "missing DKEK share" >&2; exit 1; }
    # Only the share path opens a password-share file: without --pwd-shares-total OpenSC asks
    # for a typed password, and nobody has ever seen the generated one.
    case " $* " in *" --pwd-shares-total 4 "*) ;; *) echo "Error decrypting DKEK share. Password correct ?" >&2; exit 1;; esac
    # OpenSC's stdin protocol: the prime, then per share one blank line, the ID and the value.
    read -r _ || { echo "Input aborted" >&2; exit 1; }
    ids=""
    for _n in 1 2 3 4; do
      read -r _; read -r id && read -r _ || { echo "Input aborted" >&2; exit 1; }
      ids="$ids $id"
    done
    printf '%s' "$ids" > "$S/fed_ids"
    # KCV identifies the domain: same share file -> same KCV on every card that imports it.
    kcv="$(cksum < "$2" | awk '{printf "%08X", $1}')"
    printf '%s' "$kcv" > "$S/dkek_kcv"
    # Print in the REAL OpenSC label format, so the wizard's parser is tested against it.
    echo "DKEK share imported"
    echo "DKEK key check value           : $kcv"
    exit 0;;
  --wrap-key)
    out="$2"
    [ -f "$S/dkek_kcv" ] || { echo "sc-hsm-tool(model): no active DKEK" >&2; exit 1; }
    [ -f "$S/key_generated" ] || { echo "sc-hsm-tool(model): no key to wrap" >&2; exit 1; }
    if [ "${BAD_WRAP:-0}" = 1 ]; then printf 'SCHSMW2-CORRUPT\n' > "$out"; echo "wrapped (MODEL)"; exit 0; fi
    src="$S/pub.der"; [ "${MISMATCH_WRAP:-0}" = 1 ] && src="$S/pub_bad.der"
    # The blob records the DOMAIN it was created under; a card holding a different DKEK
    # cannot unwrap it, exactly as the real card refuses a foreign-DKEK blob.
    { printf 'SCHSMW2\n'; printf 'DOMAIN:%s\n' "$(cat "$S/dkek_kcv")"; \
      printf 'PUB:'; base64 < "$src" | tr -d '\n'; printf '\n'; } > "$out"
    echo "wrapped KEYREF-1 (MODEL)"; exit 0;;
  --unwrap-key)
    blob="$2"
    [ -f "$S/dkek_kcv" ] || { echo "sc-hsm-tool(model): no active DKEK — cannot unwrap" >&2; exit 1; }
    [ -s "$blob" ] || { echo "sc-hsm-tool(model): empty/missing wrapped blob" >&2; exit 1; }
    dom="$(sed -n 's/^DOMAIN://p' "$blob" 2>/dev/null)"
    pub_b64="$(sed -n 's/^PUB://p' "$blob" 2>/dev/null)"
    [ -n "$pub_b64" ] || { echo "sc-hsm-tool(model): blob unrestorable (corrupt/truncated)" >&2; exit 1; }
    [ "$dom" = "$(cat "$S/dkek_kcv")" ] \
      || { echo "sc-hsm-tool(model): blob was wrapped under a DIFFERENT DKEK — cannot unwrap" >&2; exit 1; }
    printf '%s' "$pub_b64" | python3 -c 'import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' \
      > "$S/restored_pub.der" 2>/dev/null || { echo "unwrap decode failed" >&2; exit 1; }
    echo "Unwrapped key into the (emulated) card (MODEL)"; exit 0;;
  *) echo "sc-hsm-tool(model): unhandled $*" >&2; exit 0;;
esac
STUB
chmod +x "$FAKE/sc-hsm-tool"

cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
S="${SCHSM_STATE:?}"
mkdir -p "$S"
args="$*"
case "$args" in
  *--list-objects*)
    # A transient enumeration failure prints nothing and exits NON-ZERO; a blank card
    # enumerates SUCCESSFULLY with empty output. The guard must tell them apart.
    if [ "${PKCS11_LIST_FAIL_A:-0}" = 1 ] && [ "$S" = "${SCHSM_A:-}" ]; then
      echo "error: PKCS11 function C_FindObjects failed" >&2; exit 1; fi
    if [ "${PKCS11_LIST_FAIL_B:-0}" = 1 ] && [ "$S" = "${SCHSM_B:-}" ]; then
      echo "error: PKCS11 function C_FindObjects failed" >&2; exit 1; fi
    if [ -f "$S/key_generated" ] || [ -s "$S/restored_pub.der" ]; then
      echo "Public Key Object; EC"; echo "  label:      akash-funding"
    fi
    exit 0;;
  *--keypairgen*)
    : > "$S/key_generated"
    SCHSM_STATE="$S" python3 - "$EMU_VERIFY" <<'PY'
import importlib.machinery, importlib.util, os, secrets, sys
V=sys.argv[1]; ldr=importlib.machinery.SourceFileLoader("v",V)
spec=importlib.util.spec_from_loader("v",ldr); v=importlib.util.module_from_spec(spec); ldr.exec_module(v)
S=os.environ["SCHSM_STATE"]
def spki(Q):
    pt=b"\x04"+Q[0].to_bytes(32,"big")+Q[1].to_bytes(32,"big")
    bitstr=b"\x03"+bytes([len(pt)+1])+b"\x00"+pt
    algid=b"\x30\x10"+bytes.fromhex("06072a8648ce3d0201")+bytes.fromhex("06052b8104000a")
    body=algid+bitstr
    return b"\x30"+bytes([len(body)])+body
d=secrets.randbelow(v.N-1)+1
open(S+"/priv.hex","w").write(hex(d))
open(S+"/pub.der","wb").write(spki(v.scalar_mul(d,v.G)))
d2=secrets.randbelow(v.N-1)+1
open(S+"/pub_bad.der","wb").write(spki(v.scalar_mul(d2,v.G)))
PY
    echo "Key pair generated, id 01, label akash-funding"; exit 0;;
  *--sign*)
    inp=""; out=""; prev=""
    for a in "$@"; do
      [ "$prev" = "-i" ] && inp="$a"; [ "$prev" = "-o" ] && out="$a"; prev="$a"
    done
    [ -f "$S/priv.hex" ] || { echo "no key to sign with" >&2; exit 1; }
    SCHSM_STATE="$S" SIGN_IN="$inp" SIGN_OUT="$out" python3 - "$EMU_VERIFY" <<'PY'
import importlib.machinery, importlib.util, os, secrets, sys
V=sys.argv[1]; ldr=importlib.machinery.SourceFileLoader("v",V)
spec=importlib.util.spec_from_loader("v",ldr); v=importlib.util.module_from_spec(spec); ldr.exec_module(v)
S=os.environ["SCHSM_STATE"]
d=int(open(S+"/priv.hex").read().strip(),16)
z=int.from_bytes(open(os.environ["SIGN_IN"],"rb").read(),"big")
k=secrets.randbelow(v.N-1)+1
R=v.scalar_mul(k,v.G); r=R[0]%v.N
s=(v.inv_mod(k,v.N)*(z+r*d))%v.N
open(os.environ["SIGN_OUT"],"wb").write(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
PY
    echo "Using signature algorithm ECDSA"; exit 0;;
  *--read-object*)
    out=""; rid=""; prev=""
    for a in "$@"; do
      [ "$prev" = "-o" ] && out="$a"; [ "$prev" = "--id" ] && rid="$a"; prev="$a"
    done
    # id 02 = the same-card restore-verify scratch slot. id 01 = the funding key — on a CLONE
    # target that key arrives via --unwrap-key, so serve the restored pubkey when the device
    # has no born-on-card key of its own. A device with neither has nothing to export.
    if [ "$rid" = "02" ] || [ "$rid" = "2" ]; then src="$S/restored_pub.der"
    elif [ -f "$S/pub.der" ]; then src="$S/pub.der"
    else src="$S/restored_pub.der"; fi
    [ -n "$out" ] && [ -s "$src" ] && { cp "$src" "$out"; exit 0; }
    exit 1;;
  *) exit 0;;
esac
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


# ---- source the real wizard --------------------------------------------------------
# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
pause(){ :; }
# shellcheck disable=SC2034  # consumed by the sourced ceremony.sh, not by this harness
PRINTER=""
init_work

LAST_SHOWN=""
show(){ LAST_SHOWN="$*"; }

# Confirm every step, including the clone prompt (which is asked by question text, not by
# a shown command, so dispatch on $1 first).
ask_all(){ ask(){ case "${1:-}" in *"clone onto"*) return 0;; esac; return 0; }; }

reset_devices(){
  rm -rf "$SCHSM_A" "$SCHSM_B"; mkdir -p "$SCHSM_A" "$SCHSM_B"
  rm -f "$WORK"/funding-* "$WORK"/dkek.pbe "$WORK"/kcv-*.log 2>/dev/null
}
# Address device B the way the wizard does under the emulator.
export HSM_B_ENV="SCHSM_STATE=$SCHSM_B"

# =====================================================================================
hdr "UNIT: the DKEK key-check-value parser accepts BOTH real OpenSC and emulator formats"
printf 'DKEK share imported\nDKEK key check value           : F81CDA6B9FF1B7B4\n' > "$WORK/kcv-fmt.log"
# kcv_of normalises to lowercase ON PURPOSE — the value is compared with string equality to
# decide whether two devices share a DKEK domain, and producers differ in case (OpenSC prints
# lowercase, the emulator model uppercase). Asserting the raw case here would re-enshrine the
# bug where a correctly-cloned pair reads as a mismatch.
[ "$(kcv_of "$WORK/kcv-fmt.log")" = "f81cda6b9ff1b7b4" ] \
  && P "parses the OpenSC 'DKEK key check value : <hex>' form (normalised to lowercase)" \
  || F "failed to parse the OpenSC key-check-value line"

# The property that actually matters: the SAME key check value from two producers that differ
# only in case must compare EQUAL, or the clone path aborts on a correct pair.
printf 'kcv f81cda6b9ff1b7b4\n' > "$WORK/kcv-lower.log"
[ "$(kcv_of "$WORK/kcv-fmt.log")" = "$(kcv_of "$WORK/kcv-lower.log")" ] \
  && P "the same KCV printed in different case compares EQUAL across producers" \
  || F "case difference makes an identical KCV read as a mismatch — clone path would abort"
printf 'DKEK complete and active. KCV a1b2c3d4\n' > "$WORK/kcv-fmt.log"
[ "$(kcv_of "$WORK/kcv-fmt.log")" = "a1b2c3d4" ] \
  && P "parses the emulator model's 'KCV <hex>' form" \
  || F "failed to parse the emulator KCV line"

# REGRESSION: an ALL-ZERO KCV is the ABSENCE of a key check value, not a value. Measured on real
# hardware 2026-07-29 — a Pico HSM (firmware 6.6) prints "DKEK key check value : 0000000000000000"
# for a domain populated with a random share whose correctly-derived KCV was DA4BF33D408C5C57; the
# firmware simply does not compute the field. If kcv_of RETURNED that, two entirely UNRELATED
# devices would compare EQUAL and the wizard would print "same domain confirmed" on no evidence
# whatsoever. It must fail the parse instead, so the caller takes its "could not parse -> warn,
# do not block" path and the unwrap + restored-pubkey byte-compare remains the real gate.
printf 'DKEK share imported\nDKEK key check value           : 0000000000000000\n' > "$WORK/kcv-zero.log"
kcv_of "$WORK/kcv-zero.log" >/dev/null 2>&1 \
  && F "an all-zero KCV was accepted as a real value — two unrelated devices would read as cloned" \
  || P "an all-zero KCV is REJECTED as unparseable (Pico firmware does not compute the field)"

# The property that matters: two devices that BOTH report all-zeros must not be treated as a
# confirmed match. With kcv_of failing on both, the caller cannot conclude anything either way.
printf 'kcv 00000000\n' > "$WORK/kcv-zero-b.log"
if kcv_of "$WORK/kcv-zero.log" >/dev/null 2>&1 || kcv_of "$WORK/kcv-zero-b.log" >/dev/null 2>&1; then
  F "a zero KCV still parses on one side — the equality branch could still fire"
else
  P "two all-zero KCVs cannot reach the equality branch at all"
fi
rm -f "$WORK/kcv-fmt.log" "$WORK/kcv-zero.log" "$WORK/kcv-zero-b.log"

# =====================================================================================
hdr "HAPPY PATH: a blank second device is cloned and PROVEN before the address is fundable"
reset_devices; ask_all
out="$(step_hsm_funding 2>&1)"
grep -qi "same domain confirmed" <<< "$(echo "$out")" \
  && P "wizard compares DKEK key check values across both devices" \
  || F "wizard did not verify the two devices share a DKEK domain"
grep -qi "CLONE PROVEN on the second device" <<< "$(echo "$out")" \
  && P "wizard proves the clone landed on the SECOND device" \
  || F "wizard did not report a proven clone"
[ "$(cat "$SCHSM_A/fed_ids" 2>/dev/null)|$(cat "$SCHSM_B/fed_ids" 2>/dev/null)" = " 1 2 3 4| 3 4 5 6" ] \
  && P "device A imported from shares 1-4 and device B from a second quorum, shares 3-6" \
  || F "the two imports were not fed 1-4 and 3-6 (got A='$(cat "$SCHSM_A/fed_ids" 2>/dev/null)' B='$(cat "$SCHSM_B/fed_ids" 2>/dev/null)')"
[ -s "$SCHSM_B/restored_pub.der" ] \
  && P "second device now holds the restored funding key" \
  || F "second device did not receive the key"
cmp -s "$SCHSM_A/pub.der" "$SCHSM_B/restored_pub.der" \
  && P "cloned key on device B is byte-identical to the funding key on device A" \
  || F "device B holds a DIFFERENT key than device A"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && P "address declared fundable only after the cross-device restore proof" \
  || F "no funding address recorded on a fully proven clone"
grep -qi "seal them at different sites" <<< "$(echo "$out")" \
  && P "wizard tells the operator to seal the two devices at different sites" \
  || F "wizard did not warn about siting the clone separately"
grep -qi "do NOT pre-initialise the remaining SPARE" <<< "$(echo "$out")" \
  && P "wizard warns against pre-initialising the cold spare (would bypass the 4-of-6)" \
  || F "wizard did not warn against pre-initialising the spare"

# =====================================================================================
hdr "SAFETY: refuse to --initialize a second device that ALREADY holds a funding key"
# Models the catastrophic operator error: the HSM_B selector points back at a card that
# already carries the funding key. --initialize would WIPE a non-exportable key.
reset_devices; ask_all
: > "$SCHSM_B/key_generated"; cp /dev/null "$SCHSM_B/pub.der" 2>/dev/null
printf 'decoy' > "$SCHSM_B/pub.der"
out="$(step_hsm_funding 2>&1)"
[ -f "$SCHSM_B/key_generated" ] \
  && P "existing key on the second device was NOT destroyed" \
  || F "BUG: wizard wiped a card that already held a funding key"
grep -qi "refusing to re-initialise over an existing funding key" <<< "$(echo "$out")" \
  && P "wizard refuses to initialise over an existing funding key" \
  || F "wizard did not refuse to re-initialise the occupied second device"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: address declared fundable despite the clone being refused" \
  || P "no funding address recorded when the clone was refused"

# =====================================================================================
hdr "ENUM-FAIL GUARD: an unreadable second device must NOT be treated as blank"
reset_devices; ask_all
out="$(PKCS11_LIST_FAIL_B=1 step_hsm_funding 2>&1)"
grep -qi "could NOT enumerate key objects on the SECOND HSM" <<< "$(echo "$out")" \
  && P "wizard fails closed when the second device cannot be enumerated" \
  || F "BUG: an unreadable second device was treated as blank (re-init would wipe it)"
[ ! -s "$SCHSM_B/restored_pub.der" ] \
  && P "no clone was attempted against an unreadable device" \
  || F "wizard cloned onto a device it could not enumerate"

# =====================================================================================
hdr "DKEK MISMATCH: two devices in DIFFERENT domains must NOT yield a fundable address"
# The second card is initialised from a DIFFERENT dkek.pbe, so it can never restore this
# backup. The key check values differ and the wizard must stop before declaring fundability.
reset_devices
ask(){
  case "${1:-}" in *"clone onto"*) return 0;; esac
  # Swap in a different DKEK share file for the second device's import only.
  case "$LAST_SHOWN" in
    *"$SCHSM_B"*--import-dkek-share*) printf 'SCHSMDKEK1 a-totally-different-domain\n' > "$WORK/dkek.pbe";;
  esac
  return 0
}
out="$(step_hsm_funding 2>&1)"
grep -qi "DKEK MISMATCH" <<< "$(echo "$out")" \
  && P "wizard detects the two devices are in different DKEK domains" \
  || F "BUG: wizard did not detect a DKEK domain mismatch between the devices"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: address declared fundable with a clone that shares no DKEK domain" \
  || P "wizard refused fundability on a DKEK mismatch"

# =====================================================================================
hdr "RESTORE-VERIFY: a backup the SECOND device cannot unwrap must NOT yield an address"
reset_devices; ask_all
out="$(BAD_WRAP=1 step_hsm_funding 2>&1)"
grep -qiE "RESTORE-VERIFY FAILED|unrestorable|do NOT fund" <<< "$out" \
  && P "wizard detects the second device cannot rebuild the backup" \
  || F "BUG: an unrestorable backup passed the cross-device restore-verify"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: address declared fundable though the clone could not be restored" \
  || P "wizard refused fundability when the second device could not unwrap"

# =====================================================================================
hdr "RESTORE-VERIFY: a clone that restores a DIFFERENT key must NOT yield an address"
reset_devices; ask_all
out="$(MISMATCH_WRAP=1 step_hsm_funding 2>&1)"
grep -qi "does NOT byte-match" <<< "$(echo "$out")" \
  && P "wizard detects the cloned key differs from the funding key" \
  || F "BUG: a clone holding a DIFFERENT key passed the restore-verify"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: address declared fundable with a mismatched clone" \
  || P "wizard refused fundability on a cloned-pubkey mismatch"

# =====================================================================================
hdr "REGRESSION: with no HSM_B_* set, the single-device same-card path is unchanged"
reset_devices; ask_all
saved_env="$HSM_B_ENV"; unset HSM_B_ENV
out="$(step_hsm_funding 2>&1)"
export HSM_B_ENV="$saved_env"
grep -qi "restore-verify OK" <<< "$(echo "$out")" \
  && P "single-device fallback still restore-verifies on the same card" \
  || F "single-device fallback broke"
grep -qi "HSM_B_READER" <<< "$(echo "$out")" \
  && P "wizard hints how to enable the stronger cross-device proof" \
  || F "wizard gave no hint about the second-device clone path"
[ ! -s "$SCHSM_B/restored_pub.der" ] \
  && P "no second device was touched without an explicit HSM_B_* selector" \
  || F "BUG: wizard wrote to a second device that was never opted into"

# =====================================================================================
hdr "THE PATH IS GATED — prod refuses it without an explicit opt-in"
# Without this, "superseded" is a comment rather than a control. Run the wizard's own source
# through a shell that has the gate but NOT the opt-in, and assert it refuses.
CEREMONY_CODE="$(python3 "$TEST_HERE/source_lexing.py" shell "$SCRIPTS/ceremony.sh")" \
  || { echo "source lexer failed" >&2; exit 2; }
gate_block="$(grep -B2 -A8 'CEREMONY_ALLOW_CLONE_PATH:-0' <<<"$CEREMONY_CODE" || true)"
if grep -q 'CEREMONY_MODE:-dev.*prod' <<<"$gate_block" \
   && grep -qE '^[[:space:]]*return 1' <<<"$gate_block"; then
  P "the wizard carries a prod gate on the clone path"
else
  F "no executable prod refusal guards the clone path — 'superseded' would be only commentary"
fi
TEST_CODE="$(python3 "$TEST_HERE/source_lexing.py" shell "$0")" \
  || { echo "source lexer failed" >&2; exit 2; }
grep -q 'CEREMONY_ALLOW_CLONE_PATH=1' <<<"$TEST_CODE" \
  && P "this suite opts in EXPLICITLY rather than inheriting the old default" \
  || F "the suite exercises a gated path without declaring it"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
