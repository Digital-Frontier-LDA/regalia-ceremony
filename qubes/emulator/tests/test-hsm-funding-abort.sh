#!/usr/bin/env bash
# test-hsm-funding-abort.sh — adversarial tests for the ceremony's HSM funding-key path
# (step_hsm_funding). The wizard chains independent `run` calls for the DKEK threshold
# backup and the born-in-HSM funding key. If a DKEK init/import step is SKIPPED or FAILS,
# the wizard MUST abort BEFORE generating the non-exportable funding key — otherwise it
# creates a key on the device with NO recoverable DKEK backup (the wrap-backup then fails,
# but the key already exists). It MUST also refuse to re-`--initialize` over an existing
# funding key (re-init DESTROYS a key that has no plaintext copy).
#
# Runs natively (bash only). sc-hsm-tool / pkcs11-tool are stubbed with a faithful state
# model of the relevant device behaviour (wrap needs an active DKEK; list-objects shows the
# funding pubkey once a key exists). No SoftHSM2 / OpenSC needed.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
# step_hsm_funding is UNSUPPORTED and gated off by default (a born-in-HSM key is not
# reconstructible from the Shamir shares). These suites deliberately exercise that path,
# so they opt in explicitly — which is also a regression check that the gate exists.
export CEREMONY_ALLOW_BORN_IN_HSM=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
# The keypair-control proof (step 4) signs a random digest on the HSM and verifies it against
# the exported pubkey with this pure-stdlib secp256k1 verifier. The stubbed pkcs11-tool below
# reuses its curve arithmetic to do REAL keygen/sign, so the proof is exercised end-to-end.
export EMU_VERIFY="$SCRIPTS/verify-hsm-control.py"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# ---- device state model + stubbed hardware tools -----------------------------------
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
# Assign separately: inline "$(mktemp -d)/schsm" masks mktemp's exit status.
_schsm_base="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 1; }
export SCHSM_STATE="$_schsm_base/schsm"; mkdir -p "$SCHSM_STATE"
trap 'rm -rf "$FAKE" "$SCHSM_STATE" "${WORK:-}"' EXIT

cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
S="${SCHSM_STATE:?}"
case "${1:-}" in
  --create-dkek-share)
    printf 'SCHSMDKEK1\n' > "$2"; echo "DKEK share written to $2"
    # Six shares in OpenSC's print format, so the wizard's capture-and-feed round trip (#464)
    # has something to read. Placeholders, not key material.
    [ "${FAKE_NO_SHARES:-0}" = 1 ] || for i in 1 2 3 4 5 6; do
      printf '\nShare %s of 6\n\nPrime       : 7f:00:00:00:00:00:00:6b\nShare ID    : %s\nShare value : 0%s:0%s:0%s:0%s\n' \
        "$i" "$i" "$i" "$i" "$i" "$i"
    done
    # FAKE_CREATE_FAILS=1: the tool dies after it has shown the shares.
    [ "${FAKE_CREATE_FAILS:-0}" = 1 ] && exit 1
    exit 0;;
  --initialize)        : > "$S/dkek_domain"; rm -f "$S/dkek_loaded" "$S/key_generated"; echo "initialised (MODEL)"; exit 0;;
  --import-dkek-share)
    [ -f "$S/dkek_domain" ] || { echo "card not initialised" >&2; exit 1; }
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
    # FAKE_ROUND_TRIP_REFUSED=1: the right shares, and the card refuses anyway. That is OpenSC's
    # leading-zero drop, 1 share file in 128 (#460).
    [ "${FAKE_ROUND_TRIP_REFUSED:-0}" = 1 ] && { echo "Error decrypting DKEK share. Password correct ?" >&2; exit 1; }
    : > "$S/dkek_loaded"; echo "DKEK complete and active"; exit 0;;
  --wrap-key)
    out="$2"
    if [ -f "$S/dkek_loaded" ] && [ -f "$S/key_generated" ]; then
      # A FAITHFUL wrapped blob carries the (DKEK-encrypted) key material, so an unwrap on a
      # spare/second slot can RECONSTRUCT the key and prove it. We model that by embedding the
      # funding pubkey; the real blob carries the private key (ciphertext under the DKEK).
      #   BAD_WRAP=1      -> an UNRESTORABLE blob (truncated/garbage): no unwrap can rebuild it.
      #   MISMATCH_WRAP=1 -> a blob that unwraps to a DIFFERENT key (wrong key-reference object):
      #                      unwrap SUCCEEDS but the restored pubkey does not match funding-pub.der.
      if [ "${BAD_WRAP:-0}" = 1 ]; then
        printf 'SCHSMW2-CORRUPT-TRUNCATED\n' > "$out"
      elif [ "${MISMATCH_WRAP:-0}" = 1 ]; then
        { printf 'SCHSMW2\n'; printf 'PUB:'; base64 < "$S/pub_bad.der" | tr -d '\n'; printf '\n'; } > "$out"
      else
        { printf 'SCHSMW2\n'; printf 'PUB:'; base64 < "$S/pub.der" | tr -d '\n'; printf '\n'; } > "$out"
      fi
      echo "wrapped KEYREF-1 (MODEL)"; exit 0
    else echo "sc-hsm-tool(model): no active DKEK or no key to wrap" >&2; exit 1; fi;;
  --unwrap-key)
    # Restore-verify: unwrap the DKEK-wrapped backup into a scratch key slot. Requires an ACTIVE
    # DKEK on the card (import must have run). A corrupt/truncated blob (no PUB payload) can NOT be
    # rebuilt -> exit non-zero, exactly as the real tool fails when the wrap is unrestorable.
    blob="$2"
    [ -f "$S/dkek_loaded" ] || { echo "sc-hsm-tool(model): no active DKEK — cannot unwrap" >&2; exit 1; }
    [ -s "$blob" ] || { echo "sc-hsm-tool(model): empty/missing wrapped blob" >&2; exit 1; }
    pub_b64="$(sed -n 's/^PUB://p' "$blob" 2>/dev/null)"
    [ -n "$pub_b64" ] || { echo "sc-hsm-tool(model): wrapped blob is unrestorable (corrupt/truncated)" >&2; exit 1; }
    printf '%s' "$pub_b64" | python3 -c 'import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' > "$S/restored_pub.der" 2>/dev/null \
      || { echo "sc-hsm-tool(model): unwrap decode failed" >&2; exit 1; }
    echo "unwrapped key into scratch slot 2 (MODEL)"; exit 0;;
  *) echo "sc-hsm-tool(model): unhandled $*" >&2; exit 0;;
esac
STUB
chmod +x "$FAKE/sc-hsm-tool"

cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
# Faithful-enough HSM crypto model: keygen mints a REAL secp256k1 keypair (via the
# ceremony's own verify-hsm-control.py curve math), --read-object exports the SPKI pubkey,
# and --sign produces a REAL raw-ECDSA (r||s) signature. Set BAD_HSM=1 to model a
# malfunctioning/hostile device that EXPORTS A PUBKEY IT CANNOT SIGN FOR (wrong object /
# faulty keygen / bad firmware) — the sign still uses the real key, so the proof must fail.
S="${SCHSM_STATE:?}"
args="$*"
case "$args" in
  *--list-objects*)
    # Model a transient PKCS#11 enumeration failure (module not re-attached after qvm-usb,
    # pcscd not ready, CCID glitch): print nothing and exit NON-ZERO. A blank card, by
    # contrast, enumerates SUCCESSFULLY with empty output. The guard must tell them apart.
    if [ "${PKCS11_LIST_FAIL:-0}" = 1 ]; then echo "error: PKCS11 function C_FindObjects failed" >&2; exit 1; fi
    # public-key objects are listable without a PIN; show the funding pubkey once a key exists
    if [ -f "$S/key_generated" ]; then echo "Public Key Object; EC"; echo "  label:      akash-funding"; fi
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
# a MISMATCHED pubkey (different private key, NOT held by the signer) for the bad-HSM case
d2=secrets.randbelow(v.N-1)+1
open(S+"/pub_bad.der","wb").write(spki(v.scalar_mul(d2,v.G)))
PY
    echo "Key pair generated, id 01, label akash-funding"; exit 0;;
  *--sign*)
    inp=""; out=""; prev=""
    for a in "$@"; do
      [ "$prev" = "-i" ] && inp="$a"
      [ "$prev" = "-o" ] && out="$a"
      prev="$a"
    done
    [ -f "$S/priv.hex" ] || { echo "no key to sign with" >&2; exit 1; }
    SCHSM_STATE="$S" SIGN_IN="$inp" SIGN_OUT="$out" python3 - "$EMU_VERIFY" <<'PY'
import importlib.machinery, importlib.util, os, secrets, sys
V=sys.argv[1]; ldr=importlib.machinery.SourceFileLoader("v",V)
spec=importlib.util.spec_from_loader("v",ldr); v=importlib.util.module_from_spec(spec); ldr.exec_module(v)
S=os.environ["SCHSM_STATE"]
d=int(open(S+"/priv.hex").read().strip(),16)
digest=open(os.environ["SIGN_IN"],"rb").read()
z=int.from_bytes(digest,"big")
k=secrets.randbelow(v.N-1)+1
R=v.scalar_mul(k,v.G); r=R[0]%v.N
s=(v.inv_mod(k,v.N)*(z+r*d))%v.N
open(os.environ["SIGN_OUT"],"wb").write(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
PY
    echo "Using signature algorithm ECDSA"; exit 0;;
  *--read-object*)
    out=""; rid=""; prev=""
    for a in "$@"; do
      [ "$prev" = "-o" ] && out="$a"
      [ "$prev" = "--id" ] && rid="$a"
      prev="$a"
    done
    # id 02 is the restore-verify scratch slot (the key rebuilt by --unwrap-key); id 01 is the
    # born-in-HSM funding key. A restore-verify reads id 02 and byte-compares it to funding-pub.der.
    if [ "$rid" = "02" ] || [ "$rid" = "2" ]; then
      src="$S/restored_pub.der"
    else
      src="$S/pub.der"; [ "${BAD_HSM:-0}" = 1 ] && src="$S/pub_bad.der"
    fi
    [ -n "$out" ] && [ -f "$src" ] && cp "$src" "$out"
    exit 0;;
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
PRINTER=""
init_work

LAST_SHOWN=""
show(){ LAST_SHOWN="$*"; }     # capture the command run() is about to confirm (no echo)

reset_state(){ rm -f "$SCHSM_STATE"/* "$WORK"/funding-* "$WORK"/dkek.pbe 2>/dev/null; }

# =====================================================================================
hdr "REGRESSION: a SKIPPED DKEK import must ABORT before the funding key is generated"
reset_state
# operator confirms every step EXCEPT the DKEK import (answers 'n' there). With no DKEK
# loaded, generating the funding key would leave it with no recoverable backup.
ask(){ case "$LAST_SHOWN" in *import-dkek-share*) return 1;; *) return 0;; esac; }
out="$(step_hsm_funding 2>&1)"
[ ! -f "$SCHSM_STATE/key_generated" ] \
  && P "funding key NOT generated after DKEK import was skipped" \
  || F "BUG: funding key generated with NO DKEK backup (unrecoverable born-in-HSM key)"
grep -qiE "abort|refus" <<< "$out" \
  && P "wizard reports it aborted the HSM step" \
  || F "wizard did not report an abort when the DKEK import was skipped"
[ ! -f "$WORK/funding-wrapped.bin" ] \
  && P "no orphaned wrapped-backup left behind" \
  || F "a wrapped backup was produced despite the aborted DKEK flow"

# =====================================================================================
hdr "REGRESSION: a FAILED DKEK initialize must ABORT before the funding key is generated"
reset_state
# the DKEK domain is never created (initialize 'fails'): import then can't activate a DKEK.
ask(){ case "$LAST_SHOWN" in *--initialize*) return 1;; *) return 0;; esac; }
out="$(step_hsm_funding 2>&1)"
[ ! -f "$SCHSM_STATE/key_generated" ] \
  && P "funding key NOT generated after --initialize was skipped/failed" \
  || F "BUG: funding key generated despite a failed HSM initialize"

# =====================================================================================
hdr "#464: the DKEK share round trip is REFUSED -> re-mint, and no funding key"
# OpenSC 0.27.1 rebuilds the share password with its leading zero byte dropped, so 1 share file
# in 128 cannot be opened from its own correct shares (#460). The wizard's first import is the
# round trip that finds out. On a refusal nothing may be generated, the share file and the
# captured shares must go, and the operator must be told to re-mint before anyone leaves.
reset_state
ask(){ return 0; }
out="$(FAKE_ROUND_TRIP_REFUSED=1 step_hsm_funding 2>&1)"
[ ! -f "$SCHSM_STATE/key_generated" ] \
  && P "no funding key generated when the share round trip is refused" \
  || F "BUG: funding key generated under a DKEK share its own shares cannot open"
grep -q "DKEK SHARE ROUND TRIP FAILED" <<< "$out" \
  && P "wizard names the failed round trip" \
  || F "wizard did not report the refused round trip"
grep -q "RE-MINT NOW, before anyone leaves the room" <<< "$out" \
  && P "wizard tells the room to re-mint before leaving" \
  || F "wizard did not tell the room to re-mint"
[ ! -e "$WORK/dkek.pbe" ] && [ ! -e "$WORK/dkek-shares.txt" ] \
  && P "the refused share file and its captured shares are removed" \
  || F "a share file its own shares cannot open (or its shares) was left in the workdir"

# =====================================================================================
hdr "#464: shares the wizard failed to capture -> stop before the card is initialised"
reset_state
ask(){ return 0; }
out="$(FAKE_NO_SHARES=1 step_hsm_funding 2>&1)"
[ ! -f "$SCHSM_STATE/dkek_domain" ] \
  && P "the card is not initialised when there are no captured shares to test" \
  || F "BUG: --initialize ran although the round trip had no shares to feed"
grep -q "were not captured" <<< "$out" \
  && P "wizard says the shares were not captured" \
  || F "wizard did not explain the missing share capture"
[ ! -e "$WORK/dkek.pbe" ] && [ ! -e "$WORK/dkek-shares.txt" ] \
  && P "the untested share file and its capture are removed" \
  || F "a share file whose shares were never tested was left in the workdir"

# =====================================================================================
hdr "#464: a FAILED share creation leaves no captured shares behind"
reset_state
ask(){ return 0; }
out="$(FAKE_CREATE_FAILS=1 step_hsm_funding 2>&1)"
[ ! -f "$SCHSM_STATE/dkek_domain" ] \
  && P "the card is not initialised after a failed share creation" \
  || F "BUG: --initialize ran after the share creation failed"
[ ! -e "$WORK/dkek-shares.txt" ] \
  && P "the shares a failed creation displayed are not kept in the workdir" \
  || F "a failed creation's shares were left in the workdir"

# =====================================================================================
hdr "HAPPY PATH: all steps confirmed -> key generated AND wrapped, no abort"
reset_state
ask(){ return 0; }
out="$(step_hsm_funding 2>&1)"
[ -f "$SCHSM_STATE/key_generated" ] && P "happy path generates the funding key" || F "happy path did not generate the key"
[ -s "$WORK/funding-wrapped.bin" ]  && P "happy path wraps the key for DR backup" || F "happy path did not wrap the key"
[ "$(cat "$SCHSM_STATE/fed_ids" 2>/dev/null)" = " 1 2 3 4" ] \
  && P "the card's import was fed shares 1-4 through --pwd-shares-total 4" \
  || F "the card's import was not fed shares 1-4 (got '$(cat "$SCHSM_STATE/fed_ids" 2>/dev/null)')"
[ ! -e "$WORK/dkek-shares.txt" ] \
  && P "the captured shares are removed once the imports are done" \
  || F "the captured DKEK shares outlived the step"
grep -qiE "abort|refus" <<< "$out" && F "happy path wrongly aborted/refused" || P "happy path ran without aborting"
grep -qi "keypair-control proof PASSED" <<< "$(echo "$out")" \
  && P "happy path PROVES the HSM controls the private key before recording the address" \
  || F "happy path did not run the sign-then-verify keypair-control proof"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && P "happy path records the funding address (only after the proof passes)" \
  || F "happy path did not record a funding address on a passing proof"
grep -qi "restore-verify OK" <<< "$(echo "$out")" \
  && P "happy path RESTORE-VERIFIES the wrapped backup (unwrap round-trip + restored-pubkey match)" \
  || F "happy path did not restore-verify the wrapped DKEK backup before declaring the address fundable"

# =====================================================================================
hdr "RESTORE-VERIFY: an UNRESTORABLE wrapped backup (unwrap fails) must NOT yield a fundable address"
# THE CORE DEFECT: step 5 wrapped the born-in-HSM funding key's ONLY recoverable backup and it was
# burned to M-DISC with NO unwrap/restore-verify — the one backup path that skipped the reconstruct-
# verify every other path enforces. A wrap can return 0 yet be unrestorable (truncated write, faulty
# EEPROM, a DKEK a restore won't rebuild). If the primary HSM later dies the money is gone. Model an
# unrestorable blob and assert the wizard REFUSES to declare the address fundable.
reset_state
ask(){ return 0; }
out="$(BAD_WRAP=1 step_hsm_funding 2>&1)"
grep -qiE "RESTORE-VERIFY FAILED|could not (be )?unwrap|unrestorable|do NOT fund" <<< "$out" \
  && P "wizard detects the wrapped backup cannot be restored and warns not to fund" \
  || F "BUG: wizard did NOT detect an UNRESTORABLE wrapped backup (skips the reconstruct-verify)"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: wizard declared the address FUNDABLE despite an unrestorable backup (money-loss risk)" \
  || P "wizard refused to declare the address fundable when the backup does not restore"

# =====================================================================================
hdr "RESTORE-VERIFY: a backup that unwraps to a DIFFERENT key (pubkey mismatch) must NOT yield a fundable address"
# The wrap succeeds and the blob unwraps, but it reconstructs the WRONG key (wrong key-reference
# object). The restored pubkey must be byte-compared to funding-pub.der; a mismatch means the backup
# would NOT reconstruct the funding key, so the address must not be recorded as fundable.
reset_state
ask(){ return 0; }
out="$(MISMATCH_WRAP=1 step_hsm_funding 2>&1)"
grep -qiE "RESTORE-VERIFY FAILED|does NOT .*match|do NOT fund" <<< "$out" \
  && P "wizard detects the restored pubkey does not match the funding pubkey" \
  || F "BUG: wizard did NOT detect that the backup restores a DIFFERENT key"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: address declared fundable despite the backup restoring a different key" \
  || P "wizard refused fundability on a restored-pubkey mismatch"

# =====================================================================================
hdr "RESTORE-VERIFY: skipping the restore-verify (operator declines the unwrap) must NOT yield a fundable address"
reset_state
ask(){ case "$LAST_SHOWN" in *unwrap-key*) return 1;; *) return 0;; esac; }
out="$(step_hsm_funding 2>&1)"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: address declared fundable even though the restore-verify was skipped" \
  || P "wizard refused fundability when the restore-verify (unwrap) was skipped"

# =====================================================================================
hdr "KEYPAIR-CONTROL PROOF: an HSM that EXPORTS A PUBKEY IT CANNOT SIGN FOR must NOT yield an address"
# The core defect: step 4 derived + recorded the funding address straight from the exported
# pubkey with NO proof the device holds the matching private key. A faulty keygen / wrong --id
# object / hostile firmware hands back a pubkey whose private key it does not have; funding that
# address loses the money forever. Model it: read-object exports a MISMATCHED pubkey while sign
# uses the real key -> the signature cannot verify against the exported pubkey.
reset_state
ask(){ return 0; }
BAD_HSM=1 out="$(BAD_HSM=1 step_hsm_funding 2>&1)"
grep -qiE "KEYPAIR-CONTROL PROOF FAILED|do not fund" <<< "$out" \
  && P "wizard reports the keypair-control proof failed and warns not to fund" \
  || F "BUG: wizard did NOT detect that the HSM cannot sign for the exported pubkey"
grep -q "FUNDING ADDRESS (public" <<< "$(echo "$out")" \
  && F "BUG: wizard printed a FUNDING ADDRESS despite a failed key-control proof (unspendable-funds risk)" \
  || P "wizard refused to record a funding address when key control was NOT proven"
[ ! -s "$WORK/funding-wrapped.bin" ] \
  && P "wizard aborted before wrap — no funding workflow completed for an unprovable key" \
  || F "wizard proceeded to wrap despite a failed key-control proof"

# =====================================================================================
hdr "RE-INIT GUARD: refuse to --initialize over an existing funding key (would destroy it)"
reset_state
: > "$SCHSM_STATE/key_generated"          # a funding key already lives on the device
ask(){ return 0; }                        # operator would confirm initialize — must be blocked
out="$(step_hsm_funding 2>&1)"
grep -qiE "already exists|refus" <<< "$out" \
  && P "wizard refuses to re-initialise over an existing funding key" \
  || F "wizard did NOT refuse re-initialising over an existing funding key"
[ -f "$SCHSM_STATE/key_generated" ] \
  && P "existing funding key was NOT destroyed" \
  || F "BUG: re-initialise destroyed the existing funding key"

# =====================================================================================
hdr "ENUM-FAIL GUARD: a FAILED pubkey enumeration must NOT be treated as a blank card"
# The defect: the pre-initialize guard was `pkcs11-tool --list-objects 2>/dev/null | grep -qi
# akash-funding`. A transient PKCS#11 read error (token not re-attached after qvm-usb, pcscd
# not ready, CCID glitch) makes list-objects print NOTHING and exit non-zero; 2>/dev/null hides
# it and grep's no-match makes the guard FALSE, so --initialize proceeds and WIPES a non-
# exportable funding key that has no plaintext copy. The guard MUST fail closed: abort on any
# enumeration error instead of assuming the card is blank.
reset_state
# tag the pre-existing born-in-HSM key with a sentinel so we can tell it apart from any NEW
# key the destructive re-run would mint (--initialize rm's it, then keygen recreates it blank).
echo ORIGINAL-FUNDING-KEY > "$SCHSM_STATE/key_generated"
ask(){ return 0; }                        # operator would confirm initialize — must be blocked
out="$(PKCS11_LIST_FAIL=1 step_hsm_funding 2>&1)"
[ "$(cat "$SCHSM_STATE/key_generated" 2>/dev/null)" = ORIGINAL-FUNDING-KEY ] \
  && P "funding key survived a transient enumeration failure (guard failed closed)" \
  || F "BUG: --initialize wiped the funding key when list-objects merely FAILED to enumerate"
grep -qiE "enumerat|could not|refus|abort" <<< "$out" \
  && P "wizard reports it refused to initialise on an enumeration failure" \
  || F "wizard did NOT report aborting when pubkey enumeration failed"
[ ! -f "$SCHSM_STATE/dkek_domain" ] || {
  # If --initialize ran it would have (re)written the DKEK domain and cleared key_generated.
  F "BUG: --initialize executed despite an unreadable token"
}

# =====================================================================================
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
