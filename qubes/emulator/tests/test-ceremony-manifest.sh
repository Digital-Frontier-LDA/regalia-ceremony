#!/usr/bin/env bash
# test-ceremony-manifest.sh — the wizard, driven by a custody manifest (regalia#28), on emulators.
#
# test_ceremony_manifest.py proves ceremony-manifest.py on its own. This proves the WIRING: that the
# real main() runs `plan` before any key can be generated, that its YubiKey step generates with the
# policies the MANIFEST names and captures the token's own report of them, that `record` runs at the
# end and either writes a qualified manifest or refuses and writes nothing — and, first, that none of
# this changes the wizard in any way when no manifest is supplied.
#
# The tokens are the ykman shim in ../bin: real openssl keys, per-serial state, and ykman 5.6's exact
# `piv keys info` layout. The Nitrokey side is a commission-card.sh transcript fixture, because the
# card is commissioned at the rack by commission-card.sh (tested in test-commission-card.sh), and the
# ceremony only consumes what that prints. No hardware is touched.
#
# THE OPERATION PROOF (regalia#28 criterion 3). Each key must also be SEEN TO SIGN: the m) step runs
# operation-proof.sh on every YubiKey key it generates, and the Nitrokey's proof is made the way it is
# at the rack — operation-proof.sh against the card whose key the transcript pins. Both go through the
# pkcs11-tool shim's token model (ykcs11 for the YubiKeys, EMU_P11_TOKENS for the Nitrokey), which is
# real openssl crypto and never reaches the real OpenSC binary: EMU_PKCS11_REAL points at a tripwire
# that fails the suite if anything tries.
set -uo pipefail
# TESTS, not HERE: sourcing ceremony.sh below sets HERE to qubes/scripts.
TESTS="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 TMPDIR="$ROOT" CEREMONY_MODE=prod
export EMU_YKMAN_STATE="$ROOT/yk"
# The emulator's ykman issues Yubico-shaped attestations under its own CA (qubes/emulator/bin/ykman
# emu_ca); ceremony-manifest trusts that CA only because this is a simulation and it is named here.
export REGALIA_YUBICO_SIMULATED_TRUST_DIR="$EMU_YKMAN_STATE/trust"
export PATH="$TESTS/../bin:$PATH"
PY="${PYTHON:-python3}"
# The tokens' PIN, distinctive so the leak checks below cannot match anything by accident.
TOKEN_PIN="q7PIN4zk"
export EMU_P11_PIN="$TOKEN_PIN" EMU_P11_TOKENS="$ROOT/nk" EMU_P11_ARGV_LOG="$ROOT/p11-argv.log"
export CEREMONY_YKCS11_MODULE="$ROOT/lib/libykcs11.so.2" CEREMONY_PKCS11_MODULE="$ROOT/lib/opensc-pkcs11.so"
mkdir -p "$ROOT/lib" "$EMU_P11_TOKENS"; : > "$CEREMONY_YKCS11_MODULE"; : > "$CEREMONY_PKCS11_MODULE"
# THE REAL-HARDWARE TRIPWIRE. The shim hands anything its token model does not own to EMU_PKCS11_REAL;
# here that is a script that records the attempt and fails, so no call can reach an attached card.
printf '#!/bin/sh\necho "$*" >> "%s"\necho "REAL PKCS11-TOOL INVOKED — refused by the test" >&2\nexit 99\n' \
  "$ROOT/real-p11.log" > "$ROOT/lib/real-pkcs11-tool"; chmod +x "$ROOT/lib/real-pkcs11-tool"
export EMU_PKCS11_REAL="$ROOT/lib/real-pkcs11-tool"

# shellcheck disable=SC1090
source "$TESTS/../../scripts/ceremony.sh"
ask(){ return 0; }
pause(){ :; }
require_airgap_and_tools(){ :; }   # preflight has its own suites; this one is about the manifest
pick_printer(){ :; }
# After the source: ceremony.sh installs its own EXIT trap, which would otherwise replace this one.
trap 'rm -rf "$ROOT"' EXIT

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# Fixtures come from the python suite, so both tiers test the same fleet.
fixture(){ "$PY" - "$@" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import test_ceremony_manifest as t
what, out = sys.argv[2], sys.argv[3]
if what == "kek-manifest":
    open(out, "w").write(json.dumps(t.kek_manifest(yubikey=True), indent=2))
elif what == "manifest":
    m = t.fleet_manifest()
    if len(sys.argv) > 4 and sys.argv[4] == "touch-always":
        m["objects"][0]["bindings"][1]["touch_policy"] = "always"
    if len(sys.argv) > 4 and sys.argv[4] == "two-slots":
        # A second key on the same two tokens, in slot 9a, so one token has two planned slots.
        second = json.loads(json.dumps(m["objects"][0]))
        second["id"] = "second-signer"
        second["bindings"] = [b for b in second["bindings"] if b["backend"] == "yubikey-piv"]
        for b in second["bindings"]:
            b["object_id"] = "9a"
        m["objects"].append(second)
    open(out, "w").write(json.dumps(m, indent=2))
else:
    kw = dict(zip(("pin", "serial", "kek_id"), sys.argv[4:]))
    open(out, "w").write(t.commission_transcript(**kw))
EOF
}
{ fixture "$TESTS" manifest "$ROOT/manifest.json" \
  && fixture "$TESTS" manifest "$ROOT/bad-manifest.json" touch-always \
  && fixture "$TESTS" manifest "$ROOT/two-slot-manifest.json" two-slots \
  ; } || { echo "  FAIL cannot build fixtures"; exit 1; }

# The Nitrokey, as the rack leaves it: a key GENERATED on the card at id 0a (the manifest's p256), and
# the commission transcript pinning exactly that key. A decoy card is attached too, and lists FIRST, so
# the proof must find DENK0404144 by serial (it is slot 0x4, not slot 0).
mkdir -p "$EMU_P11_TOKENS/AAAA0000001" "$EMU_P11_TOKENS/DENK0404144"
nk_p11(){ pkcs11-tool --module "$CEREMONY_PKCS11_MODULE" --slot 0x4 "$@"; }
{ NKPIN="$TOKEN_PIN" nk_p11 --login --pin env:NKPIN --keypairgen --key-type EC:prime256v1 --id 0a >/dev/null \
  && nk_p11 --read-object --type pubkey --id 0a --output-file "$ROOT/nk.der" \
  && NK_PIN="sha256:$(sha256sum < "$ROOT/nk.der" | awk '{print $1}')" \
  && fixture "$TESTS" commission "$ROOT/commission.txt" "$NK_PIN"; } || { echo "  FAIL cannot build the Nitrokey"; exit 1; }
# operation-proof.sh for the Nitrokey, the way the operator runs it after commission-card.sh.
nk_proof(){ "$TESTS/../../scripts/operation-proof.sh" --operation sign --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 0a \
              --device-id nitrokey-sitea --out "$1/opproof-nitrokey-sitea-0a.json" <<< "$TOKEN_PIN" 2>&1; }

# Drive the real main() in a subshell with a scripted stdin; $1 = the stdin, rest = env assignments.
# shellcheck disable=SC2163  # "$@" is NAME=value pairs, exported as given
drive(){ local input="$1"; shift; ( export "$@"; trap cleanup EXIT; main ) <<< "$input" 2>&1; }

# =================================================================================================
hdr "No manifest: the wizard is exactly what it was"
unset CEREMONY_MANIFEST_EVIDENCE_DIR
out="$(CEREMONY_MANIFEST='' manifest_plan 2>&1)"; rc=$?
[ "$rc" = 0 ] && [ -z "$out" ] && P "manifest_plan is a silent no-op without CEREMONY_MANIFEST" \
  || F "manifest_plan did something without a manifest (rc=$rc): $out"
out="$(CEREMONY_MANIFEST='' manifest_record 2>&1)"; rc=$?
[ "$rc" = 0 ] && [ -z "$out" ] && P "manifest_record is a silent no-op without CEREMONY_MANIFEST" \
  || F "manifest_record did something without a manifest (rc=$rc): $out"
out="$(drive $'m\nq' CEREMONY_MANIFEST=)"; rc=$?
{ [ "$rc" = 0 ] && grep -q "workdir shredded on exit" <<< "$out"; } \
  && P "main() runs to its normal end" || F "main() without a manifest did not finish (rc=$rc)"
grep -q "m) Manifest" <<< "$out" && F "the manifest menu entry shows with no manifest" \
  || P "no manifest menu entry"
grep -q "pick 1-9 or q" <<< "$out" && P "'m' is still an unknown choice, as before" \
  || F "'m' was handled without a manifest"
grep -q "Custody manifest" <<< "$out" && F "a manifest banner appeared with no manifest" \
  || P "no plan or record banner"

# =================================================================================================
hdr "Manifest without an evidence directory: refused before the menu"
out="$(drive q CEREMONY_MANIFEST="$ROOT/manifest.json")"; rc=$?
{ [ "$rc" != 0 ] && grep -q "CEREMONY_MANIFEST_EVIDENCE_DIR is not" <<< "$out"; } \
  && P "refuses: nowhere to keep the evidence" || F "started without an evidence dir (rc=$rc)"
grep -q "Choose a step" <<< "$out" && F "the menu rendered anyway" || P "the menu never rendered"

# =================================================================================================
hdr "A manifest the ceremony cannot honour: refused before any key exists"
out="$(drive q CEREMONY_MANIFEST="$ROOT/bad-manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$ROOT/ev-bad")"; rc=$?
{ [ "$rc" != 0 ] && grep -q "touch_policy=never" <<< "$out" && grep -q "cannot honour" <<< "$out"; } \
  && P "plan refuses touch_policy=always, by name" || F "a touch=always manifest was accepted (rc=$rc)"
grep -q "Choose a step" <<< "$out" && F "the menu rendered anyway" || P "the menu never rendered"

# =================================================================================================
hdr "Mixed fleet: plan, generate two YubiKeys from the manifest, record with the Nitrokey transcript"
EV="$ROOT/ev"; mkdir -p "$EV"; cp "$ROOT/commission.txt" "$EV/commission-nitrokey-sitea-0a.txt"
nkout="$(nk_proof "$EV")"; rc=$?
{ [ "$rc" = 0 ] && grep -q "OPERATION PROOF .*nitrokey-pkcs11 serial=DENK0404144 object=0a p256" <<< "$nkout"; } \
  && P "the Nitrokey's key signs with its PIN at the rack (found by serial past a decoy card)" \
  || F "the Nitrokey operation proof failed (rc=$rc): $nkout"
before="$(sha256sum < "$ROOT/manifest.json")"
out="$(drive $'m\nyubikey-sitea\n36345471\n'"$TOKEN_PIN"$'\nm\nyubikey-siteb\n25923905\n'"$TOKEN_PIN"$'\nq' \
        CEREMONY_MANIFEST="$ROOT/manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EV")"; rc=$?
[ "$rc" = 0 ] && P "the ceremony completes" || { F "the ceremony failed (rc=$rc)"; printf '%s\n' "$out" | tail -15; }
[ "$(grep -c "OPERATION PROOF .*yubikey-piv" <<< "$out")" = 2 ] \
  && P "m) proved each generated YubiKey key signs with the PIN, right after generation" \
  || F "the m) step did not produce two YubiKey operation proofs"
[ "$(grep -c "OPERATION VERIFIED" <<< "$out")" = 3 ] \
  && P "record re-verified all three operation proofs before qualifying" || F "record did not re-verify three proofs"
{ grep -qF -- "$TOKEN_PIN" <<< "$out$nkout" || grep -rqF -- "$TOKEN_PIN" "$EV" "$EMU_P11_ARGV_LOG"; } \
  && F "THE TOKEN PIN APPEARS in the wizard output, the evidence or a pkcs11-tool command line" \
  || P "the PIN is in no output, no evidence file and no pkcs11-tool command line"
grep -q -- "--pin env:REGALIA_OPPROOF_PIN" "$EMU_P11_ARGV_LOG" \
  && P "pkcs11-tool got the PIN by environment reference only" || F "no env: PIN reference was seen on the token"
grep -q "PLAN regalia-test-fleet (site=all backend=all): 3 binding(s)" <<< "$out" \
  && P "plan ran at the start and names 3 bindings" || F "no plan at the start"
grep -q -- "--pin-policy 'ALWAYS' --touch-policy 'NEVER' '9c'" <<< "$out" \
  && P "the siteb token was generated with the manifest's pin_policy=always" || F "generation did not use the manifest's policies"
Q="$EV/custody-manifest.qualified.json"
if [ -s "$Q" ]; then
  P "record wrote the qualified manifest"
  check="$("$PY" - "$Q" "$EMU_YKMAN_STATE" <<'EOF'
import hashlib, json, subprocess, sys
m = json.load(open(sys.argv[1]))
nk, a, b = m["objects"][0]["bindings"]
def pin(serial):
    der = subprocess.run(["openssl", "pkey", "-in", f"{sys.argv[2]}/{serial}/9c/key.pem", "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    return "sha256:" + hashlib.sha256(der).hexdigest()
ok = [nk["state"] == a["state"] == b["state"] == "qualified",
      nk["device_serial"] == "DENK0404144",
      (a["device_serial"], a["pin_policy"], a["touch_policy"]) == ("36345471", "once", "never"),
      (b["device_serial"], b["pin_policy"]) == ("25923905", "always"),
      a["public_key_sha256"] == pin("36345471"), b["public_key_sha256"] == pin("25923905"),
      [x["state"] for x in m["objects"][1]["bindings"]] == ["planned", "planned"]]
print("ok" if all(ok) else f"mismatch {ok}")
EOF
)"
  [ "$check" = ok ] && P "three bindings qualified with the tokens' own serials, policies and key digests" \
    || F "the qualified manifest is wrong: $check"
else
  F "no qualified manifest was written"
fi
[ "$(sha256sum < "$ROOT/manifest.json")" = "$before" ] && P "the input manifest was not rewritten" \
  || F "the wizard rewrote the input manifest"

# =================================================================================================
hdr "One YubiKey never generated: record refuses and writes nothing"
EV2="$ROOT/ev2"; mkdir -p "$EV2"; cp "$ROOT/commission.txt" "$EV2/"
out="$(drive $'m\nyubikey-sitea\n36345471\n'"$TOKEN_PIN"$'\nq' CEREMONY_MANIFEST="$ROOT/manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EV2")"; rc=$?
{ [ "$rc" != 0 ] && grep -q "left without evidence" <<< "$out" && grep -q "record REFUSED" <<< "$out"; } \
  && P "record refuses the unproven siteb binding, by name" || F "record accepted a fleet with a binding unproven (rc=$rc)"
[ -e "$EV2/custody-manifest.qualified.json" ] && F "a refused record wrote a manifest" || P "nothing written"

# =================================================================================================
hdr "A token that reports an imported key: refused at the device"
EV3="$ROOT/ev3"; mkdir -p "$EV3"
out="$(drive $'m\nyubikey-sitea\n11110001\nq' CEREMONY_MANIFEST="$ROOT/manifest.json" \
        CEREMONY_MANIFEST_EVIDENCE_DIR="$EV3" EMU_YKMAN_ORIGIN=IMPORTED)"; rc=$?
grep -q "attests only keys generated on it" <<< "$out" && grep -q "NOT provisioned as planned" <<< "$out" \
  && P "the step refuses an imported key: the token will not attest it (ADR-0002 D5)" || F "an imported key was captured as evidence"
ls "$EV3"/*.json >/dev/null 2>&1 && F "evidence was written for an imported key" || P "no evidence written for it"
[ "$rc" != 0 ] && P "and the ceremony does not end as a success" || F "the ceremony ended rc=0"

EV4="$ROOT/ev4"; mkdir -p "$EV4"
out="$(drive $'m\nyubikey-sitea\n11110002\nq' CEREMONY_MANIFEST="$ROOT/two-slot-manifest.json" \
        CEREMONY_MANIFEST_EVIDENCE_DIR="$EV4" EMU_YKMAN_ORIGIN=IMPORTED)"
{ [ -d "$EMU_YKMAN_STATE/11110002/9c" ] && [ ! -d "$EMU_YKMAN_STATE/11110002/9a" ]; } \
  && P "a token that lied about one slot gets no further keys generated on it" \
  || F "the step kept generating on a token that reported an imported key"

# =================================================================================================
hdr "Operation behaviour: a wrong PIN leaves the binding unqualified, and record says why"
EV5="$ROOT/ev5"; mkdir -p "$EV5"; cp "$ROOT/commission.txt" "$EV5/"; nk_proof "$EV5" >/dev/null
out="$(drive $'m\nyubikey-sitea\n36345471\n'"$TOKEN_PIN"$'\nm\nyubikey-siteb\n25923905\nWRONGpin9\nq' \
        CEREMONY_MANIFEST="$ROOT/manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EV5")"; rc=$?
grep -q "CKR_PIN_INCORRECT) — ONE RETRY WAS SPENT" <<< "$out" \
  && P "the token refused the wrong PIN and the operator is told a retry was spent" || F "a wrong PIN was not reported"
[ "$(cat "$EMU_YKMAN_STATE/25923905/pin-tries" 2>/dev/null)" = 2 ] \
  && P "exactly one retry was spent — no automatic second attempt" || F "the proof retried a wrong PIN"
[ -e "$EV5/opproof-yubikey-yubikey-siteb-9c.json" ] && F "a proof was written for a refused PIN" || P "no proof written for it"
{ [ "$rc" != 0 ] && grep -q "no operation proof for objects\[0\](release-signing-key).bindings\[2\]" <<< "$out" \
  && grep -q "record REFUSED" <<< "$out"; } \
  && P "record refuses the unproven binding by name" || F "record accepted a binding with no operation proof (rc=$rc)"
[ -e "$EV5/custody-manifest.qualified.json" ] && F "a refused record wrote a manifest" || P "nothing written"
grep -qF "WRONGpin9" <<< "$out" && F "the wrong PIN was echoed" || P "the wrong PIN was not echoed either"
echo 3 > "$EMU_YKMAN_STATE/25923905/pin-tries"

# =================================================================================================
hdr "Operation behaviour: a token that returns a bad signature is refused at the token"
EV6="$ROOT/ev6"; mkdir -p "$EV6"
out="$(drive $'m\nyubikey-sitea\n36345471\n'"$TOKEN_PIN"$'\nq' CEREMONY_MANIFEST="$ROOT/manifest.json" \
        CEREMONY_MANIFEST_EVIDENCE_DIR="$EV6" EMU_P11_BAD_SIGNATURE=1)"; rc=$?
grep -q "the token's signature does not verify" <<< "$out" && grep -q "NOTHING WRITTEN" <<< "$out" \
  && P "the bad signature is refused at the token" || F "a bad signature was accepted at the token"
ls "$EV6"/opproof-* >/dev/null 2>&1 && F "a proof was written for a bad signature" || P "no proof written"
[ "$rc" != 0 ] && P "and the ceremony does not end as a success" || F "the ceremony ended rc=0"
EV6b="$ROOT/ev6b"; mkdir -p "$EV6b"
drive $'m\nyubikey-sitea\n11110003\n'"$TOKEN_PIN"$'\nq' CEREMONY_MANIFEST="$ROOT/two-slot-manifest.json" \
  CEREMONY_MANIFEST_EVIDENCE_DIR="$EV6b" EMU_P11_BAD_SIGNATURE=1 >/dev/null
{ [ -d "$EMU_YKMAN_STATE/11110003/9c" ] && [ ! -d "$EMU_YKMAN_STATE/11110003/9a" ]; } \
  && P "a token whose key failed its operation proof gets no further keys generated on it" \
  || F "the step kept generating on a token whose key did not sign"
# The full, good fleet from above, then siteb's key regenerated and proved again: its evidence still
# pins the FIRST key, its proof now signs with the second. record must refuse, by name.
EV7="$ROOT/ev7"; cp -r "$EV" "$EV7"; rm -f "$EV7/custody-manifest.qualified.json"
ykman --device 25923905 piv keys generate --algorithm ECCP256 --pin-policy ALWAYS --touch-policy NEVER 9c "$ROOT/regen.pem"
"$TESTS/../../scripts/operation-proof.sh" --operation sign --backend yubikey-piv --serial 25923905 --object-id 9c \
  --device-id yubikey-siteb --out "$EV7/opproof-yubikey-yubikey-siteb-9c.json" <<< "$TOKEN_PIN" >/dev/null 2>&1 \
  || F "could not re-prove the regenerated slot"
out="$(drive q CEREMONY_MANIFEST="$ROOT/manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EV7")"; rc=$?
{ [ "$rc" != 0 ] && grep -q "the operation proof is over a different key" <<< "$out" \
  && grep -q "Was the slot regenerated" <<< "$out"; } \
  && P "record refuses a proof over a key other than the one being pinned" || F "a proof over another key was accepted (rc=$rc)"
[ -e "$EV7/custody-manifest.qualified.json" ] && F "a refused record wrote a manifest" || P "nothing written"

# =================================================================================================
hdr "KEKs (ADR-0002): RSA unwrap and EC key-agreement provision end to end with a labelled round trip"
# The Nitrokey's main role: an RSA envelope KEK (0b) and an EC key-agreement key (0c) on each of two
# cards, plus an RSA PIV KEK (slot 9d) on both YubiKeys through the wizard's m) step. A signature cannot
# prove these operations, so each is proven by a live round trip — attested now, not re-verifiable later.
fixture "$TESTS" kek-manifest "$ROOT/kek-manifest.json" || F "cannot build the KEK manifest"
mkdir -p "$EMU_P11_TOKENS/DENK0000002"      # lists as 0x4 now; DENK0404144 moves to 0x8
EVK="$ROOT/evk"; mkdir -p "$EVK"
for card in "DENK0000002 0x4 nitrokey-siteb" "DENK0404144 0x8 nitrokey-sitea"; do
  set -- $card
  for kg in "0b rsa:2048 decrypt" "0c EC:prime256v1 key-agreement"; do
    # shellcheck disable=SC2086
    set -- "$1" "$2" "$3" $kg
    NKPIN="$TOKEN_PIN" pkcs11-tool --module "$CEREMONY_PKCS11_MODULE" --slot "$2" --login --pin env:NKPIN \
      --keypairgen --key-type "$5" --id "$4" >/dev/null
    pkcs11-tool --module "$CEREMONY_PKCS11_MODULE" --slot "$2" --read-object --type pubkey --id "$4" \
      --output-file "$ROOT/kek.der"
    fixture "$TESTS" commission "$EVK/commission-$3-$4.txt" "sha256:$(sha256sum < "$ROOT/kek.der" | awk '{print $1}')" "$1" "$4"
    kout="$("$TESTS/../../scripts/operation-proof.sh" --operation "$6" --backend nitrokey-pkcs11 --serial "$1" \
             --object-id "$4" --device-id "$3" --out "$EVK/opproof-$3-$4.json" <<< "$TOKEN_PIN" 2>&1)" \
      && grep -q "completed a live $6 round trip" <<< "$kout" \
      && P "Nitrokey $1 id $4: $6 round trip at the rack" || F "Nitrokey $1 id $4 $6 round trip failed: $kout"
  done
done
out="$(drive $'m\nyubikey-sitea\n36345471\n'"$TOKEN_PIN"$'\nm\nyubikey-siteb\n25923905\n'"$TOKEN_PIN"$'\nq' \
        CEREMONY_MANIFEST="$ROOT/kek-manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EVK")"; rc=$?
[ "$rc" = 0 ] && P "the KEK ceremony completes" || { F "the KEK ceremony failed (rc=$rc)"; printf '%s\n' "$out" | tail -15; }
grep -q "operation-proof.sh --operation 'decrypt' --backend yubikey-piv" <<< "$out" \
  && P "m) proved each YubiKey KEK with a decrypt round trip, the operation the manifest's proof class names" \
  || F "m) did not run a decrypt round trip for the PIV KEK"
[ "$(grep -c "OPERATION ATTESTED" <<< "$out")" = 6 ] && ! grep -q "OPERATION VERIFIED" <<< "$out" \
  && P "record qualified all six KEK bindings as ATTESTED (never reported as re-verified)" \
  || F "record did not attest six KEK bindings"
grep -q "ATTESTED AT CEREMONY TIME, NOT RE-VERIFIABLE AFTERWARDS" <<< "$out" \
  && P "plan states plainly that a round trip is not re-verifiable afterwards" || F "plan did not label the round trip"
check="$("$PY" -c 'import json,sys; m=json.load(open(sys.argv[1])); print(" ".join(b["state"] for o in m["objects"][:3] for b in o["bindings"]))' \
          "$EVK/custody-manifest.qualified.json" 2>/dev/null)"
[ "$check" = "qualified qualified qualified qualified qualified qualified" ] \
  && P "the qualified manifest carries all six KEK bindings" || F "the KEK bindings were not qualified: $check"
{ grep -qF -- "$TOKEN_PIN" <<< "$out" || grep -rqF -- "$TOKEN_PIN" "$EVK"; } && F "THE PIN APPEARS in the KEK run" \
  || P "the PIN is in no output and no KEK evidence"
! grep -rq '"challenge_b64"' "$EVK"/opproof-*.json && P "no round-trip proof records its plaintext challenge" \
  || F "a round-trip proof recorded its plaintext challenge"

# DRIFT: a ceremony-manifest.py whose piv-steps names no proof operation (an older copy, a hand-edited
# one) must stop the step — never fall back to a default proof that could be the wrong class.
EVD="$ROOT/evd"; mkdir -p "$EVD"
out="$( ( manifest_tool(){ if [ "$1" = piv-steps ]; then python3 "$HERE/ceremony-manifest.py" "$@" | cut -f1-5; \
                           else python3 "$HERE/ceremony-manifest.py" "$@"; fi; }
         # shellcheck disable=SC2034  # read by step_manifest_yubikey, sourced from ceremony.sh
         CEREMONY_MANIFEST="$ROOT/kek-manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EVD" WORK="$EVD"
         step_manifest_yubikey ) <<< $'yubikey-sitea\n11110007\n'"$TOKEN_PIN" 2>&1)"; rc=$?
{ [ "$rc" != 0 ] && grep -q "piv-steps named no proof operation" <<< "$out" && ! ls "$EVD"/opproof-* >/dev/null 2>&1; } \
  && P "a step list with no proof operation stops the step; no proof is guessed" \
  || F "the m) step proceeded without a proof operation (rc=$rc): $(tail -5 <<< "$out")"
# AND THE TOKEN WAS NEVER TOUCHED. `piv keys generate` replaces the slot's key irreversibly, so the
# refusal must come BEFORE it (review of #39): no key generated for 11110007, no evidence written.
{ ! ls "${EMU_YKMAN_STATE:-${TMPDIR:-/tmp}/emu-ykman}/11110007"/*/key.pem >/dev/null 2>&1 \
  && ! ls "$EVD"/yubikey-* >/dev/null 2>&1; } \
  && P "…and it stopped before generating: no key replaced on the token, no evidence written" \
  || F "a key was GENERATED (irreversibly replacing the slot) before the step list was refused"

# =================================================================================================
hdr "Operation behaviour: nothing reached the real pkcs11-tool"
[ -e "$ROOT/real-p11.log" ] && F "THE REAL pkcs11-tool WAS INVOKED: $(head -3 "$ROOT/real-p11.log")" \
  || P "every pkcs11-tool call was served by the emulator's token model"

printf '\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
