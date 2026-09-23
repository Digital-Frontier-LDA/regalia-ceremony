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
set -uo pipefail
# TESTS, not HERE: sourcing ceremony.sh below sets HERE to qubes/scripts.
TESTS="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 TMPDIR="$ROOT" CEREMONY_MODE=prod
export EMU_YKMAN_STATE="$ROOT/yk"
export PATH="$TESTS/../bin:$PATH"
PY="${PYTHON:-python3}"

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
if what == "manifest":
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
    open(out, "w").write(t.commission_transcript())
EOF
}
{ fixture "$TESTS" manifest "$ROOT/manifest.json" \
  && fixture "$TESTS" manifest "$ROOT/bad-manifest.json" touch-always \
  && fixture "$TESTS" manifest "$ROOT/two-slot-manifest.json" two-slots \
  && fixture "$TESTS" commission "$ROOT/commission.txt"; } || { echo "  FAIL cannot build fixtures"; exit 1; }

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
before="$(sha256sum < "$ROOT/manifest.json")"
out="$(drive $'m\nyubikey-sitea\n36345471\nm\nyubikey-siteb\n25923905\nq' \
        CEREMONY_MANIFEST="$ROOT/manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EV")"; rc=$?
[ "$rc" = 0 ] && P "the ceremony completes" || { F "the ceremony failed (rc=$rc)"; printf '%s\n' "$out" | tail -15; }
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
out="$(drive $'m\nyubikey-sitea\n36345471\nq' CEREMONY_MANIFEST="$ROOT/manifest.json" CEREMONY_MANIFEST_EVIDENCE_DIR="$EV2")"; rc=$?
{ [ "$rc" != 0 ] && grep -q "left without evidence" <<< "$out" && grep -q "record REFUSED" <<< "$out"; } \
  && P "record refuses the unproven siteb binding, by name" || F "record accepted a fleet with a binding unproven (rc=$rc)"
[ -e "$EV2/custody-manifest.qualified.json" ] && F "a refused record wrote a manifest" || P "nothing written"

# =================================================================================================
hdr "A token that reports an imported key: refused at the device"
EV3="$ROOT/ev3"; mkdir -p "$EV3"
out="$(drive $'m\nyubikey-sitea\n11110001\nq' CEREMONY_MANIFEST="$ROOT/manifest.json" \
        CEREMONY_MANIFEST_EVIDENCE_DIR="$EV3" EMU_YKMAN_ORIGIN=IMPORTED)"; rc=$?
grep -q "reports Origin IMPORTED" <<< "$out" && grep -q "NOT provisioned as planned" <<< "$out" \
  && P "the step refuses the token's own IMPORTED report (ADR-0002 D5)" || F "an imported key was captured as evidence"
ls "$EV3"/*.json >/dev/null 2>&1 && F "evidence was written for an imported key" || P "no evidence written for it"
[ "$rc" != 0 ] && P "and the ceremony does not end as a success" || F "the ceremony ended rc=0"

EV4="$ROOT/ev4"; mkdir -p "$EV4"
out="$(drive $'m\nyubikey-sitea\n11110002\nq' CEREMONY_MANIFEST="$ROOT/two-slot-manifest.json" \
        CEREMONY_MANIFEST_EVIDENCE_DIR="$EV4" EMU_YKMAN_ORIGIN=IMPORTED)"
{ [ -d "$EMU_YKMAN_STATE/11110002/9c" ] && [ ! -d "$EMU_YKMAN_STATE/11110002/9a" ]; } \
  && P "a token that lied about one slot gets no further keys generated on it" \
  || F "the step kept generating on a token that reported an imported key"

printf '\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
