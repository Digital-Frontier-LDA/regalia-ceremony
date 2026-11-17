#!/usr/bin/env bash
# test-genesis-step.sh — ceremony.sh step g (regalia-ceremony#134, regalia-htl; regalia-kms#361, #438): regalia-kms's
# `manifest propose --genesis` run from the image's regalia-kms tree with --offline-keys-record set to this session's
# offline-keys.record.json, after the step has checked that record as kms takes it (offline-keys.py genesis-check).
# Three cases the bead names: PASS (the record, the card record and the signing state handed over), a MISSING record and
# FORGED records (each refused before any regalia-kms code runs). And the typed second channel for K_A
# (CEREMONY_GENESIS_TYPED_ANCHOR_CHECK, default 1; the owner's decision is pending) and the tree-digest gate.
# regalia-kms stands in as a tree whose deploy/baremetal/manifest.py logs its argv and writes --out: what kms itself does
# with the record is pinned by test_genesis_record_contract.py (against kms's own code, REGALIA_KMS_GENESIS_DIR).
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins first, as under run-tests.sh (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
SCRIPTS="$(cd "$SCRIPTS" && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
skip_dep(){ # a missing dependency: a skip by hand, a failure where REQUIRE_EMULATOR_DEPS=1 (CI), so a test that never ran is never green (#166)
  if [ "${REQUIRE_EMULATOR_DEPS:-0}" = 1 ]; then echo "  FAIL: $1, and REQUIRE_EMULATOR_DEPS=1: this test must run here, not skip"; exit 1; fi
  echo "  SKIP: $1 (REQUIRE_EMULATOR_DEPS=1 makes this a failure)"; exit 0
}
python3 -Es -c 'import shamir_mnemonic, cryptography' 2>/dev/null || { skip_dep "python3 lacks shamir-mnemonic or cryptography"; }
command -v age >/dev/null && command -v age-keygen >/dev/null || { skip_dep "age is not installed"; }
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ALLOW_SWAP=1 CEREMONY_THRESHOLD=2 CEREMONY_SHARES=3 PYTHONDONTWRITEBYTECODE=1
unset CEREMONY_GENESIS_TYPED_ANCHOR_CHECK
T="$(mktemp -d)"; export T SCRIPTS
trap 'rm -rf -- "$T"' EXIT
if grep -q '^AGE-SECRET-KEY-PQ-1' <<< "$(age-keygen -pq 2>/dev/null)"; then PQ=(-pq); else PQ=(); export CEREMONY_ALLOW_CLASSICAL_BREAKGLASS=1; fi

# the image's regalia-kms tree, stood in for: propose logs its argv (one JSON line) and writes --out, or fails on request
mkdir -p "$T/kms/deploy/baremetal"
: > "$T/kms/deploy/__init__.py"; : > "$T/kms/deploy/baremetal/__init__.py"
cat > "$T/kms/deploy/baremetal/manifest.py" <<'PY'
import json, os, sys
args = sys.argv[1:]
with open(os.environ["GEN_PROPOSE_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
if os.environ.get("GEN_PROPOSE_FAIL"):
    print("manifest: REFUSED: the stand-in was asked to fail", file=sys.stderr)
    sys.exit(1)
with open(args[args.index("--out") + 1], "x") as f:
    f.write('{"stand-in": "genesis"}\n')
print("UNSIGNED genesis (stand-in) written")
PY
KMS_DIGEST="$(python3 -Es "$SCRIPTS/offline-keys.py" tree-digest --root "$T/kms")"
# the enrolment directory (two nodes), the measurements and the system-phase key: opaque to the step, read by kms
for n in kms-a kms-b; do mkdir -p "$T/nodes/$n"; for f in bundle.json keep.json activation.json; do printf '{"node":"%s"}\n' "$n" > "$T/nodes/$n/$f"; done; done
printf '{}\n' > "$T/measurements.json"; printf -- '-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n' > "$T/system.pem"

# the step k stand-in for the writer's terminal prompt (as test-card-record-step.sh)
mkdir "$T/scripts"
cat > "$T/scripts/offline-keys.py" <<'PY'
import importlib.machinery, importlib.util, os, sys
loader = importlib.machinery.SourceFileLoader("offline_keys", os.path.join(os.environ["SCRIPTS"], "offline-keys.py"))
ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("offline_keys", loader))
loader.exec_module(ok)
shown, digest = {}, ok.card_record_digest
def seen(record):
    value = digest(record); shown.update(sequence=record["sequence"], digest=value); return value
ok.card_record_digest = seen
ok.card_record.__defaults__ = (False, lambda prompt: "%d %s" % (shown["sequence"], shown["digest"][:8]), None)
sys.exit(ok.main(sys.argv[1:]))
PY

new_work(){ # a session after steps o, c, r and k: the offline keys, both cards' facts, card record 1 and the signing state
  local w; w="$(mktemp -d "$T/w.XXXXXX")"
  ( umask 077; age-keygen ${PQ[@]+"${PQ[@]}"} -o "$w/bg.key" 2>/dev/null; age-keygen -y "$w/bg.key" > "$w/breakglass.recipient"; mkdir "$w/offline" "$w/cards" "$w/developers" )
  python3 -Es "$SCRIPTS/offline-keys.py" generate --threshold 2 --shares 3 --out "$w/offline" --breakglass-recipient "$w/breakglass.recipient" >/dev/null
  head -2 "$w/offline/offline-shares.txt" > "$w/two-shares"
  # step o's own proof of the forms, so the session also holds a genuine root-signed record of ANOTHER event
  python3 -Es "$SCRIPTS/offline-keys.py" verify-forms --sealed "$w/offline/offline-keys.sealed.json" --shares-file "$w/offline/offline-shares.txt" \
      < "$w/offline/offline-shares.txt" >/dev/null
  python3 -Es - "$SCRIPTS/offline-keys.py" "$HERE/vectors/card-ceremony-record/make.py" "$w" <<'PY'
import importlib.machinery, importlib.util, json, os, sys
def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path); m = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader)); loader.exec_module(m); return m
ok, vectors, w = load("ok", sys.argv[1]), load("vectors", sys.argv[2]), sys.argv[3]
record = vectors.valid_record()
json.dump({k: record[k] for k in ok.CARD_FIELDS}, open(os.path.join(w, "cards", "cards.json"), "w"))
release = record["release_key"]
json.dump({"master_id": "m" * 16, "slip39_identifier": 4242, "publics": {"release": {"key": release["key"]}}},
          open(os.path.join(w, "developers", "developers.sealed.json"), "w"))
for serial in release["cards"]:
    json.dump({"schema": ok.SCHEMA_RELEASE_IMPORT, "serial": serial, "key": release["key"], "fingerprint": release["fingerprint"],
               "touch": "fixed", "imported": True, "attested": False, "master_id": "m" * 16, "slip39_identifier": 4242},
              open(os.path.join(w, "cards", "release-import-%s.json" % serial), "w"))
PY
  local out
  out="$(WORKDIR="$w" CEREMONY_STATE_DIR="$w/state" CARD_RECORD_FIRST=FIRST bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="$T/scripts"; WORK="$WORKDIR"; OA_SHARES_FROM="$WORK/two-shares"
    step_card_record; echo "RC=$?"' 2>&1)"
  grep -q "RC=0" <<< "$out" && [ -s "$w/cards/card-record-1.record.json" ] || { echo "fixture: step k failed: $(tail -5 <<< "$out")" >&2; return 1; }
  printf '%s' "$w"
}
anchor_fp(){ python3 -Es -c 'import hashlib,json,sys; print(hashlib.sha256(bytes.fromhex(json.load(open(sys.argv[1]))["record"]["anchor_policy_entry"]["key"])).hexdigest())' "$1/offline/offline-keys.record.json"; }
sealed_root(){ python3 -Es - "$SCRIPTS/offline-keys.py" "$1/offline/offline-keys.sealed.json" <<'PY'
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("ok", sys.argv[1]); ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("ok", loader)); loader.exec_module(ok)
print(ok.sealed_root(sys.argv[2]))
PY
}

run_g(){ # run_g WORK: step g in a fresh shell; GENESIS_* and CEREMONY_GENESIS_TYPED_ANCHOR_CHECK from the caller's environment
  WORKDIR="$1" CEREMONY_STATE_DIR="$1/state" GEN_PROPOSE_LOG="$1/propose.log" \
  GENESIS_TOOL_ROOT="${GENESIS_TOOL_ROOT-$T/kms}" GENESIS_TOOL_DIGEST="${GENESIS_TOOL_DIGEST-$KMS_DIGEST}" \
  GENESIS_MEASUREMENTS="$T/measurements.json" GENESIS_SYSTEM_PUB="$T/system.pem" GENESIS_NODES="$T/nodes" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"
    step_genesis; echo "RC=$?"' 2>&1
}
calls(){ [ -f "$1/propose.log" ] && grep -c . "$1/propose.log" || echo 0; }
arg(){ # arg WORK FLAG [N]: the value after the N-th FLAG (default 1) in the logged propose call
  python3 -Es -c 'import json,sys; a=json.loads(open(sys.argv[1]).readline()); i=[j for j,x in enumerate(a) if x==sys.argv[2]][int(sys.argv[3])-1]; print(a[i+1])' \
    "$1/propose.log" "$2" "${3:-1}" 2>/dev/null
}

hdr "PASS: the record verified, K_A's fingerprint typed from the sheet, propose --genesis handed this session's record"
W="$(new_work)" || exit 1
FP="$(anchor_fp "$W")"; ROOT="$(sealed_root "$W")"
out="$(GENESIS_TYPED_ANCHOR="$FP" run_g "$W")"
grep -q "RC=0" <<< "$out" && [ "$(calls "$W")" = 1 ] && [ -s "$W/genesis/genesis.unsigned.json" ] \
  && P "step g runs propose once and the unsigned genesis is written" || F "pass case: $(tail -15 <<< "$out")"
[ "$(python3 -Es -c 'import json,sys; print(" ".join(json.loads(open(sys.argv[1]).readline())[:2]))' "$W/propose.log")" = "propose --genesis" ] \
  && P "the call is manifest propose --genesis" || F "the call: $(head -c 200 "$W/propose.log")"
[ "$(arg "$W" --offline-keys-record)" = "$W/offline/offline-keys.record.json" ] \
  && P "--offline-keys-record is this session's offline/offline-keys.record.json" || F "--offline-keys-record: $(arg "$W" --offline-keys-record)"
[ "$(arg "$W" --root-key)" = "$ROOT" ] && P "--root-key is the sealed set's root, as kms takes an Ed25519 root (bare 64 hex)" || F "--root-key: $(arg "$W" --root-key)"
[ "$(arg "$W" --card-record)" = "$W/cards/card-record-1.record.json" ] && [ "$(arg "$W" --state-dir)" = "$W/state" ] \
  && P "--card-record is step k's newest record; --state-dir the signing state" || F "card record/state: $(arg "$W" --card-record) $(arg "$W" --state-dir)"
[ "$(arg "$W" --node 1)" = "$T/nodes/kms-a/bundle.json" ] && [ "$(arg "$W" --node 2)" = "$T/nodes/kms-b/bundle.json" ] \
  && [ "$(arg "$W" --measurements)" = "$T/measurements.json" ] && [ "$(arg "$W" --system-pub)" = "$T/system.pem" ] \
  && [ "$(arg "$W" --out)" = "$W/genesis/genesis.unsigned.json" ] \
  && P "every node, the measurements, the system key and --out are passed" || F "inputs: $(head -c 400 "$W/propose.log")"
python3 -Es -c 'import json,sys; a=json.loads(open(sys.argv[1]).readline()); i=a.index("--node"); sys.exit(0 if a[i+1:i+4]==[sys.argv[2]+"/"+f for f in ("bundle.json","keep.json","activation.json")] else 1)' \
  "$W/propose.log" "$T/nodes/kms-a" && P "each --node is BUNDLE KEEP ACTIVATION, in that order" || F "--node triple: $(head -c 300 "$W/propose.log")"
! grep -q "$FP" <<< "$out" && ! grep -q "$(python3 -Es -c 'import json,sys; print(json.load(open(sys.argv[1]))["record"]["anchor_policy_entry"]["key"])' "$W/offline/offline-keys.record.json")" <<< "$out" \
  && P "K_A and its fingerprint are never shown by the step (they are typed from the sheet)" || F "K_A was shown"
grep -q "genesis proposed, UNSIGNED" <<< "$out" && grep -q "manifest sign --genesis" <<< "$out" \
  && P "the next act, sign --genesis through offline-keys.py sign, is shown, not run" || F "next step: $(tail -4 <<< "$out")"
out="$(GENESIS_TYPED_ANCHOR="$FP" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "nothing is overwritten" <<< "$out" && [ "$(calls "$W")" = 1 ] \
  && P "run again: an existing genesis is never overwritten" || F "rerun: $(tail -4 <<< "$out")"

hdr "MISSING: no offline-keys record, nothing proposed"
W="$(new_work)" || exit 1
rm -f -- "$W/offline/offline-keys.record.json"
out="$(GENESIS_TYPED_ANCHOR="$FP" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "no offline-keys generation record" <<< "$out" && [ "$(calls "$W")" = 0 ] && [ ! -e "$W/genesis" ] \
  && P "a missing record is refused before regalia-kms runs" || F "missing: $(tail -5 <<< "$out")"
W="$(new_work)" || exit 1
mv "$W/offline/offline-keys.record.json" "$W/real.json"; ln -s "$W/real.json" "$W/offline/offline-keys.record.json"
out="$(GENESIS_TYPED_ANCHOR="$(anchor_fp "$W")" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "is not a plain file" <<< "$out" && [ "$(calls "$W")" = 0 ] && P "a link in its place is refused" || F "link: $(tail -4 <<< "$out")"

hdr "FORGED: each refused by the record check, before regalia-kms runs"
forge(){ # forge WORK KIND: replace the session's record with a forgery of KIND
  python3 -Es - "$1" "$2" <<'PY'
import base64, glob, hashlib, json, os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
w, kind = sys.argv[1], sys.argv[2]
path = os.path.join(w, "offline", "offline-keys.record.json")
doc = json.load(open(path)); record = doc["record"]
canon = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
k_a = ec.generate_private_key(ec.SECP256R1()).public_key()
point = k_a.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
spki = base64.b64encode(k_a.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
record.update(anchor_policy_entry={"alg": "ecdsa-p256", "key": point}, publics=dict(record["publics"], **{"anchor-policy": {"alg": "ecdsa-p256", "spki": spki}}))
other = Ed25519PrivateKey.generate()
if kind == "swapped":            # another K_A, the root's signature kept
    pass
elif kind == "self-signed":      # another K_A, signed by another key that names itself the root
    raw = other.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    record.update(root_entry={"alg": "ed25519", "key": raw}, root_fingerprint=hashlib.sha256(bytes.fromhex(raw)).hexdigest())
    doc["signature"] = other.sign(b"regalia.offline-keys-record/v1\x00" + canon(record)).hex()
elif kind == "root-named":       # another K_A, naming the real root, signed by another key
    doc["signature"] = other.sign(b"regalia.offline-keys-record/v1\x00" + canon(record)).hex()
elif kind == "other-event":      # a genuine root-signed record of this session, but forms-verified, not the generation
    doc = json.load(open(sorted(glob.glob(os.path.join(w, "offline", "forms-verified-*.record.json")))[0]))
json.dump(doc, open(path, "w"))
PY
}
for kind in swapped self-signed root-named other-event; do
  W="$(new_work)" || exit 1
  FP="$(anchor_fp "$W")"          # the sheet's: the REAL K_A, written at step o
  forge "$W" "$kind"
  out="$(GENESIS_TYPED_ANCHOR="$FP" run_g "$W")"
  grep -q "RC=1" <<< "$out" && grep -q "the offline-keys record was REFUSED" <<< "$out" && [ "$(calls "$W")" = 0 ] && [ ! -e "$W/genesis/genesis.unsigned.json" ] \
    && P "forged ($kind): refused, regalia-kms never ran" || F "forged ($kind): $(tail -5 <<< "$out")"
  out="$(CEREMONY_GENESIS_TYPED_ANCHOR_CHECK=0 run_g "$W")"
  grep -q "RC=1" <<< "$out" && [ "$(calls "$W")" = 0 ] && P "forged ($kind): refused with the typed channel off too (the record check alone)" \
    || F "forged ($kind), switch 0: $(tail -5 <<< "$out")"
done

hdr "the typed second channel (CEREMONY_GENESIS_TYPED_ANCHOR_CHECK, default 1; the owner's decision is pending)"
W="$(new_work)" || exit 1
FP="$(anchor_fp "$W")"
for typed in "" "${FP:0:63}" "$(printf '%s' "$FP" | tr '0-9a-f' '1-9a-f0')" "$(python3 -Es -c 'import json,sys; print(json.load(open(sys.argv[1]))["record"]["root_fingerprint"])' "$W/offline/offline-keys.record.json")"; do
  out="$(GENESIS_TYPED_ANCHOR="$typed" run_g "$W")"
  grep -q "RC=1" <<< "$out" && grep -q "ANCHOR-POLICY-FINGERPRINT typed" <<< "$out" && [ "$(calls "$W")" = 0 ] \
    && P "typed '${typed:0:8}…' (not K_A's): refused, nothing proposed" || F "typed ${typed:0:8}: $(tail -4 <<< "$out")"
done
out="$(CEREMONY_GENESIS_TYPED_ANCHOR_CHECK=1 GENESIS_TYPED_ANCHOR="$(printf '%s' "$FP" | tr a-f A-F)" run_g "$W")"
grep -q "RC=0" <<< "$out" && [ "$(calls "$W")" = 1 ] && P "explicitly on, typed in capitals: accepted" || F "typed capitals: $(tail -4 <<< "$out")"
W="$(new_work)" || exit 1
out="$(CEREMONY_GENESIS_TYPED_ANCHOR_CHECK=0 run_g "$W")"
grep -q "RC=0" <<< "$out" && [ "$(calls "$W")" = 1 ] && grep -q "typed second channel for K_A is OFF" <<< "$out" && ! grep -q "type the ANCHOR-POLICY-FINGERPRINT" <<< "$out" \
  && P "switch 0: not asked, said loudly, still proposed from the verified record" || F "switch 0: $(tail -6 <<< "$out")"
W="$(new_work)" || exit 1
for v in yes 2 on; do
  out="$(CEREMONY_GENESIS_TYPED_ANCHOR_CHECK="$v" GENESIS_TYPED_ANCHOR="$(anchor_fp "$W")" run_g "$W")"
  grep -q "RC=1" <<< "$out" && grep -q "CEREMONY_GENESIS_TYPED_ANCHOR_CHECK is 1" <<< "$out" && [ "$(calls "$W")" = 0 ] \
    && P "switch '$v': refused, nothing proposed" || F "switch $v: $(tail -4 <<< "$out")"
done
out="$(CEREMONY_GENESIS_TYPED_ANCHOR_CHECK="" GENESIS_TYPED_ANCHOR="nope" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "ANCHOR-POLICY-FINGERPRINT typed" <<< "$out" && [ "$(calls "$W")" = 0 ] \
  && P "switch empty: the default (on), so the typed value is checked" || F "switch empty: $(tail -4 <<< "$out")"

hdr "the regalia-kms tree is run only by the digest the kit pins"
W="$(new_work)" || exit 1
out="$(GENESIS_TOOL_DIGEST="$(printf '%064d' 0)" GENESIS_TYPED_ANCHOR="$(anchor_fp "$W")" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "not the reviewed tree" <<< "$out" && [ "$(calls "$W")" = 0 ] && P "another digest: refused, never run" || F "digest: $(tail -4 <<< "$out")"
out="$(GENESIS_TOOL_ROOT="$T/nodes" GENESIS_TYPED_ANCHOR="$(anchor_fp "$W")" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "is not a regalia-kms tree" <<< "$out" && [ "$(calls "$W")" = 0 ] && P "not a kms tree: refused" || F "tree: $(tail -4 <<< "$out")"
out="$(GEN_PROPOSE_FAIL=1 GENESIS_TYPED_ANCHOR="$(anchor_fp "$W")" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "regalia-kms did NOT propose the genesis manifest" <<< "$out" && [ ! -s "$W/genesis/genesis.unsigned.json" ] \
  && P "kms refusing: the step says so and nothing is there to sign" || F "kms refused: $(tail -4 <<< "$out")"

hdr "the session's prerequisites"
W="$(new_work)" || exit 1
rm -f -- "$W"/cards/card-record-*.record.json
out="$(GENESIS_TYPED_ANCHOR="$(anchor_fp "$W")" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "sign it first (step k)" <<< "$out" && [ "$(calls "$W")" = 0 ] && P "no card record: refused (step k first)" || F "no card record: $(tail -4 <<< "$out")"
W="$(new_work)" || exit 1
rm -f -- "$W/state/regalia-signing-state.json"
out="$(GENESIS_TYPED_ANCHOR="$(anchor_fp "$W")" run_g "$W")"
grep -q "RC=1" <<< "$out" && grep -q "no signing state in this session" <<< "$out" && [ "$(calls "$W")" = 0 ] && P "no signing state: refused" || F "no state: $(tail -4 <<< "$out")"
grep -q '^      g|G) step_genesis;;$' "$SCRIPTS/ceremony.sh" && grep -q '^   g) Genesis' "$SCRIPTS/ceremony.sh" && P "the menu offers step g" || F "menu: step g"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
