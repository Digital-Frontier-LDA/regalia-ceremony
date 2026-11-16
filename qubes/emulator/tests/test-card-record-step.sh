#!/usr/bin/env bash
# test-card-record-step.sh — ceremony.sh step k (regalia-ceremony#111, regalia-ceremony-oo0; regalia-kms#403, #408): the
# root signs the owner cards' and release cards' facts as the card record, through offline-keys.py card-record. The
# first record creates the laptop's signing state (--first-card-record, typed FIRST); the next one supersedes it; every
# refusal leaves nothing signed. The writer's own rules are test_card_record_writer.py's; this drives them through the
# step. The writer reads its confirmation from /dev/tty: a stand-in for offline-keys.py loads the real one and answers
# that one prompt as the screen asked (or as CR_CONFIRM says), and nothing else.
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
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ALLOW_SWAP=1 CEREMONY_THRESHOLD=2 CEREMONY_SHARES=3
T="$(mktemp -d)"; export T SCRIPTS
trap 'rm -rf -- "$T"' EXIT
if grep -q '^AGE-SECRET-KEY-PQ-1' <<< "$(age-keygen -pq 2>/dev/null)"; then PQ=(-pq); else PQ=(); export CEREMONY_ALLOW_CLASSICAL_BREAKGLASS=1; fi

# The step's HERE: offline-keys.py only, a stand-in that runs the real one with the writer's terminal prompt answered.
mkdir "$T/scripts"
cat > "$T/scripts/offline-keys.py" <<'PY'
import importlib.machinery, importlib.util, os, sys
path = os.path.join(os.environ["SCRIPTS"], "offline-keys.py")
loader = importlib.machinery.SourceFileLoader("offline_keys", path)
ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("offline_keys", loader))
loader.exec_module(ok)
shown = {}
digest = ok.card_record_digest
def seen(record):                       # what the screen shows: the record's sequence and digest
    value = digest(record)
    shown.update(sequence=record["sequence"], digest=value)
    return value
ok.card_record_digest = seen
def terminal(prompt):                   # the operator at /dev/tty: types what the screen asked, unless CR_CONFIRM says otherwise
    sys.stderr.write(prompt + "\n")
    return os.environ.get("CR_CONFIRM") or "%d %s" % (shown["sequence"], shown["digest"][:8])
defaults = list(ok.card_record.__defaults__)
defaults[ok.card_record.__code__.co_varnames[:ok.card_record.__code__.co_argcount][-len(defaults):].index("ask")] = terminal
ok.card_record.__defaults__ = tuple(defaults)
sys.exit(ok.main(sys.argv[1:]))
PY

new_work(){ # a session after steps o, c and r: the offline keys (forms proven), the owner cards' facts, both release cards' facts
  local w; w="$(mktemp -d "$T/w.XXXXXX")"
  ( umask 077; age-keygen ${PQ[@]+"${PQ[@]}"} -o "$w/bg.key" 2>/dev/null; age-keygen -y "$w/bg.key" > "$w/breakglass.recipient"; mkdir "$w/offline" "$w/cards" "$w/developers" )
  python3 -Es "$SCRIPTS/offline-keys.py" generate --threshold 2 --shares 3 --out "$w/offline" --breakglass-recipient "$w/breakglass.recipient" >/dev/null
  head -2 "$w/offline/offline-shares.txt" > "$w/two-shares"; head -1 "$w/offline/offline-shares.txt" > "$w/one-share"
  rm -f -- "$w/offline/offline-shares.txt"         # step o's forms taken as proven (its own gate is test-offline-keys-step's)
  python3 -Es - "$SCRIPTS/offline-keys.py" "$HERE/vectors/card-ceremony-record/make.py" "$w" <<'PY'
import importlib.machinery, importlib.util, json, os, sys
def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path); m = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader)); loader.exec_module(m); return m
ok, vectors, w = load("ok", sys.argv[1]), load("vectors", sys.argv[2]), sys.argv[3]
record = vectors.valid_record()
json.dump({k: record[k] for k in ok.CARD_FIELDS}, open(os.path.join(w, "cards", "cards.json"), "w"))
release = record["release_key"]
# step r's set: the developers' sealed header names it (rk_facts reads master_id, slip39_identifier and the release key)
json.dump({"master_id": "m" * 16, "slip39_identifier": 4242, "publics": {"release": {"key": release["key"]}}},
          open(os.path.join(w, "developers", "developers.sealed.json"), "w"))
for serial in release["cards"]:
    json.dump({"schema": ok.SCHEMA_RELEASE_IMPORT, "serial": serial, "key": release["key"], "fingerprint": release["fingerprint"],
               "touch": "fixed", "imported": True, "attested": False, "master_id": "m" * 16, "slip39_identifier": 4242},
              open(os.path.join(w, "cards", "release-import-%s.json" % serial), "w"))
PY
  printf '%s' "$w"
}

run_k(){ # run_k WORK [SHARES_FILE]: step k in a fresh shell, CARD_RECORD_FIRST and CR_CONFIRM from the caller's environment
  WORKDIR="$1" SHARES="${2:-$1/two-shares}" CEREMONY_STATE_DIR="$1/state" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="$T/scripts"; WORK="$WORKDIR"; OA_SHARES_FROM="$SHARES"
    step_card_record; echo "RC=$?"' 2>&1
}
current(){ # current RECORD STATE: the sequence the consumer's own check takes as current, or its refusal
  python3 -Es - "$SCRIPTS/offline-keys.py" "$1" "$2" <<'PY'
import importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader("ok", sys.argv[1]); ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("ok", loader)); loader.exec_module(ok)
doc = json.load(open(sys.argv[2])); root = doc["record"]["root_entry"]["key"]
try:
    print("CURRENT %d" % ok.card_record_current(doc, root, ok.read_signing_state(sys.argv[3], root))["sequence"])
except ok.Refused as refused:
    print("REFUSED %s" % refused)
PY
}
lines(){ [ -f "$1/state/signing-record.jsonl" ] && grep -c '"kind": *"card-record"' "$1/state/signing-record.jsonl" || echo 0; }

hdr "the first card record: FIRST typed, the marker made, record 1 signed and logged"
W="$(new_work)"
out="$(CARD_RECORD_FIRST=FIRST run_k "$W")"
grep -q "RC=0" <<< "$out" && [ -s "$W/cards/card-record-1.record.json" ] && [ -s "$W/state/regalia-signing-state.json" ] \
  && P "step k signs card record 1 and creates the signing state" || F "first record: $(tail -15 <<< "$out")"
[ "$(lines "$W")" = 1 ] && P "the signing record holds one card-record line" || F "card-record lines: $(lines "$W")"
[ "$(stat -c %a "$W/state" 2>/dev/null || stat -f %Lp "$W/state")" = 700 ] && P "the state directory is 0700" || F "state mode"
grep -q "CURRENT 1" <<< "$(current "$W/cards/card-record-1.record.json" "$W/state")" \
  && P "the consumer's check takes record 1 as current" || F "current: $(current "$W/cards/card-record-1.record.json" "$W/state")"
grep -q "CARD RECORD 1 SIGNED" <<< "$out" && grep -q "WRITE the card record's SEQUENCE and DIGEST" <<< "$out" \
  && grep -q "card-record-1.record.json  sha256 " <<< "$out" \
  && P "the operator is told what goes on the sheet and what is committed" || F "sheet/commit lines: $(grep -i -e write -e commit <<< "$out")"

hdr "the next card record: no question asked, record 2 supersedes record 1"
out="$(CARD_RECORD_FIRST=bogus run_k "$W")"
grep -q "RC=0" <<< "$out" && [ -s "$W/cards/card-record-2.record.json" ] && ! grep -q "type FIRST" <<< "$out" \
  && P "a session with a signing state signs the next record, without the FIRST question" || F "second record: $(tail -10 <<< "$out")"
[ "$(lines "$W")" = 2 ] && P "the signing record holds two card-record lines" || F "card-record lines: $(lines "$W")"
python3 -Es -c 'import json,sys; a=json.load(open(sys.argv[1]))["record"]; b=json.load(open(sys.argv[2]))["record"]; sys.exit(0 if b["sequence"]==2 and b["supersedes"] else 1)' \
  "$W/cards/card-record-1.record.json" "$W/cards/card-record-2.record.json" && P "record 2 supersedes record 1" || F "record 2's supersedes"
grep -q "not the newest the root signed" <<< "$(current "$W/cards/card-record-1.record.json" "$W/state")" \
  && grep -q "CURRENT 2" <<< "$(current "$W/cards/card-record-2.record.json" "$W/state")" \
  && P "record 1 is now superseded; record 2 is current" || F "supersede: $(current "$W/cards/card-record-1.record.json" "$W/state")"

hdr "a first run that stopped after the marker, before its line: finished as the first, without the question"
W="$(new_work)"
( umask 077; mkdir "$W/state" )
python3 -Es - "$SCRIPTS/offline-keys.py" "$W" <<'PY2'
import importlib.machinery, importlib.util, json, os, sys
loader = importlib.machinery.SourceFileLoader("ok", sys.argv[1]); ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("ok", loader)); loader.exec_module(ok)
w = sys.argv[2]; path = os.path.join(w, "state", ok.SIGNING_STATE)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, ok.canonical({"schema": ok.SCHEMA_SIGNING_STATE, "root": ok.sealed_root(os.path.join(w, "offline", "offline-keys.sealed.json"))}) + b"\n")
os.close(fd)
PY2
out="$(CARD_RECORD_FIRST=bogus run_k "$W")"
grep -q "RC=0" <<< "$out" && [ -s "$W/cards/card-record-1.record.json" ] && [ "$(lines "$W")" = 1 ] && ! grep -q "type FIRST" <<< "$out" \
  && P "the marker alone: record 1 signed as the first (--first-card-record), no FIRST question" || F "marker only: $(tail -8 <<< "$out")"

hdr "refusals: nothing signed, nothing created"
W="$(new_work)"
out="$(CARD_RECORD_FIRST=yes run_k "$W")"
grep -q "RC=1" <<< "$out" && grep -q "neither FIRST nor RESTORE was typed" <<< "$out" && [ ! -e "$W/state" ] && ! ls "$W"/cards/card-record-* >/dev/null 2>&1 \
  && P "a session with no signing state must say FIRST or RESTORE: anything else is refused, no state started" || F "no answer: $(tail -5 <<< "$out")"
out="$(CR_CONFIRM="1 00000000" CARD_RECORD_FIRST=FIRST run_k "$W")"
grep -q "RC=1" <<< "$out" && grep -q "the card record was NOT signed" <<< "$out" && grep -q 'the confirmation typed is not "1 ' <<< "$out" \
  && ! ls "$W"/cards/card-record-* >/dev/null 2>&1 && [ ! -e "$W/state/regalia-signing-state.json" ] && [ ! -e "$W/state/signing-record.jsonl" ] \
  && P "a wrong confirmation signs nothing and leaves no marker" || F "wrong confirmation: $(tail -6 <<< "$out")"
out="$(CARD_RECORD_FIRST=FIRST run_k "$W" "$W/one-share")"
grep -q "RC=1" <<< "$out" && ! ls "$W"/cards/card-record-* >/dev/null 2>&1 && [ ! -e "$W/state/signing-record.jsonl" ] \
  && P "fewer than k shares: nothing signed" || F "one share: $(tail -6 <<< "$out")"
out="$(CARD_RECORD_FIRST=FIRST run_k "$W")"
grep -q "RC=0" <<< "$out" && [ -s "$W/cards/card-record-1.record.json" ] && [ "$(lines "$W")" = 1 ] \
  && P "after those refusals, the first record is still record 1" || F "rerun after refusals: $(tail -8 <<< "$out")"

W="$(new_work)"; rm -f -- "$W/cards/cards.json"
out="$(CARD_RECORD_FIRST=FIRST run_k "$W")"
grep -q "RC=1" <<< "$out" && grep -q "run step c first" <<< "$out" && [ ! -e "$W/state" ] && P "no owner cards' facts: refused (step c first)" || F "no cards.json: $(tail -4 <<< "$out")"
W="$(new_work)"; rm -f -- "$(ls "$W"/cards/release-import-*.json | head -1)"
out="$(CARD_RECORD_FIRST=FIRST run_k "$W")"
grep -q "RC=1" <<< "$out" && grep -q "1 release cards hold this developers' set" <<< "$out" && [ ! -e "$W/state" ] \
  && P "one release card's facts: refused (step r first)" || F "one release fact: $(tail -4 <<< "$out")"
W="$(new_work)"; python3 -Es -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["key"]="00"*32; json.dump(d,open(p,"w"))' "$(ls "$W"/cards/release-import-*.json | head -1)"
out="$(CARD_RECORD_FIRST=FIRST run_k "$W")"
grep -q "RC=1" <<< "$out" && ! ls "$W"/cards/card-record-* >/dev/null 2>&1 && P "a release fact of another key: refused" || F "stale release fact: $(tail -4 <<< "$out")"
W="$(new_work)"; rm -rf -- "$W/offline"
out="$(CARD_RECORD_FIRST=FIRST run_k "$W")"
grep -q "RC=1" <<< "$out" && grep -q "run step o first" <<< "$out" && P "no offline keys: refused (step o first)" || F "no sealed set: $(tail -4 <<< "$out")"

hdr "the step is wired, and the owner cards' tool no longer says it is missing"
grep -q '^      k|K) step_card_record;;$' "$SCRIPTS/ceremony.sh" && grep -q '^   k) Card record' "$SCRIPTS/ceremony.sh" \
  && P "the menu offers step k" || F "menu: step k"
! grep -q "card-record has no ceremony step yet" "$SCRIPTS/owner-cards.py" && P "owner-cards.py:44's 'no ceremony step yet' is gone" || F "owner-cards.py still says no step"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
