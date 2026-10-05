#!/usr/bin/env bash
# test-ownerauth-rotation-step.sh — ceremony.sh step t (regalia-ceremony#135): owner-authorization rotation in a LATER
# session. The sealed set comes from the first ceremony's archive (here a "disc" directory), never this session's step
# o; fresh values are made as step a makes them, both owner cards prove them, the drill opens the new recovery copies,
# and the archive stages the set beside the old one and refuses a real burn until all of that is done. The stand-ins
# (software GnuPG homes as owner cards, a gpg wrapper) are test-ownerauth-step.sh's.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins first, as under run-tests.sh (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
python3 -Es -c 'import shamir_mnemonic, cryptography' 2>/dev/null || { echo "  SKIP: python3 lacks shamir-mnemonic or cryptography"; exit 0; }
command -v age >/dev/null && command -v age-keygen >/dev/null || { echo "  SKIP: age is not installed"; exit 0; }
REAL_GPG="$(command -v gpg)" || { echo "  SKIP: gpg is not installed"; exit 0; }
command -v sops >/dev/null || { echo "  SKIP: sops is not installed (the emulator job installs the pinned one)"; exit 0; }
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ALLOW_SWAP=1 CEREMONY_THRESHOLD=2 CEREMONY_SHARES=3
T="$(mktemp -d)"; export T
cleanup(){ local h; for h in "$T"/card1 "$T"/card2 "$T"/stranger "$T"/w*/ownerauth-gnupg; do [ -d "$h" ] && gpgconf --homedir "$h" --kill all 2>/dev/null; done; rm -rf -- "$T"; }
trap cleanup EXIT
if grep -q '^AGE-SECRET-KEY-PQ-1' <<< "$(age-keygen -pq 2>/dev/null)"; then PQ=(-pq); else PQ=(); export CEREMONY_ALLOW_CLASSICAL_BREAKGLASS=1; fi

# the inserted card: --card-status answers with CARD_SERIAL; a decryption runs in CARD_HOME, the card's own keys
mkdir "$T/shim"
cat > "$T/shim/gpg" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [ "\$a" = --card-status ] && { printf 'Reader ...........: Yubico YubiKey\nSerial number ....: %s\n' "\${CARD_SERIAL:-}"; exit 0; }; done
if [ -n "\${CARD_HOME:-}" ] && [[ " \$* " == *" --decrypt "* ]]; then
  args=(); skip=0
  for a in "\$@"; do if [ \$skip = 1 ]; then args+=("\$CARD_HOME"); skip=0; elif [ "\$a" = --homedir ]; then args+=(--homedir); skip=1; else args+=("\$a"); fi; done
  exec "$REAL_GPG" "\${args[@]}"
fi
exec "$REAL_GPG" "\$@"
EOF
chmod +x "$T/shim/gpg"

card(){ # card NAME: a software "owner card", an Ed25519 primary and a cv25519 encryption subkey
  local home="$T/$1" fpr
  ( umask 077; mkdir "$home" )
  "$REAL_GPG" --homedir "$home" --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "$1 <$1@example.invalid>" ed25519 sign never 2>/dev/null
  local listing; listing="$("$REAL_GPG" --homedir "$home" --with-colons --list-keys)"
  fpr="$(awk -F: '/^fpr/{print $10; exit}' <<< "$listing")"
  "$REAL_GPG" --homedir "$home" --batch --pinentry-mode loopback --passphrase "" --quick-add-key "$fpr" cv25519 encr never 2>/dev/null
}
card card1; card card2; card stranger

new_work(){ # a session after step o: the break-glass key, the offline keys and their shares, the cards' exported keys
  local w; w="$(mktemp -d "$T/w.XXXXXX")"
  ( umask 077; age-keygen ${PQ[@]+"${PQ[@]}"} -o "$w/bg.key" 2>/dev/null; age-keygen -y "$w/bg.key" > "$w/breakglass.recipient"; mkdir "$w/offline" "$w/cards" )
  python3 -Es "$SCRIPTS/offline-keys.py" generate --threshold 2 --shares 3 --out "$w/offline" --breakglass-recipient "$w/breakglass.recipient" >/dev/null
  head -2 "$w/offline/offline-shares.txt" > "$w/two-shares"
  rm -f -- "$w/offline/offline-shares.txt"         # step o's forms taken as proven (its own gate is test-offline-keys-step's)
  { "$REAL_GPG" --homedir "$T/card1" --export; "$REAL_GPG" --homedir "$T/card2" --export; } > "$w/cards/owner-cards.gpg"
  ( umask 077; mkdir "$w/state" )                   # the laptop's signing state directory (CEREMONY_STATE_DIR)
  sign_card_record "$w" card1 card2 1
  printf '%s' "$w"
}

sign_card_record(){ # sign_card_record WORK CARD_A CARD_B N: card record N naming the two homes' keys, signed by WORK's root, logged
  python3 -Es - "$SCRIPTS/offline-keys.py" "$HERE/vectors/card-ceremony-record/make.py" "$1" "$4" \
      "$("$REAL_GPG" --homedir "$T/$2" --with-colons --list-keys | awk -F: '/^fpr/{print $10}' | head -2 | tr '\n' ' ')" \
      "$("$REAL_GPG" --homedir "$T/$3" --with-colons --list-keys | awk -F: '/^fpr/{print $10}' | head -2 | tr '\n' ' ')" <<'PY2'
import importlib.machinery, importlib.util, json, os, sys
def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path); m = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader)); loader.exec_module(m); return m
ok, vectors = load("ok", sys.argv[1]), load("vectors", sys.argv[2])
w, n, cards = sys.argv[3], int(sys.argv[4]), [a.split() for a in sys.argv[5:7]]
sealed = json.load(open(w + "/offline/offline-keys.sealed.json"))
shares = [" ".join(line.split()) for line in open(w + "/two-shares").read().splitlines()[:2]]
root = ok._private_key(ok.unseal(ok.combine(shares, sealed)[0], sealed)["keys"]["root"])
entry = {"alg": "ed25519", "key": ok.root_entry_of(sealed)}
state = w + "/state"
if n == 1:
    with open(os.path.join(state, ok.SIGNING_STATE), "w") as f:
        json.dump({"schema": ok.SCHEMA_SIGNING_STATE, "root": entry["key"]}, f)
    os.chmod(os.path.join(state, ok.SIGNING_STATE), 0o600)
lines = ok.card_lines_of(ok.read_signing_state(state, entry["key"]), entry["key"]) if n > 1 else []
record = vectors.valid_record()
for i, (primary, subkey) in enumerate(cards):
    record["ownerauth_recipients"][i].update(primary=primary, subkey=subkey)
record.update(root_entry=entry, root_fingerprint=ok.root_fingerprint(entry), sequence=n, supersedes=lines[-1]["digest"] if lines else "")
ok.card_record_check(record)
ok.append_card_record_line(state, record)
json.dump({"record": record, "signature": root.sign(ok.RECORD_DOMAIN + ok.canonical(record)).hex()}, open(w + "/cards/card-record-%d.record.json" % n, "w"))
PY2
}


later_session(){ # a session after the first ceremony: its sealed set and its owner authorizations on a "disc"
  local w; w="$(new_work)"
  mkdir -p "$w.disc/offline" "$w.disc/ownerauth"
  python3 -Es "$SCRIPTS/offline-keys.py" ownerauth --sealed "$w/offline/offline-keys.sealed.json" --nodes a,b,c --yk-keys "$w/cards/owner-cards.gpg" \
      --card-record "$w/cards/card-record-1.record.json" --state-dir "$w/state" --out "$w.disc/ownerauth" < "$w/two-shares" >/dev/null 2>&1 \
    || { echo "later_session: the first set's owner authorizations were not made" >&2; return 1; }
  mv "$w/offline/offline-keys.sealed.json" "$w.disc/offline/" && rm -rf -- "$w/offline"
  sleep 1                                       # the rotation's record is later than the current one, to the second
  printf '%s' "$w"
}
rotate(){ # rotate WORK [EXTRA]: step t, the operator inserting card1 then card2; EXTRA is shell run first (a stand-in)
  WORKDIR="$1" EXTRA="${2:-}" CEREMONY_STATE_DIR="$1/state" PATH="$T/shim:$PATH" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; OA_SHARES_FROM="$WORK/two-shares"; OA_ROTATE_SEALED="$WORK.disc/offline/offline-keys.sealed.json"
    OA_ROTATE_CURRENT="$WORK.disc/ownerauth/ownerauth.record.json"
    oa_insert_card(){ if [ "$1" = 1 ]; then OA_SERIAL=1001; export CARD_HOME="$T/card1"; else OA_SERIAL=1002; export CARD_HOME="$T/card2"; fi
                      export CARD_SERIAL="$OA_SERIAL"; }
    eval "$EXTRA"
    step_ownerauth_rotate; echo "RC=$?"' 2>&1
}
arch(){ # arch WORK SIMULATE
  WORKDIR="$1" SIM="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""; WORK="$WORKDIR"
    printf "0123456789abcdef\n" > "$WORK/escrow-mac.kcv"
    CEREMONY_SIMULATE="$SIM" step_archive; echo "RC=$?"' 2>&1
}
checks(){ python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["record"]; print(json.dumps({n: r["nodes"][n] for n in sorted(r["nodes"])}, sort_keys=True))' "$1"; }

hdr "a rotation from the archived sealed set: made, both owner cards proving it, the drill, the commit list"
W="$(later_session)"
out="$(rotate "$W")"
grep -q "RC=0" <<< "$out" && grep -q "owner authorizations done: both owner cards open every node's envelope" <<< "$out" \
  && grep -q "owner-auth drill passed for every node (a b c)" <<< "$out" && P "step t completes, with the drill" || F "step t: $(tail -15 <<< "$out")"
for f in ownerauth.record.json ownerauth-verified.record.json ownerauth-a.yk.gpg ownerauth-b.bg.sops ownerauth-c.yk.gpg drill-passed; do
  [ -e "$W/ownerauth-rotation/$f" ] && P "ownerauth-rotation/$f is in the workdir" || F "ownerauth-rotation/$f is missing"
done
[ ! -e "$W/offline" ] && [ ! -e "$W/ownerauth" ] && [ "$(stat -c %a "$W/rotation/offline-keys.sealed.json")" = 600 ] \
  && P "the sealed copy is in rotation/ (0600), and the session has no offline/ or ownerauth/ of its own" || F "layout: $(ls "$W")"
grep -q "hsm-backups/ownerauth/rotation-20[0-9-]*T[0-9]*Z/, beside the set it replaces, never over it" <<< "$out" \
  && grep -qF "cd /usr/lib/regalia-kms && (gpg --decrypt <current set>/ownerauth-<n>.yk.gpg; gpg --decrypt ownerauth-<n>.yk.gpg) | sudo python3 -Es -m deploy.baremetal.enrol ownerauth --rotate-from <current set>/ownerauth.record.json --record ownerauth.record.json --node-id <n> --root-key <root>" <<< "$out" \
  && grep -qF "enrol ownerauth --check --adopt --record <current set>/ownerauth.record.json" <<< "$out" \
  && P "it says where to commit, and each node's whole command (current value first, then new; the one-time adopt)" || F "instructions: $(grep -i 'commit\|enrol' <<< "$out")"
cur_at="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["record"]["at"])' "$W.disc/ownerauth/ownerauth.record.json")"
new_at="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["record"]["at"])' "$W/ownerauth-rotation/ownerauth.record.json")"
[[ "$new_at" > "$cur_at" ]] && P "the new record is later than the current one ($new_at > $cur_at)" || F "at: $new_at vs $cur_at"
out2="$(rotate "$W")"
grep -q "RC=0" <<< "$out2" && grep -q "already proven in this session" <<< "$out2" && ! grep -q "drill passed" <<< "$out2" \
  && P "run again: nothing is made or drilled twice" || F "rerun: $(tail -5 <<< "$out2")"

hdr "a second rotation from the same disc: fresh values, a later record"
W2="$(later_session)"
cp "$W.disc/offline/offline-keys.sealed.json" "$W2.disc/offline/offline-keys.sealed.json"
cp "$W/two-shares" "$W2/two-shares"; cp -r "$W/state/." "$W2/state/"; cp "$W/cards/"* "$W2/cards/"
cp "$W/ownerauth-rotation/ownerauth.record.json" "$W2.disc/ownerauth/ownerauth.record.json"   # the first rotation is now current
sleep 1
out="$(rotate "$W2")"
grep -q "RC=0" <<< "$out" && [ "$(checks "$W/ownerauth-rotation/ownerauth.record.json")" != "$(checks "$W2/ownerauth-rotation/ownerauth.record.json")" ] \
  && P "a second rotation, from the first one's record: every node's check value is new" || F "second rotation: $(tail -5 <<< "$out")"

hdr "the archive: the rotation staged beside the old set; a real burn waits for the proof and the drill"
arch "$W" 1 > "$T/arch.out"
burned="$(ls "$W/mdisc/ownerauth-rotation" 2>/dev/null | tr '\n' ' ')"
for f in ownerauth.record.json ownerauth-verified.record.json ownerauth-verify.jsonl ownerauth-a.yk.gpg ownerauth-a.bg.sops; do
  grep -q "$f" <<< "$burned" || F "$f is not staged (staged: $burned)"
done
grep -q "ownerauth-c.bg.sops" <<< "$burned" && ! grep -q "drill-passed" <<< "$burned" && [ ! -e "$W/mdisc/offline/offline-keys.sealed.json" ] \
  && P "the new set is staged in ownerauth-rotation/, not the session's marker, not the sealed copy" || F "staged: $burned"
! grep -q "owner authorizations are not proven" "$T/arch.out" && P "step a's gate does not take a rotation session for a first ceremony" || F "step a gate fired: $(grep -i 'not proven' "$T/arch.out")"
W3="$(later_session)"
out="$(rotate "$W3" 'ownerauth_drill(){ err "drill stand-in: FAILED"; return 1; }')"
grep -q "RC=1" <<< "$out" && grep -q "the new recovery copies did NOT pass the drill" <<< "$out" && [ ! -e "$W3/ownerauth-rotation/drill-passed" ] \
  && P "a failed drill: the step fails, nothing marks it passed" || F "failed drill: $(tail -5 <<< "$out")"
out="$(arch "$W3" 0)"
grep -q "RC=1" <<< "$out" && grep -q "the rotation is not proven by both owner cards and its drill" <<< "$out" \
  && P "proven but not drilled: a real burn is refused" || F "real archive: $(tail -4 <<< "$out")"
W4="$(later_session)"
out="$(rotate "$W4" 'oa_insert_card(){ OA_SERIAL=1001; export CARD_HOME="$T/stranger" CARD_SERIAL=1001; }')"
out="$(arch "$W4" 0)"
grep -q "RC=1" <<< "$out" && grep -q "the rotation is not proven" <<< "$out" && P "unproven by the cards: a real burn is refused" || F "unproven archive: $(tail -4 <<< "$out")"

hdr "the current record and this laptop's clock, before the root signs anything (95 on #137)"
W8="$(later_session)"
out="$(rotate "$W8" 'oa_utc_now(){ echo 2020-01-01T00:00:00Z; }')"
grep -q "RC=1" <<< "$out" && grep -q "this laptop's clock (2020-01-01T00:00:00Z) is not later than the current record's" <<< "$out" && [ ! -e "$W8/ownerauth-rotation" ] \
  && P "a clock behind the current record: refused, nothing made" || F "clock behind: $(tail -4 <<< "$out")"
at8="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["record"]["at"])' "$W8.disc/ownerauth/ownerauth.record.json")"
out="$(rotate "$W8" "oa_utc_now(){ echo $at8; }")"
grep -q "RC=1" <<< "$out" && grep -q "is not later than the current record's ($at8)" <<< "$out" && [ ! -e "$W8/ownerauth-rotation" ] \
  && P "a clock equal to the current record's at: refused (strictly later)" || F "clock equal: $(tail -4 <<< "$out")"
W9="$(later_session)"; W10="$(later_session)"
out="$(rotate "$W9" "OA_ROTATE_CURRENT=$W10.disc/ownerauth/ownerauth.record.json")"
grep -q "RC=1" <<< "$out" && grep -q "the record is signed by another root than this sealed set's" <<< "$out" \
  && grep -q "the current record is not this root's owner-authorization record" <<< "$out" && [ ! -e "$W9/ownerauth-rotation" ] && [ ! -e "$W9/rotation/current.record.json" ] \
  && P "another root's record as the current one: refused, and its copy removed" || F "other root: $(tail -4 <<< "$out")"
ln -s "$W9.disc/ownerauth/ownerauth.record.json" "$T/link.current.json"
out="$(rotate "$W9" 'OA_ROTATE_CURRENT="$T/link.current.json"')"
grep -q "RC=1" <<< "$out" && grep -q "is not the current record (a regular file, not a link)" <<< "$out" && [ ! -e "$W9/ownerauth-rotation" ] \
  && P "a link given as the current record: refused" || F "current link: $(tail -3 <<< "$out")"

hdr "the signing state restored from the newest disc and opened (24, d9, 1e)"
disc_state(){ # a later session whose signing state is on the disc only: $WORK/state is restored from it
  local w; w="$(later_session)" || return 1
  mv "$w/state" "$w.disc/state"
  printf '%s' "$w"
}
rotate_disc(){ # rotate_disc WORK SESSION [EXTRA]: step t with the state restored from WORK.disc/state, the sheet saying SESSION
  WORKDIR="$1" SESS="$2" EXTRA="${3:-}" PATH="$T/shim:$PATH" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; OA_SHARES_FROM="$WORK/two-shares"; OA_ROTATE_SEALED="$WORK.disc/offline/offline-keys.sealed.json"
    OA_ROTATE_CURRENT="$WORK.disc/ownerauth/ownerauth.record.json"; unset CEREMONY_STATE_DIR
    STATE_FROM="$WORK.disc/state"; STATE_SESSION="$SESS"; STATE_COMPARE=""; STATE_CHAIN=""
    oa_insert_card(){ if [ "$1" = 1 ]; then OA_SERIAL=1001; export CARD_HOME="$T/card1"; else OA_SERIAL=1002; export CARD_HOME="$T/card2"; fi
                      export CARD_SERIAL="$OA_SERIAL"; }
    eval "$EXTRA"
    step_ownerauth_rotate; echo "RC=$?"' 2>&1 < /dev/null
}
S1="$(disc_state)"
out="$(rotate_disc "$S1" 0)"
grep -q "RC=0" <<< "$out" && grep -q "SESSION 1 opened (the disc's state was session 0)" <<< "$out" && grep -q "NEWEST card-record sequence=1" <<< "$out" \
  && [ "$(stat -c %a "$S1/state")" = 700 ] && [ "$(stat -c %a "$S1/state/signing-record.jsonl")" = 600 ] \
  && P "the state restored into the session's RAM (0700, 0600), session 1 opened, its newest lines shown" || F "restore: $(grep -v '^gpg' <<< "$out" | tail -8)"
arch "$S1" 1 > "$T/arch-s.out"
[ -s "$S1/mdisc/state/signing-record.jsonl" ] && [ -s "$S1/mdisc/state/regalia-signing-state.json" ] && grep -q "SESSIONS 1" "$T/arch-s.out" \
  && ! grep -q "WRITE ON THE SHEET" "$T/arch-s.out" && grep -q "Do NOT write the session count on the sheet yet" "$T/arch-s.out" \
  && grep -q "hsm-backups/state/" "$T/arch-s.out" \
  && P "the archive stages state/, and the sheet waits for the readback (d9)" || F "archive state: $(grep -i 'state\|SESSION\|sheet' "$T/arch-s.out" | head -5)"
readback(){ # readback WORK DISC_STATE: step w
  WORKDIR="$1" DISC="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; unset CEREMONY_STATE_DIR; STATE_READBACK="$DISC"
    step_state_readback; echo "RC=$?"' 2>&1 < /dev/null
}
out="$(readback "$S1" "$S1/mdisc/state")"
grep -q "RC=0" <<< "$out" && grep -q "WRITE ON THE SHEET AND ON THE DISC LABEL: SESSIONS 1" <<< "$out" \
  && P "step w: the disc's state/ read back equal, then the sheet's count" || F "step w: $(tail -4 <<< "$out")"
cp -r "$S1/mdisc/state" "$T/s1-bad"; printf 'x' >> "$T/s1-bad/signing-record.jsonl"
out="$(readback "$S1" "$T/s1-bad")"
grep -q "RC=1" <<< "$out" && grep -q "do NOT write the sheet; burn the disc again" <<< "$out" && ! grep -q "WRITE ON THE SHEET" <<< "$out" \
  && P "step w: a disc whose state/ differs: no sheet line" || F "step w bad disc: $(tail -4 <<< "$out")"
S2="$(disc_state)"
out="$(rotate_disc "$S2" 1)"
grep -q "RC=1" <<< "$out" && grep -q "this disc's state is session 0, and the sheet says 1: an OLDER disc" <<< "$out" \
  && [ ! -e "$S2/state" ] && [ ! -e "$S2/ownerauth-rotation" ] && P "an older disc than the sheet: refused, nothing restored or made" || F "older disc: $(tail -5 <<< "$out")"
out="$(rotate_disc "$S2" 0 'STATE_FROM="$WORK.disc/offline"')"
grep -q "RC=1" <<< "$out" && grep -q "is not a disc's state directory" <<< "$out" && [ ! -e "$S2/state" ] \
  && P "a directory that is not a disc's state: refused" || F "not a state dir: $(tail -3 <<< "$out")"
out="$(rotate_disc "$S2" "zero")"
grep -q "RC=1" <<< "$out" && grep -q "the session count is a number from the sheet" <<< "$out" && [ ! -e "$S2/state" ] \
  && P "a session count that is not a number: refused" || F "typed count: $(tail -3 <<< "$out")"

leave(){ # leave WORK ANSWER: may the session quit?
  WORKDIR="$1" ANS="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; unset CEREMONY_STATE_DIR; STATE_LEAVE="$ANS"
    state_may_leave; echo "RC=$?"' 2>&1 < /dev/null
}
out="$(leave "$S1" "")"
grep -q "RC=0" <<< "$out" && P "quit after step w read the state back: allowed" || F "quit after burn: $(tail -3 <<< "$out")"
printf '{"kind": "anchor-first", "node_id": "a"}\n' >> "$S1/state/signing-record.jsonl"
out="$(leave "$S1" "")"
grep -q "RC=1" <<< "$out" && grep -q "changed since its last burn was read back" <<< "$out" && P "quit with a state changed since its burn: refused (d9)" || F "quit unburned: $(tail -3 <<< "$out")"
out="$(leave "$S1" "LEAVE WITHOUT BURNING")"
grep -q "RC=0" <<< "$out" && grep -q "leaving without a burned state" <<< "$out" && P "... unless LEAVE WITHOUT BURNING is typed" || F "typed leave: $(tail -3 <<< "$out")"
ended(){ # ended WORK: the menu's input ends; prints RC and whether the workdir is still there
  WORKDIR="$1" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; unset CEREMONY_STATE_DIR
    trap "echo SHREDDED" EXIT                      # stands in for cleanup(): menu_input_ended must clear it
    menu_input_ended; echo "RETURNED"' 2>&1 < /dev/null; echo "RC=$?"
}
out="$(ended "$S1")"
grep -q "RC=3" <<< "$out" && ! grep -q "SHREDDED\|RETURNED" <<< "$out" && grep -q "the workdir is KEPT, not shredded" <<< "$out" && [ -d "$S1/state" ] \
  && P "input ending with the state unburned: the workdir is kept, exit 3 (d9)" || F "EOF unburned: $(tail -4 <<< "$out")"
out="$(ended "$S2")"
grep -q "RETURNED" <<< "$out" && P "input ending with no signing state: the menu ends as before" || F "EOF no state: $(tail -3 <<< "$out")"
out="$(leave "$S2" "")"
grep -q "RC=0" <<< "$out" && P "a session with no signing state quits freely" || F "no state: $(tail -3 <<< "$out")"

hdr "the preconditions"
W5="$(new_work)"
out="$(WORKDIR="$W5" CEREMONY_STATE_DIR="$W5/state" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM; WORK="$WORKDIR"; step_ownerauth_rotate; echo "RC=$?"' 2>&1 < /dev/null)"
grep -q "RC=1" <<< "$out" && grep -q "this session made the offline keys (step o): step a makes their owner authorizations" <<< "$out" && [ ! -e "$W5/ownerauth-rotation" ] \
  && P "a session that made the offline keys: refused, use step a" || F "step-o session: $(tail -3 <<< "$out")"
W6="$(later_session)"
ln -s "$W6.disc/offline/offline-keys.sealed.json" "$T/link.sealed.json"
out="$(rotate "$W6" 'OA_ROTATE_SEALED="$T/link.sealed.json"')"
grep -q "RC=1" <<< "$out" && grep -q "is not the archived sealed file (a regular file, not a link)" <<< "$out" && [ ! -e "$W6/ownerauth-rotation" ] \
  && P "a link given as the sealed file: refused before anything" || F "link: $(tail -3 <<< "$out")"
W7="$(later_session)"
python3 - "$W7.disc/offline/offline-keys.sealed.json" <<'PY2'
import json, sys
d = json.load(open(sys.argv[1])); d["master_id"] = "0" * len(d["master_id"]); json.dump(d, open(sys.argv[1], "w"))
PY2
out="$(rotate "$W7")"
grep -q "RC=1" <<< "$out" && grep -q "the owner authorizations were NOT made" <<< "$out" && [ ! -e "$W7/ownerauth-rotation" ] \
  && P "an altered sealed file (its header changed): the shares do not open it, nothing is made" || F "altered sealed: $(tail -5 <<< "$out")"
out="$(bash -c 'source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM; WORK=""; step_ownerauth_rotate; echo "RC=$?"' 2>&1)"
grep -q "RC=1" <<< "$out" && grep -q "no session workdir" <<< "$out" && P "WORK empty: refused before anything" || F "empty WORK: $(tail -3 <<< "$out")"
src="$(bash -c 'source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM; OA_ROTATE_SEALED=/x; CEREMONY_SIMULATE= oa_rotate_sealed_in < /dev/null' 2>/dev/null)"
[ "$src" != /x ] && P "outside a simulation the sealed file is asked for, whatever OA_ROTATE_SEALED says" || F "sealed source: $src"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
