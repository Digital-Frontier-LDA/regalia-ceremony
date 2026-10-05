#!/usr/bin/env bash
# test-ownerauth-step.sh — ceremony.sh step a (regalia-kms#242, regalia-ceremony#122): each KMS host's TPM owner
# authorization made by offline-keys.py ownerauth (the root signs, the offline set's shares typed), both owner
# cards proving they open every node's envelope (ownerauth-verify), the root signing that proof (--summary); and the
# archive staging the files, refusing a real burn while the proof is missing. Two software GnuPG homes stand in for
# the owner cards; a gpg wrapper first on PATH answers --card-status as the inserted card and decrypts with its home.
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
  # the root-signed card record naming card1 and card2 as the owner cards (only what ownerauth reads of it)
  python3 -Es - "$SCRIPTS/offline-keys.py" "$w" "$("$REAL_GPG" --homedir "$T/card1" --with-colons --list-keys | awk -F: '/^fpr/{print $10}' | sed -n 2p)" \
      "$("$REAL_GPG" --homedir "$T/card2" --with-colons --list-keys | awk -F: '/^fpr/{print $10}' | sed -n 2p)" <<'PY2'
import importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader("ok", sys.argv[1]); ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("ok", loader)); loader.exec_module(ok)
w = sys.argv[2]
sealed = json.load(open(w + "/offline/offline-keys.sealed.json"))
shares = [" ".join(open(w + "/two-shares").read().splitlines()[i].split()) for i in range(2)]
root = ok._private_key(ok.unseal(ok.combine(shares, sealed)[0], sealed)["keys"]["root"])
record = {"schema": ok.SCHEMA_CARD_RECORD, "ownerauth_recipients": [{"serial": "1001", "primary": "A" * 40, "subkey": sys.argv[3]},
                                                                     {"serial": "1002", "primary": "B" * 40, "subkey": sys.argv[4]}]}
json.dump({"record": record, "signature": root.sign(ok.RECORD_DOMAIN + ok.canonical(record)).hex()}, open(w + "/cards/card-record-1.record.json", "w"))
PY2
  printf '%s' "$w"
}

run_step(){ # run_step WORK SECOND_CARD: the operator inserts card1 (serial 1001) then SECOND_CARD (serial 1002)
  WORKDIR="$1" SECOND="$2" PATH="$T/shim:$PATH" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; OA_SHARES_FROM="$WORK/two-shares"
    oa_insert_card(){ if [ "$1" = 1 ]; then OA_SERIAL=1001; export CARD_HOME="$T/card1"; else OA_SERIAL=1002; export CARD_HOME="$T/$SECOND"; fi
                      export CARD_SERIAL="$OA_SERIAL"; }
    step_ownerauth; echo "RC=$?"' 2>&1
}
arch(){ # arch WORK SIMULATE
  WORKDIR="$1" SIM="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""; WORK="$WORKDIR"
    printf "0123456789abcdef\n" > "$WORK/escrow-mac.kcv"
    CEREMONY_SIMULATE="$SIM" step_archive; echo "RC=$?"' 2>&1
}

hdr "the owner authorizations made, both owner cards proving them, the root signing the proof"
W="$(new_work)"
out="$(run_step "$W" card2)"
grep -q "RC=0" <<< "$out" && grep -q "owner authorizations done: both owner cards open every node's envelope" <<< "$out" \
  && P "step a completes" || F "step a: $(tail -15 <<< "$out")"
for f in ownerauth.record.json ownerauth-verified.record.json ownerauth-verify.jsonl ownerauth-a.yk.gpg ownerauth-b.bg.sops ownerauth-c.yk.gpg; do
  [ -s "$W/ownerauth/$f" ] && P "$f is in the workdir" || F "$f is missing"
done
grep -q "YubiKey 1001 opens a, b, c" <<< "$out" && grep -q "YubiKey 1002 opens a, b, c" <<< "$out" && P "each card proved every node" \
  || F "per-card proof: $(grep -i yubikey <<< "$out")"
out="$(run_step "$W" card2)"
grep -q "RC=0" <<< "$out" && grep -q "already proven in this session" <<< "$out" && P "run again: nothing is made twice" || F "rerun: $(tail -5 <<< "$out")"

hdr "the wrong second card: refused, no proof, and a real burn waits for it"
W2="$(new_work)"
out="$(run_step "$W2" stranger)"
grep -q "RC=1" <<< "$out" && grep -q "owner card 2 (1002) did NOT open every envelope" <<< "$out" && [ ! -e "$W2/ownerauth/ownerauth-verified.record.json" ] \
  && P "a card that opens nothing is refused" || F "stranger: $(tail -8 <<< "$out")"
out="$(arch "$W2" 0)"
grep -q "RC=1" <<< "$out" && grep -q "the owner authorizations are not proven by both owner cards" <<< "$out" \
  && P "unproven owner authorizations: a real burn is refused" || F "real archive: $(tail -5 <<< "$out")"
out="$(arch "$W2" 1)"
grep -q "simulated run: the owner authorizations are not proven" <<< "$out" && P "a simulated burn says so" || F "simulated archive: $(tail -5 <<< "$out")"

hdr "the same card inserted twice cannot stand in for both (3e on #130)"
W7="$(new_work)"
out="$(run_step "$W7" card1)"
grep -q "RC=1" <<< "$out" && grep -q "not yet proven to open every envelope" <<< "$out" && [ ! -e "$W7/ownerauth/ownerauth-verified.record.json" ] \
  && P "card 1 twice: the summary refuses, nothing signed" || F "same card twice: $(tail -6 <<< "$out")"

hdr "outside a simulation a stray OA_NODES is ignored: the three hosts, always (3e on #130)"
W8="$(new_work)"
out="$(WORKDIR="$W8" PATH="$T/shim:$PATH" OA_NODES=a,b bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"
    oa_shares_in(){ printf "%s" "$WORK/two-shares"; }           # the terminal, stood in for
    python3(){ CEREMONY_SIMULATE=1 command python3 "$@"; }       # offline-keys keeps this machine'"'"'s test overrides (an older age)
    oa_insert_card(){ if [ "$1" = 1 ]; then OA_SERIAL=1001; export CARD_HOME="$T/card1"; else OA_SERIAL=1002; export CARD_HOME="$T/card2"; fi
                      export CARD_SERIAL="$OA_SERIAL"; }
    CEREMONY_SIMULATE= step_ownerauth; echo "RC=$?"' 2>&1)"
nodes="$(python3 -c 'import json,sys; print(",".join(sorted(json.load(open(sys.argv[1]))["record"]["nodes"])))' "$W8/ownerauth/ownerauth.record.json" 2>/dev/null)"
grep -q "RC=0" <<< "$out" && [ "$nodes" = "a,b,c" ] && P "OA_NODES=a,b outside a simulation: records for a, b and c" || F "real-mode nodes: $nodes $(tail -4 <<< "$out")"

hdr "offline keys made and step a skipped altogether: a real burn is refused too (d9 on #130)"
W5="$(new_work)"
out="$(arch "$W5" 0)"
grep -q "RC=1" <<< "$out" && grep -q "step a skipped, failed or unfinished" <<< "$out" && P "no ownerauth/ at all: a real burn is refused" \
  || F "skipped step a: $(tail -5 <<< "$out")"

hdr "a card gpg cannot see is said as such"
W6="$(new_work)"
out="$(WORKDIR="$W6" PATH="$T/shim:$PATH" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; OA_SHARES_FROM="$WORK/two-shares"
    gpg(){ for a in "$@"; do [ "$a" = --card-status ] && return 2; done; command gpg "$@"; }
    oa_insert_card(){ OA_SERIAL=1001; }
    step_ownerauth; echo "RC=$?"' 2>&1)"
grep -q "RC=1" <<< "$out" && grep -q "gpg cannot see a card: is owner card 1 inserted, and is pcscd running" <<< "$out" \
  && P "no card seen: said by name" || F "unseen card: $(tail -5 <<< "$out")"

hdr "no session workdir: the step does nothing"
out="$(bash -c 'source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM; WORK=""; step_ownerauth; echo "RC=$?"' 2>&1)"
grep -q "RC=1" <<< "$out" && grep -q "no session workdir" <<< "$out" && P "WORK empty: refused before anything" || F "empty WORK: $(tail -3 <<< "$out")"

hdr "the archive stages the envelopes, the records and the verify log"
arch "$W" 1 > "$T/arch.out"
burned="$(ls "$W/mdisc/ownerauth" 2>/dev/null | tr '\n' ' ')"
for f in ownerauth.record.json ownerauth-verified.record.json ownerauth-verify.jsonl ownerauth-a.yk.gpg ownerauth-a.bg.sops; do
  grep -q "$f" <<< "$burned" || F "$f is not staged (staged: $burned)"
done
grep -q "ownerauth-verify-key\." <<< "$burned" && P "the envelopes, records, verify keys and log are staged in ownerauth/" || F "staged: $burned"
grep -q "hsm-backups/ownerauth/" "$T/arch.out" && P "the archive step lists what to commit" || F "no commit list"

hdr "the step's preconditions, and the simulation-only share source"
W3="$(mktemp -d "$T/w.XXXXXX")"
out="$(run_step "$W3" card2)"
grep -q "RC=1" <<< "$out" && grep -q "run step o first" <<< "$out" && [ ! -e "$W3/ownerauth" ] && P "no offline keys: refused before anything" || F "no step o: $out"
W4="$(new_work)"; rm "$W4/cards/owner-cards.gpg"
out="$(run_step "$W4" card2)"
grep -q "RC=1" <<< "$out" && grep -q "no owner cards' public keys" <<< "$out" && P "no owner cards' keys: refused" || F "no keys: $out"
W5b="$(new_work)"; rm "$W5b/cards/card-record-1.record.json"
out="$(run_step "$W5b" card2)"
grep -q "RC=1" <<< "$out" && grep -q "no card record in this session" <<< "$out" && P "no card record: refused" || F "no card record: $(tail -3 <<< "$out")"

hdr "the rehearsal drill: the recovery identity from the shares, one node's recovery copy checked, the key shredded"
drill(){ # drill WORK NODE
  WORKDIR="$1" NODE="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"; OA_SHARES_FROM="$WORK/two-shares"
    ownerauth_drill "$NODE"; echo "RC=$?"' 2>&1
}
out="$(drill "$W" a)"
grep -q "RC=0" <<< "$out" && grep -q "owner-auth drill passed: node a's recovery copy opens" <<< "$out" && [ ! -e "$W/ownerauth-recovery.key" ] \
  && P "the drill opens node a's recovery copy, checks it, and leaves no identity file" || F "drill: $(tail -6 <<< "$out")"
cp "$W/ownerauth/ownerauth-b.bg.sops" "$T/b.keep"; cp "$W/ownerauth/ownerauth-a.bg.sops" "$W/ownerauth/ownerauth-b.bg.sops"
out="$(drill "$W" b)"
grep -q "RC=1" <<< "$out" && grep -q "owner-auth drill FAILED for node b" <<< "$out" && [ ! -e "$W/ownerauth-recovery.key" ] \
  && P "a recovery copy holding another node's value fails the drill, and the identity file is still removed" || F "swapped copy: $(tail -6 <<< "$out")"
cp "$T/b.keep" "$W/ownerauth/ownerauth-b.bg.sops"
src="$(bash -c 'source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM; OA_SHARES_FROM=/x; CEREMONY_SIMULATE= oa_shares_in')"
[ "$src" = /dev/tty ] && P "outside a simulation the shares come from the terminal, whatever OA_SHARES_FROM says" || F "share source: $src"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
