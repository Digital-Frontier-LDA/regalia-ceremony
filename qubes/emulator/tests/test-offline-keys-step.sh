#!/usr/bin/env bash
# test-offline-keys-step.sh — ceremony.sh step o (ADR-0002 D28, regalia-ceremony#111): the offline keys generated in
# the RAM workdir, each share copied by hand and typed back (record_share, stood in for here by a typist), the copies
# typed back proven against the sealed file (offline-keys.py verify-forms), the shares file shredded; and the archive
# step burning the sealed file, the break-glass copy and the records, refusing while the forms are unproven.
# Needs python3 with shamir-mnemonic and cryptography (the emulator image has both) and age.
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
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ALLOW_SWAP=1 CEREMONY_THRESHOLD=2 CEREMONY_SHARES=3
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# one run of step o in a fresh shell; TYPIST says what the stand-in for record_share does with each share:
#   copy     types it back exactly (the sink gets it)
#   refuse:N refuses share N (as three mismatches do)
#   wrong:N  types back, for share N, a valid share of ANOTHER set (a form copied from the wrong sheet)
run_step(){ # run_step WORK TYPIST
  local work="$1" typist="$2"
  WORKDIR="$work" TYPIST="$typist" FOREIGN="$T/foreign" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"
    record_share(){
      local n="${1#*share }"; n="${n%% of*}"
      case "$TYPIST" in
        refuse:"$n") return 1;;
        wrong:"$n") sed -n 1p "$FOREIGN" >> "$3"; return 0;;
      esac
      cat "$2" >> "$3"; printf "\n" >> "$3"
    }
    step_offline_keys; echo "RC=$?"' 2>&1
}
new_work(){ local w; w="$(mktemp -d "$T/work.XXXXXX")"; ( umask 077; age-keygen -o "$w/bg.key" 2>/dev/null; age-keygen -y "$w/bg.key" > "$w/breakglass.recipient" ); printf '%s' "$w"; }
python3 -Es - "$T/foreign" <<'PY'
import sys
from shamir_mnemonic import generate_mnemonics
open(sys.argv[1], "w").write("\n".join(generate_mnemonics(1, [(2, 3)], b"\x05" * 32)[0]) + "\n")
PY

hdr "generate, copy and type back every form, prove them, shred the shares"
W="$(new_work)"
out="$(run_step "$W" copy)"
grep -q "RC=0" <<< "$out" && grep -q "^ROOT-ENTRY {\"alg\": \"ed25519\"" <<< "$out" && grep -q "FORMS VERIFIED 1,2,3" <<< "$out" \
  && P "the keys are generated and the three forms proven" || F "step o: $(tail -15 <<< "$out")"
for f in offline-keys.sealed.json offline-keys.breakglass.age offline-keys.record.json; do
  [ -s "$W/offline/$f" ] && P "$f is in the workdir" || F "$f is missing"
done
ls "$W"/offline/forms-verified-*.record.json >/dev/null 2>&1 && P "the forms-verified record is written" || F "no forms-verified record"
[ ! -e "$W/offline/offline-shares.txt" ] && [ ! -e "$W/offline-typed.txt" ] && ! ls "$W"/osh* >/dev/null 2>&1 \
  && P "the shares file, the copies typed back and each share's file are gone" || F "left behind: $(ls "$W" "$W/offline")"
out="$(run_step "$W" copy)"
grep -q "RC=0" <<< "$out" && grep -q "already proven" <<< "$out" && ! grep -q "ROOT-ENTRY" <<< "$out" \
  && P "run again: nothing is generated twice" || F "re-run: $(tail -5 <<< "$out")"

hdr "a form not verified: the keys are kept, the forms redone"
W="$(new_work)"
out="$(run_step "$W" refuse:2)"
grep -q "RC=1" <<< "$out" && grep -q "forms 2 were not verified" <<< "$out" && [ -s "$W/offline/offline-shares.txt" ] && [ ! -e "$W/offline-typed.txt" ] \
  && P "refused; the shares file stays for the redo, no typed copy is kept" || F "refused form: $(tail -5 <<< "$out")"
root="$(python3 -Es -c 'import json,sys; print(json.load(open(sys.argv[1]))["record"]["root_entry"]["key"])' "$W/offline/offline-keys.record.json")"
out="$(run_step "$W" copy)"
grep -q "RC=0" <<< "$out" && ! grep -q "ROOT-ENTRY" <<< "$out" && [ ! -e "$W/offline/offline-shares.txt" ] \
  && [ "$(python3 -Es -c 'import json,sys; print(json.load(open(sys.argv[1]))["record"]["root_entry"]["key"])' "$W/offline/offline-keys.record.json")" = "$root" ] \
  && P "run again: the same keys, the forms redone and proven" || F "redo: $(tail -5 <<< "$out")"

hdr "a form copied from another set's sheet: the copies do not open the sealed keys"
W="$(new_work)"
out="$(run_step "$W" wrong:2)"
grep -q "RC=1" <<< "$out" && grep -q "belongs to another set\|do NOT open the sealed keys" <<< "$out" && [ -s "$W/offline/offline-shares.txt" ] \
  && P "refused, nothing shredded" || F "wrong form: $(tail -5 <<< "$out")"

hdr "no break-glass recipient in this session: nothing is generated"
W="$(mktemp -d "$T/work.XXXXXX")"
out="$(run_step "$W" copy)"
grep -q "RC=1" <<< "$out" && grep -q "make the break-glass key first" <<< "$out" && [ ! -e "$W/offline" ] && P "refused before anything" || F "no recipient: $out"

hdr "the archive: the public files go on the disc; unproven forms stop a real burn"
W="$(new_work)"; run_step "$W" copy >/dev/null
arch(){ # arch WORK SIMULATE
  WORKDIR="$1" SIM="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""; WORK="$WORKDIR"
    printf "0123456789abcdef\n" > "$WORK/escrow-mac.kcv"
    CEREMONY_SIMULATE="$SIM" step_archive; echo "RC=$?"' 2>&1
}
out="$(arch "$W" 1)"
burned="$(ls "$W/mdisc/offline" 2>/dev/null | tr '\n' ' ')"
for f in offline-keys.sealed.json offline-keys.breakglass.age offline-keys.record.json; do
  grep -q "$f" <<< "$burned" || F "$f is not staged for the disc (staged: $burned)"
done
grep -q "forms-verified-" <<< "$burned" && P "the sealed file, the break-glass copy and both records are staged in offline/" || F "staged: $burned"
[ -z "$(find "$W/mdisc" -name '*shares*' -o -name 'osh*' 2>/dev/null)" ] && P "no share is staged" || F "a share is staged"
W2="$(new_work)"; run_step "$W2" refuse:1 >/dev/null
out="$(arch "$W2" 0)"
grep -q "RC=1" <<< "$out" && grep -q "the offline keys' forms were not proven" <<< "$out" && P "unproven forms: a real burn is refused" || F "real archive: $(tail -5 <<< "$out")"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
