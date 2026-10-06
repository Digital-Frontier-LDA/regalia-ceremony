#!/usr/bin/env bash
# test-release-key-step.sh — ceremony.sh step r (ADR-0002 D29.2, D30; regalia-ceremony#124): the developers' set made
# (developer-keys.py generate), every form copied and typed back (record_share, stood in for by a typist) and proven
# (verify-forms), the release key imported onto both release cards (release_import_card, here the stand-in card of
# test_developer_keys.py driving developer-keys.release_import), the facts for card-record; and the archive staging
# the set and the facts, refusing a real burn until both cards hold the key.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins first, as under run-tests.sh (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
python3 -Es -c 'import shamir_mnemonic, cryptography, yubikit.openpgp' 2>/dev/null || { echo "  SKIP: python3 lacks shamir-mnemonic, cryptography or yubikey-manager"; exit 0; }
command -v age >/dev/null && command -v age-keygen >/dev/null || { echo "  SKIP: age is not installed"; exit 0; }
PY_TEST="$(command -v python3)"; export PY_TEST          # the interpreter checked above (ceremony.sh sets its own PATH)
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ALLOW_SWAP=1 CEREMONY_THRESHOLD=2 CEREMONY_SHARES=3
T="$(mktemp -d)"; export T; trap 'rm -rf -- "$T"' EXIT
if grep -q '^AGE-SECRET-KEY-PQ-1' <<< "$(age-keygen -pq 2>/dev/null)"; then PQ=(-pq); else PQ=(); export CEREMONY_ALLOW_CLASSICAL_BREAKGLASS=1; fi
new_work(){ local w; w="$(mktemp -d "$T/w.XXXXXX")"; ( umask 077; age-keygen ${PQ[@]+"${PQ[@]}"} -o "$w/bg.key" 2>/dev/null; age-keygen -y "$w/bg.key" > "$w/breakglass.recipient" ); printf '%s' "$w"; }

# the import onto a stand-in card: developer-keys.release_import with test_developer_keys.FakeCard, the k shares the
# first two forms (kept by the typist), the PINs a non-default pair; FAIL_CARD=N makes card N fail its read-back
cat > "$T/import.py" <<'PY'
import importlib.machinery, importlib.util, io, os, sys, contextlib
tests = os.environ["TESTS"]
def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader)); loader.exec_module(module); return module
t = load("tdk", os.path.join(tests, "test_developer_keys.py"))
work, n, serial = sys.argv[1], sys.argv[2], sys.argv[3]
fake = t.FakeCard(fail="uif-after" if os.environ.get("FAIL_CARD") == n else None)
@contextlib.contextmanager
def card(s):
    yield fake, "5.7.4"
pins = iter([fake.admin, fake.user])
shares = open(os.path.join(work, "kept-shares")).read()
try:
    t.dk.release_import(os.path.join(work, "developers", "developers.sealed.json"), serial, os.path.join(work, "cards"), io.StringIO(shares),
                        ask_secret=lambda prompt: next(pins), card=card)
except t.dk.Refused as refusal:
    print("REFUSED: %s" % refusal, file=sys.stderr); sys.exit(1)
PY

run_step(){ # run_step WORK [FAIL_CARD]
  WORKDIR="$1" FAIL_CARD="${2:-}" TESTS="$HERE" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"
    record_share(){ cat "$2" >> "$3"; printf "\n" >> "$3"; [ -s "$WORK/kept-shares" ] && [ "$(wc -l < "$WORK/kept-shares")" -ge 2 ] || { cat "$2"; printf "\n"; } >> "$WORK/kept-shares"; }
    rk_insert_card(){ RK_SERIAL=$((40000002 + $1)); }
    release_import_card(){ "$PY_TEST" -Es "$T/import.py" "$WORK" "$1" "$2"; }
    step_release_key; echo "RC=$?"' 2>&1
}
arch(){ # arch WORK SIMULATE
  WORKDIR="$1" SIM="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""; WORK="$WORKDIR"
    printf "0123456789abcdef\n" > "$WORK/escrow-mac.kcv"
    CEREMONY_SIMULATE="$SIM" step_archive; echo "RC=$?"' 2>&1
}

hdr "the developers' set, its forms proven, the release key on both release cards"
W="$(new_work)"
out="$(run_step "$W")"
grep -q "RC=0" <<< "$out" && grep -q "release key done: both release cards hold it" <<< "$out" && grep -q "FORMS VERIFIED 1,2,3" <<< "$out" \
  && P "step r completes" || F "step r: $(tail -12 <<< "$out")"
for f in developers/developers.sealed.json developers/developers.breakglass.age developers/developers.record.json \
         cards/release-import-40000003.json cards/release-import-40000004.json; do
  [ -s "$W/$f" ] && P "$f is in the workdir" || F "$f is missing"
done
[ ! -e "$W/developers/developers-shares.txt" ] && P "the shares file is shredded once the forms are proven" || F "shares file left"
fp1="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$W/cards/release-import-40000003.json")"
fp2="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$W/cards/release-import-40000004.json")"
[ -n "$fp1" ] && [ "$fp1" = "$fp2" ] && P "both cards hold one key, one fingerprint" || F "fingerprints: $fp1 / $fp2"
out="$(run_step "$W")"
grep -q "RC=0" <<< "$out" && ! grep -q "FORMS VERIFIED" <<< "$out" && P "run again: nothing is made or imported twice" || F "rerun: $(tail -5 <<< "$out")"

hdr "a release card that fails its read-back: the step stops, the disc waits"
W2="$(new_work)"
out="$(run_step "$W2" 2)"
grep -q "RC=1" <<< "$out" && grep -q "release card 2 (40000004) was NOT imported" <<< "$out" && grep -q "unusable for release" <<< "$out" \
  && P "card 2 refused, said by developer-keys" || F "failing card: $(tail -6 <<< "$out")"
out="$(arch "$W2" 0)"
grep -q "RC=1" <<< "$out" && grep -q "the release key is not finished" <<< "$out" && P "one card only: a real burn is refused" || F "real archive: $(tail -4 <<< "$out")"
out="$(run_step "$W2")"
grep -q "RC=0" <<< "$out" && [ -s "$W2/cards/release-import-40000004.json" ] && P "the step resumes with the second card" || F "resume: $(tail -5 <<< "$out")"

hdr "the same release card inserted twice: refused"
W4="$(new_work)"
out="$(WORKDIR="$W4" TESTS="$HERE" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"
    record_share(){ cat "$2" >> "$3"; printf "\n" >> "$3"; [ -s "$WORK/kept-shares" ] && [ "$(wc -l < "$WORK/kept-shares")" -ge 2 ] || { cat "$2"; printf "\n"; } >> "$WORK/kept-shares"; }
    rk_insert_card(){ RK_SERIAL=40000003; }
    release_import_card(){ "$PY_TEST" -Es "$T/import.py" "$WORK" "$1" "$2"; }
    step_release_key; echo "RC=$?"' 2>&1)"
grep -q "RC=1" <<< "$out" && grep -q "release card 40000003 is already imported: insert the OTHER release card" <<< "$out" \
  && P "card 1 again as card 2: refused" || F "same card twice: $(tail -4 <<< "$out")"

hdr "the archive stages the developers' set and both cards' facts"
arch "$W" 1 > "$T/arch.out"
burned="$(ls "$W/mdisc/developers" 2>/dev/null | tr '\n' ' ')"
for f in developers.sealed.json developers.breakglass.age developers.record.json release-import-40000003.json release-import-40000004.json; do
  grep -q "$f" <<< "$burned" || F "$f is not staged (staged: $burned)"
done
grep -q "release-import-40000004.json" <<< "$burned" && P "the set and both facts are staged in developers/" || F "staged: $burned"
[ -z "$(find "$W/mdisc" -name '*shares*' -o -name 'dsh*' 2>/dev/null)" ] && P "no share is staged" || F "a share is staged"
grep -q "hsm-backups/developers/" "$T/arch.out" && P "the archive lists what to commit" || F "no commit list"

hdr "the preconditions"
W3="$(mktemp -d "$T/w.XXXXXX")"
out="$(run_step "$W3")"
grep -q "RC=1" <<< "$out" && grep -q "make the break-glass key first" <<< "$out" && [ ! -e "$W3/developers" ] && P "no break-glass recipient: refused before anything" || F "no recipient: $out"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
