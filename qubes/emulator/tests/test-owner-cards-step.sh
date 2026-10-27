#!/usr/bin/env bash
# test-owner-cards-step.sh — ceremony.sh step c (ADR-0002 D30.7, regalia-ceremony#111 step 2): both owner cards enrolled
# by owner-cards.py (here against test_owner_cards.py's stand-in card, which "generates" a software gpg key's keys), then
# joined into cards.json and owner-cards.gpg; a rerun skips what is done; the archive stages both cards' public files
# and refuses a real burn while only one card is enrolled.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins first, as under run-tests.sh (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
python3 -Es -c 'import cryptography, yubikit.openpgp' 2>/dev/null || { echo "  SKIP: python3 lacks cryptography or yubikey-manager"; exit 0; }
command -v gpg >/dev/null && command -v age-keygen >/dev/null || { echo "  SKIP: gpg or age is not installed"; exit 0; }
grep -q '^AGE-SECRET-KEY-PQ-1' <<< "$(age-keygen -pq 2>/dev/null)" || { echo "  SKIP: this age has no -pq (the emulator job installs the pinned one)"; exit 0; }
PY_TEST="$(command -v python3)"; export PY_TEST
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ALLOW_SWAP=1
T="$(mktemp -d)"; export T
cleanup(){ local h; for h in "$T"/k-*; do [ -d "$h" ] && gpgconf --homedir "$h" --kill all 2>/dev/null; done; rm -rf -- "$T"; }
trap cleanup EXIT

# the enrolment of one card against the stand-in: owner-cards.enroll with test_owner_cards.FakeCard and a software key
# per role (made once, in $T/k-ROLE); FAIL_ROLE=ROLE makes that card's SIG attestation lie (touch not fixed)
cat > "$T/enroll.py" <<'PY'
import contextlib, importlib.machinery, importlib.util, os, shutil, sys
def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader)); loader.exec_module(module); return module
t = load("toc", os.path.join(os.environ["TESTS"], "test_owner_cards.py"))
oc = t.oc
work, role, serial = sys.argv[1], sys.argv[2], sys.argv[3]
home = os.path.join(os.environ["T"], "k-" + role)
if not os.path.isdir(home):
    os.mkdir(home, 0o700)
    t.software_key(home, role)
listing = __import__("subprocess").run(["gpg", "--homedir", home, "--with-colons", "--list-keys"], capture_output=True, text=True, check=True).stdout
fpr = listing.split("fpr:::::::::")[1].split(":")[0]
export = __import__("subprocess").run(["gpg", "--homedir", home, "--export", fpr], capture_output=True, check=True).stdout
keys = oc.certificate_keys(export, oc.gpg_capabilities(home))
lie = {"sig": {"8": t.make._der_octets(b"\x00")}} if os.environ.get("FAIL_ROLE") == role else {}
fake = t.FakeCard(serial, keys, lie=lie)
@contextlib.contextmanager
def card(s):
    fake.opened()
    yield fake, fake.firmware
def build(target, name, email, pin):
    for entry in os.listdir(home):
        if not entry.startswith("S."):
            path = os.path.join(home, entry)
            (shutil.copytree(path, os.path.join(target, entry), dirs_exist_ok=True) if os.path.isdir(path) else shutil.copy2(path, os.path.join(target, entry)))
    return fpr
pins = iter([t.ADMIN, t.USER])
try:
    oc.enroll(role, serial, os.environ["OC_NAME"], os.environ["OC_EMAIL"], os.path.join(work, "cards"), os.path.join(work, "breakglass.recipient"),
              ask_secret=lambda p: next(pins), card=card, build=build, seen=lambda h, s: None)
except oc.Refused as refusal:
    print("REFUSED: %s" % refusal, file=sys.stderr); sys.exit(1)
PY

new_work(){ local w; w="$(mktemp -d "$T/w.XXXXXX")"; ( umask 077; age-keygen -pq -o "$w/bg.key" 2>/dev/null; age-keygen -y "$w/bg.key" > "$w/breakglass.recipient" ); printf '%s' "$w"; }
run_step(){ # run_step WORK [FAIL_ROLE] [SECOND_SERIAL]: the operator inserts 40000001 (owner-main), then SECOND_SERIAL (40000002)
  WORKDIR="$1" FAIL_ROLE="${2:-}" SECOND="${3:-40000002}" TESTS="$HERE" OC_NAME="Owner" OC_EMAIL="owner@example.invalid" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""
    HERE="'"$SCRIPTS"'"; WORK="$WORKDIR"
    oc_insert_card(){ if [ "$1" = owner-main ]; then OC_SERIAL=40000001; else OC_SERIAL="$SECOND"; fi; }
    owner_card_enroll(){ "$PY_TEST" -Es "$T/enroll.py" "$WORK" "$1" "$2"; }
    step_owner_cards; echo "RC=$?"' 2>&1 < /dev/null
}
arch(){ # arch WORK SIMULATE
  WORKDIR="$1" SIM="$2" bash -c '
    source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM
    pause(){ :; }; ask(){ return 0; }; PRINTER=""; WORK="$WORKDIR"
    printf "0123456789abcdef\n" > "$WORK/escrow-mac.kcv"
    CEREMONY_SIMULATE="$SIM" step_archive; echo "RC=$?"' 2>&1 < /dev/null
}

hdr "both owner cards enrolled and joined"
W="$(new_work)"
out="$(run_step "$W")"
grep -q "RC=0" <<< "$out" && grep -q "owner cards done: cards.json (for card-record) and owner-cards.gpg (for step a)" <<< "$out" \
  && P "step c completes" || F "step c: $(tail -8 <<< "$out")"
for f in cards.json owner-cards.gpg owner-card-40000001.json owner-card-40000002.json owner-card-40000001.sig.attest.der \
         owner-card-40000002.att.der owner-card-40000001.rev.age; do
  [ -s "$W/cards/$f" ] && P "cards/$f is in the workdir" || F "cards/$f is missing"
done
roles="$(python3 -c 'import json,sys; print(",".join(k["role"] + "=" + k["serial"] for k in json.load(open(sys.argv[1]))["owner_keys"]))' "$W/cards/cards.json")"
[ "$roles" = "owner-main=40000001,owner-backup=40000002" ] && P "cards.json names owner-main and owner-backup" || F "roles: $roles"
grep -q "REMOVE the owner-main card now" <<< "$out" && grep -q "REMOVE the owner-backup card now" <<< "$out" && P "each card is to be removed after it" || F "remove: $out"
out="$(run_step "$W")"
grep -q "RC=0" <<< "$out" && grep -q "the owner-main card (40000001) is already enrolled" <<< "$out" && grep -q "the owner-backup card (40000002) is already enrolled" <<< "$out" \
  && P "run again: nothing is enrolled twice" || F "rerun: $(tail -5 <<< "$out")"

hdr "a card whose attestation lies: the step stops, the disc waits"
W2="$(new_work)"
out="$(run_step "$W2" owner-backup)"
grep -q "RC=1" <<< "$out" && grep -q "the owner-backup card (40000002) was NOT enrolled" <<< "$out" && grep -q "touch not fixed" <<< "$out" \
  && grep -q "now holds NEW keys: reset" <<< "$out" && [ ! -e "$W2/cards/cards.json" ] && P "a lying attestation: refused, said, nothing joined" || F "lie: $(tail -6 <<< "$out")"
out="$(arch "$W2" 0)"
grep -q "RC=1" <<< "$out" && grep -q "the owner cards are not finished" <<< "$out" && P "one card enrolled: a real burn is refused" || F "real archive: $(tail -4 <<< "$out")"
out="$(run_step "$W2")"
grep -q "RC=0" <<< "$out" && [ -s "$W2/cards/cards.json" ] && P "the step resumes with the backup card" || F "resume: $(tail -5 <<< "$out")"

hdr "the same card offered as both: refused"
W3="$(new_work)"
out="$(run_step "$W3" "" 40000001)"
grep -q "RC=1" <<< "$out" && grep -q "card 40000001 is already enrolled as the other owner card" <<< "$out" && P "owner-main's card again as owner-backup: refused" \
  || F "same card: $(tail -4 <<< "$out")"

hdr "the archive stages both cards' public files"
printf 'partial\n' > "$W/cards/owner-card-40000009.gpg"; printf 'partial\n' > "$W/cards/owner-card-40000009.sig.attest.der"   # a stray, unfinished card
arch "$W" 1 > "$T/arch.out"
partial=("$W"/mdisc/cards/*40000009*); [ ! -e "${partial[0]}" ] && ! grep -q 40000009 "$T/arch.out" && P "an unfinished card's files (no facts) are neither staged nor listed (d9)" \
  || F "partial staged: $(ls "$W/mdisc/cards" | tr '\n' ' ')"
burned="$(ls "$W/mdisc/cards" 2>/dev/null | tr '\n' ' ')"
for f in cards.json owner-cards.gpg owner-card-40000001.json owner-card-40000002.aut.attest.der owner-card-40000002.rev.age; do
  grep -q "$f" <<< "$burned" || F "$f is not staged (staged: $burned)"
done
grep -q "owner-card-40000001.att.der" <<< "$burned" && ! grep -q "bg.key\|gnupg" <<< "$burned" && P "certificates, attestations, facts and sealed revocations staged; no key or GnuPG home" \
  || F "staged: $burned"
grep -q "hsm-backups/cards/" "$T/arch.out" && P "the archive lists what to commit" || F "no commit list"

hdr "the preconditions"
W4="$(mktemp -d "$T/w.XXXXXX")"
out="$(run_step "$W4")"
grep -q "RC=1" <<< "$out" && grep -q "no break-glass recipient in this session" <<< "$out" && [ ! -e "$W4/cards" ] && P "no break-glass recipient: refused before anything" || F "no recipient: $out"
out="$(WORKDIR="$(new_work)" bash -c 'source "'"$SCRIPTS"'/ceremony.sh" >/dev/null 2>&1; trap - EXIT INT TERM; WORK="$WORKDIR"; OC_NAME=""; OC_EMAIL=""; step_owner_cards; echo "RC=$?"' 2>&1 < /dev/null)"
grep -q "RC=1" <<< "$out" && grep -q "the certificates need a name and an e-mail" <<< "$out" && P "no name or e-mail: refused" || F "no name: $(tail -3 <<< "$out")"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
