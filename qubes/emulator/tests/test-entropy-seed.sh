#!/usr/bin/env bash
# ceremony.sh step e (step_entropy_seed): a new wallet seed from dice + HSM + /dev/urandom.
# Owner's rule (2026-09-25): dice are ALWAYS mixed in on top of the Nitrokey HSM's RNG, so the
# step must refuse without either. Runs natively: hsm-random.py is a stub, the dice come from a
# file (dice-entropy.py --from-stdin), hsm-random.py is a stub, everything else is the real code.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/s" "$T/bin"
cp "$SCRIPTS"/*.py "$T/s/"
mv "$T/s/dice-entropy.py" "$T/s/dice-entropy-real.py"
cat > "$T/s/dice-entropy.py" <<'PY'
import os, sys
os.execvp("python3", ["python3", os.path.join(os.path.dirname(__file__), "dice-entropy-real.py"), "--from-stdin"] + sys.argv[1:])
PY
# hsm-random.py stub: 32 bytes unless NO_HSM (no reader) or SHORT_RNG (a device that answers nothing)
cat > "$T/s/hsm-random.py" <<'PY'
import os, sys
out = sys.argv[sys.argv.index("--out") + 1]
if os.environ.get("NO_HSM"):
    sys.exit("hsm-random: no Nitrokey HSM / Pico HSM reader found")
with open(out, "wb") as fh:
    fh.write(b"" if os.environ.get("SHORT_RNG") else os.urandom(32))
print("hsm-random: 32 bytes from Nitrokey Nitrokey HSM (DENK00000000000) 00 00")
PY
# Fixed rolls, two dice per line as the wizard asks: random ones would trip the fairness check
# (correctly) about once in 3,000 runs and make this test flaky.
F50=35116424236655142311453662245135524611326443155226
for i in $(seq 0 2 48); do echo "${F50:$i:2}"; done > "$T/rolls"

run(){ # $1 = stdin file; env passes through. Prints the step's output then "WORK: <files>" and a mnemonic check.
  ( PATH="$T/bin:$PATH"; source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1
    HERE="$T/s"; WORK="$T/w.$RANDOM"; mkdir -p "$WORK"; ask(){ return 0; }
    step_entropy_seed < "$1" 2>&1; echo "RC=$?"
    echo "WORK: $(ls "$WORK" | tr '\n' ' ')"
    [ -s "$WORK/secret.in" ] && python3 -c "
import sys
try:
    from mnemonic import Mnemonic
except ImportError:
    print('MNEMONIC-UNCHECKED'); sys.exit()
w=open('$WORK/secret.in').read().split(); print('MNEMONIC-OK' if len(w)==24 and Mnemonic('english').check(' '.join(w)) else 'MNEMONIC-BAD')"
  ) 2>&1 | sed $'s/\033\\[[0-9;]*m//g'
}

hdr "dice + HSM + OS: a valid 24-word seed, and no entropy file left behind"
out="$(run "$T/rolls")"
grep -q "RC=0" <<< "$out" && P "the step succeeds" || F "the step failed: $(tail -5 <<< "$out")"
grep -qE "MNEMONIC-(OK|UNCHECKED)" <<< "$out" && P "secret.in holds the new seed" || F "no valid seed written"
grep -q "WORK: secret.in $" <<< "$out" && P "dice, HSM, OS and mixed entropy files are removed" || F "entropy files left: $(grep WORK: <<< "$out")"
grep -qE "mixed 3 sources" <<< "$out" && P "all three sources were mixed" || F "not all three sources mixed"

hdr "no HSM attached: REFUSE, and no seed from dice + OS alone"
out="$(NO_HSM=1 run "$T/rolls")"
grep -q "RC=1" <<< "$out" && grep -q "no random bytes from an HSM" <<< "$out" && P "refused without the HSM" || F "did not refuse without the HSM"
grep -q "secret.in" <<< "$(grep WORK: <<< "$out")" && F "a seed was written without the HSM" || P "no seed written"

hdr "the HSM returns nothing: REFUSE"
out="$(SHORT_RNG=1 run "$T/rolls")"
grep -q "RC=1" <<< "$out" && grep -q "no random bytes from an HSM" <<< "$out" && P "a short HSM read is refused" || F "a short HSM read was accepted"

hdr "no dice (input ends): REFUSE before touching the HSM"
: > "$T/empty"
out="$(run "$T/empty")"
grep -q "dice entropy not collected" <<< "$out" && P "no dice, no seed" || F "went on without dice"

hdr "made-up digits with no repeat in a row: REFUSED, nothing written"
printf '%s\n' 3516 4236 5142 3145 3625 1352 4613 2643 1524 1326 4351 6245 45 > "$T/typed"
o="$(python3 "$SCRIPTS/dice-entropy.py" --from-stdin --out "$T/typed.hex" < "$T/typed" 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "twice in a row" <<< "$o" && [ ! -e "$T/typed.hex" ] && P "refused, no file" || F "typed digits accepted: $o"

hdr "dice-entropy selftest"
python3 "$SCRIPTS/dice-entropy.py" --selftest >/dev/null && P "selftest passes" || F "selftest failed"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
