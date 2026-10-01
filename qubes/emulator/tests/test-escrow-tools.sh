#!/usr/bin/env bash
# test-escrow-tools.sh — the PIN escrow tools the archive disc carries (scripts/escrow/):
#   - pin_escrow_mac.py: the key on stdin only; KCV and MAC deterministic; select takes the highest
#     escrow whose MAC verifies across git history, so a deleted or MAC-replaced file cannot roll
#     recovery back, and it copies out exactly the verified bytes; the next sequence counts every
#     escrow ever committed;
#   - pin-escrow.sh refuses to run from inside the checkout it writes to (the disc's copy is the
#     producer);
#   - step_archive refuses to stage a disc without both tools.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
MAC="$SCRIPTS/escrow/pin_escrow_mac.py"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
KEY="$(printf '5a%.0s' {1..16})"   # a stand-in 32-hex key, built at runtime
g(){ git -C "$T/repo" -c user.name=t -c user.email=t@t "$@" >/dev/null 2>&1; }
put(){ printf '%s' "$2" > "$T/repo/escrow/$1"; python3 "$MAC" mac "$T/repo/escrow/$1" <<< "${3:-$KEY}" > "$T/repo/escrow/$1.mac"; }

hdr "the tools are present and executable"
for t in pin-escrow.sh pin_escrow_mac.py; do [ -x "$SCRIPTS/escrow/$t" ] && P "escrow/$t" || F "escrow/$t missing or not executable"; done

hdr "KCV and MAC"
k1="$(python3 "$MAC" kcv <<< "$KEY")"; k2="$(python3 "$MAC" kcv <<< "${KEY^^}")"
[[ "$k1" =~ ^[0-9a-f]{16}$ ]] && [ "$k1" = "$k2" ] && P "the KCV is 16 hex and ignores letter case" || F "KCV $k1 / $k2"
python3 "$MAC" kcv <<< "nothex" >/dev/null 2>&1 && F "a malformed key was accepted" || P "a malformed key is refused"

hdr "selection over git history"
mkdir -p "$T/repo/escrow"; g init -q
put pins-0001.age stale; g add -A; g commit -qm one
put pins-0002.age current; g add -A; g commit -qm two
sel(){ rm -f "$T/out"; python3 "$MAC" select "$T/repo" "$T/out" <<< "$KEY" 2>"$T/err"; }
[ "$(sel)" = pins-0002.age ] && [ "$(cat "$T/out")" = current ] && P "the highest verified escrow, exact bytes" || F "selected $(cat "$T/out" 2>/dev/null)"
[ "$(stat -c %a "$T/out")" = 600 ] && P "the copy is 0600" || F "copy mode $(stat -c %a "$T/out")"
g rm -q escrow/pins-0002.age escrow/pins-0002.age.mac; g commit -qm delete
[ "$(sel)" = pins-0002.age ] && [ "$(cat "$T/out")" = current ] && grep -q "NOTE pins-0002.age" "$T/err" \
  && P "deleting the newest pair does not roll recovery back (reported)" || F "after deletion: $(cat "$T/out" 2>/dev/null)"
put pins-0003.age forged "$(printf '00%.0s' {1..16})"; g add -A; g commit -qm forged
[ "$(sel)" = pins-0002.age ] && grep -q "SKIPPED pins-0003.age" "$T/err" && P "a forged escrow is skipped and reported" || F "forged escrow selected"
[ "$(python3 "$MAC" highest "$T/repo")" = 3 ] && P "the next sequence counts deleted escrows too (highest = 3, not 1)" || F "highest $(python3 "$MAC" highest "$T/repo")"
put pins-0004.age genuine; g add -A; g commit -qm four
printf 'f%.0s' {1..64} > "$T/repo/escrow/pins-0004.age.mac"; g add -A; g commit -qm "replace only the mac"
[ "$(sel)" = pins-0004.age ] && [ "$(cat "$T/out")" = genuine ] && P "replacing only the .mac does not hide the earlier valid pair" || F "after a MAC-only replacement: $(cat "$T/out" 2>/dev/null)"

mkdir -p "$T/empty"; git -C "$T/empty" init -q
python3 "$MAC" highest "$T/empty" >/dev/null 2>&1 && P "highest works with no escrow/ directory (every file deleted)" || F "highest fails without escrow/"

hdr "the producer refuses to run from the checkout it writes to"
mkdir -p "$T/repo/tools"; cp "$SCRIPTS/escrow/pin-escrow.sh" "$SCRIPTS/escrow/pin_escrow_mac.py" "$T/repo/tools/"
: > "$T/repo/escrow/breakglass.recipient"; printf 'x' > "$T/repo/escrow/breakglass.recipient"; printf '%s\n' "$k1" > "$T/repo/escrow/escrow-mac.kcv"
out="$(cd "$T/repo" && bash tools/pin-escrow.sh < /dev/null 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "archive disc" <<< "$out" && P "the repository copy refuses and names the disc's copy" || F "rc=$rc: $out"

hdr "the producer, end to end (the disc's copy, a stub age that records what it was given)"
mkdir -p "$T/disc" "$T/stub" "$T/co/escrow"; cp "$SCRIPTS/escrow/pin-escrow.sh" "$SCRIPTS/escrow/pin_escrow_mac.py" "$T/disc/"
cat > "$T/stub/age" <<'STUB'
#!/usr/bin/env bash
# stub: age -R <recipients> -o <out> <in>; "encrypts" by tagging the plaintext (test only)
while [ $# -gt 1 ]; do case "$1" in -R) shift 2;; -o) out="$2"; shift 2;; *) shift;; esac; done
{ printf 'STUB-AGE\n'; cat "$1"; } > "$out"
STUB
chmod +x "$T/stub/age"
git -C "$T/co" init -q; printf 'age1pq1stubrecipient\n' > "$T/co/escrow/breakglass.recipient"
printf '%s\n' "$k1" > "$T/co/escrow/escrow-mac.kcv"
fp="$(sha256sum "$T/co/escrow/breakglass.recipient" | cut -c1-16)"
six="7310048261 7310048261 8420159372 8420159372 9531260483 9531260483 90817263 90817263 a1b2c3 a1b2c3 72635445 72635445"
before="$(ls /dev/shm)"
out="$(cd "$T/co" && printf '%s\n' "$fp" "$KEY" $six | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1)"; rc=$?
[ "$rc" = 0 ] && [ -s "$T/co/escrow/pins-0001.age" ] && [ -s "$T/co/escrow/pins-0001.age.mac" ] \
  && P "six devices escrowed to pins-0001.age + .mac (a 6-character YubiKey PIN accepted)" || F "rc=$rc: $out"
[ "$(grep -cE '^(hsm|yubikey)_[abc]=' "$T/co/escrow/pins-0001.age")" = 6 ] && grep -qx 'yubikey_b=a1b2c3' "$T/co/escrow/pins-0001.age" \
  && P "the plaintext handed to age holds exactly the six device=PIN lines" || F "plaintext: $(cat "$T/co/escrow/pins-0001.age")"
git -C "$T/co" add -A >/dev/null; git -C "$T/co" -c user.name=t -c user.email=t@t commit -qm e >/dev/null
rm -f "$T/out"; [ "$(python3 "$MAC" select "$T/co" "$T/out" <<< "$KEY" 2>/dev/null)" = pins-0001.age ] \
  && P "its MAC verifies with the key" || F "the producer's MAC does not verify"
[ "$(ls /dev/shm)" = "$before" ] && P "nothing left in /dev/shm" || F "left in /dev/shm: $(comm -13 <(echo "$before") <(ls /dev/shm))"
out="$(cd "$T/co" && printf '%s\n' "$fp" "$KEY" 7310048261 7310048262 | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q differ <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] && P "mismatched entries: refused, nothing written" || F "rc=$rc: $out"
out="$(cd "$T/co" && printf '%s\n' "$fp" "$(printf '11%.0s' {1..16})" | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "does not match" <<< "$out" && P "a key that does not match the KCV: refused" || F "rc=$rc: $out"

hdr "the archive step refuses a disc without the escrow tools"
mkdir -p "$T/scripts"; cp "$SCRIPTS"/ceremony.sh "$T/scripts/"
out="$(
  # shellcheck disable=SC1091
  source "$T/scripts/ceremony.sh" >/dev/null 2>&1
  ask(){ return 0; }; pause(){ :; }
  # shellcheck disable=SC2034  # read by the sourced ceremony.sh
  PRINTER=""
  HERE="$T/scripts"; init_work >/dev/null 2>&1
  step_archive 2>&1; echo "RC=$?"
)"
grep -q "RC=1" <<< "$out" && grep -q "PIN escrow tools" <<< "$out" && P "no escrow tools, no disc" || F "$(tail -5 <<< "$out")"

hdr "the real archive step refuses a disc without a valid escrow-mac.kcv"
out="$(
  # shellcheck disable=SC1091
  source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1
  ask(){ return 0; }; pause(){ :; }
  # shellcheck disable=SC2034  # read by the sourced ceremony.sh
  PRINTER=""
  init_work >/dev/null 2>&1; printf 'not-a-kcv\n' > "$WORK/escrow-mac.kcv"
  CEREMONY_SIMULATE=0 step_archive 2>&1; echo "RC=$?"
)"
grep -q "RC=1" <<< "$out" && grep -q "escrow-mac.kcv (step 0) is missing or malformed" <<< "$out" \
  && P "a malformed KCV: no disc" || F "$(tail -5 <<< "$out")"

echo; echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
