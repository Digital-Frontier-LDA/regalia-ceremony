#!/usr/bin/env bash
# test-escrow-tools.sh — the PIN escrow tools the archive disc carries (scripts/escrow/):
#   - pin_escrow_mac.py: the key on stdin only; KCV and MAC deterministic; select takes the highest
#     escrow whose MAC verifies across git history, so a deleted or MAC-replaced file cannot roll
#     recovery back, and it copies out exactly the verified bytes; the next sequence counts every
#     escrow ever committed;
#   - pin-escrow.sh refuses to run from inside the checkout it writes to (the disc's copy is the
#     producer);
#   - step_archive refuses to stage a disc without both tools.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
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
mkdir -p "$T/repo/escrow/pins-0009.age.mac"; : > "$T/repo/escrow/pins-0009.age.mac/x"; printf 'x' > "$T/repo/escrow/pins-0009.age"
g add -A; g commit -qm "a directory named like a .mac"
[ "$(sel)" = pins-0002.age ] && grep -q "SKIPPED pins-0009.age" "$T/err" && P "a directory where a .mac should be is skipped, not a crash" || F "directory .mac: $(cat "$T/err")"
g rm -rq escrow/pins-0009.age escrow/pins-0009.age.mac; g commit -qm "remove it"
h="$(python3 "$MAC" highest "$T/repo" <<< "$KEY")"
[ "$h" = 2 ] && P "the next sequence counts the deleted VERIFIED 0002, and ignores the forged 0003 and 0009 (highest = 2)" || F "highest $h"
put pins-9999.age squatter "$(printf '00%.0s' {1..16})"; g add -A; g commit -qm "a forged 9999"
h="$(python3 "$MAC" highest "$T/repo" <<< "$KEY")"
[ "$h" = 2 ] && P "a forged pins-9999.age cannot exhaust the sequence (highest still 2)" || F "highest after a forged 9999: $h"
g rm -q escrow/pins-9999.age escrow/pins-9999.age.mac; g commit -qm "remove the squatter"
put pins-0004.age genuine; g add -A; g commit -qm four
printf 'f%.0s' {1..64} > "$T/repo/escrow/pins-0004.age.mac"; g add -A; g commit -qm "replace only the mac"
[ "$(sel)" = pins-0004.age ] && [ "$(cat "$T/out")" = genuine ] && P "replacing only the .mac does not hide the earlier valid pair" || F "after a MAC-only replacement: $(cat "$T/out" 2>/dev/null)"

mkdir -p "$T/io/escrow"; git -C "$T/io" init -q
ln -s /proc/self/mem "$T/io/escrow/pins-0004.age"; printf 'x\n' > "$T/io/escrow/pins-0004.age.mac"
python3 "$MAC" highest "$T/io" <<< "$KEY" >/dev/null 2>&1 && F "an unreadable escrow was skipped as if invalid" \
  || P "an escrow that cannot be read stops sequencing (never treated as a squatter)"

mkdir -p "$T/empty"; git -C "$T/empty" init -q
[ "$(python3 "$MAC" highest "$T/empty" <<< "$KEY" 2>&1)" = 0 ] && P "highest works with no commit and no escrow/ directory" || F "highest fails on an empty repository"

mkdir -p "$T/none/escrow"; git -C "$T/none" init -q
put2(){ printf '%s' "$2" > "$T/none/escrow/$1"; python3 "$MAC" mac "$T/none/escrow/$1" <<< "$(printf '00%.0s' {1..16})" > "$T/none/escrow/$1.mac"; }
put2 pins-0001.age forged; git -C "$T/none" add -A; git -C "$T/none" -c user.name=t -c user.email=t@t commit -qm f
rm -f "$T/o3"; python3 "$MAC" select "$T/none" "$T/o3" <<< "$KEY" >/dev/null 2>&1; rc=$?
[ "$rc" = 3 ] && P "no verified escrow exits 3 (the only status that means: use the payload)" || F "no-escrow exit $rc"
: > "$T/o3"; python3 "$MAC" select "$T/repo" "$T/o3" <<< "$KEY" >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ] && [ "$rc" != 3 ] && P "an output problem is not 'no escrow' (exit $rc: stop, do not fall back)" || F "output problem exit $rc"
python3 "$MAC" select "$T/repo" "$T/o4" <<< "bad" >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ] && [ "$rc" != 3 ] && P "a malformed key is not 'no escrow' (exit $rc)" || F "bad key exit $rc"

hdr "the producer refuses to run from the checkout it writes to"
mkdir -p "$T/repo/tools"; cp "$SCRIPTS/escrow/pin-escrow.sh" "$SCRIPTS/escrow/pin_escrow_mac.py" "$T/repo/tools/"
: > "$T/repo/escrow/breakglass.recipient"; printf 'x' > "$T/repo/escrow/breakglass.recipient"; printf '%s\n' "$k1" > "$T/repo/escrow/escrow-mac.kcv"
out="$(cd "$T/repo" && bash tools/pin-escrow.sh < /dev/null 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "archive disc" <<< "$out" && P "the repository copy refuses and names the disc's copy" || F "rc=$rc: $out"

hdr "the producer, end to end (the disc's copy, a stub age that records what it was given)"
mkdir -p "$T/disc" "$T/stub" "$T/co/escrow"; cp "$SCRIPTS/escrow/pin-escrow.sh" "$SCRIPTS/escrow/pin_escrow_mac.py" "$T/disc/"
cat > "$T/disc/age" <<'STUB'
#!/usr/bin/env bash
# stub: age -R <recipients> -o <out> <in>; "encrypts" by tagging the plaintext (test only)
while [ $# -gt 1 ]; do case "$1" in -R) shift 2;; -o) out="$2"; shift 2;; *) shift;; esac; done
{ printf 'STUB-AGE\n'; cat "$1"; } > "$out"
STUB
chmod +x "$T/disc/age"
printf '#!/bin/sh\necho "the PATH age must never be used" >&2; exit 9\n' > "$T/stub/age"; chmod +x "$T/stub/age"
git -C "$T/co" init -q; printf 'age1pq1stubrecipient\n' > "$T/co/escrow/breakglass.recipient"
printf '%s\n' "$k1" > "$T/co/escrow/escrow-mac.kcv"
fp="$(sha256sum "$T/co/escrow/breakglass.recipient" | cut -c1-16)"
six="7310048261 7310048261 8420159372 8420159372 9531260483 9531260483 90817263 90817263 a1b2c3 a1b2c3 72635445 72635445"
# ...and each KMS host's TPM lockout authorization, twice (regalia-ceremony#92): 20-character
# placeholders built at runtime, so no secret-shaped literal sits in the repository.
ta="$(printf 'QA%.0s' {1..10})"; tb="$(printf 'QB%.0s' {1..10})"; tc="$(printf 'QC%.0s' {1..10})"
# ...and each KMS host's disk recovery key, twice (regalia-kms#77): systemd's format, one group
# repeated eight times, built at runtime too.
rk(){ printf "$1-%.0s" {1..8} | sed 's/-$//'; }
la="$(rk cbdefghi)"; lb="$(rk jklnrtuv)"; lc="$(rk vutrnlkj)"
pins_only="$six"; pins_tpm="$six $ta $ta $tb $tb $tc $tc"; six="$pins_tpm $la $la $lb $lb $lc $lc"
printf 'planted' > "$T/co/escrow/pins-0001.age"   # a squatter on the next name, written without the key
before="$(ls /dev/shm)"
out="$(cd "$T/co" && printf '%s\n' "$fp" "$KEY" $six | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1)"; rc=$?
grep -q "exists but does not verify" <<< "$out" && ! grep -q planted "$T/co/escrow/pins-0001.age" \
  && P "an unverified file on the next name is replaced, and reported" || F "squatter: $out"
[ "$rc" = 0 ] && [ -s "$T/co/escrow/pins-0001.age" ] && [ -s "$T/co/escrow/pins-0001.age.mac" ] \
  && P "six devices, three TPM lockout authorizations and three disk recovery keys escrowed to pins-0001.age + .mac (a 6-character YubiKey PIN accepted)" || F "rc=$rc: $out"
[ "$(grep -cE '^(hsm|yubikey)_[abc]=' "$T/co/escrow/pins-0001.age")" = 6 ] && grep -qx 'yubikey_b=a1b2c3' "$T/co/escrow/pins-0001.age" \
  && P "the plaintext handed to age holds exactly the six device=PIN lines" || F "plaintext: $(cat "$T/co/escrow/pins-0001.age")"
[ "$(grep -cE '^tpm_[abc]=' "$T/co/escrow/pins-0001.age")" = 3 ] && grep -qx "tpm_a=$ta" "$T/co/escrow/pins-0001.age" && grep -qx "tpm_b=$tb" "$T/co/escrow/pins-0001.age" && grep -qx "tpm_c=$tc" "$T/co/escrow/pins-0001.age" \
  && P "and exactly the three tpm_<host>=<lockout authorization> lines" || F "plaintext: $(cat "$T/co/escrow/pins-0001.age")"
shown=0; for v in "$ta" "$tb" "$tc"; do grep -qF "$v" <<< "$out" && shown=1; done
[ "$shown" = 0 ] && P "no TPM lockout authorization (of any of the three hosts) appears in the tool's output" || F "a TPM lockout authorization appeared in the tool's output"
[ "$(grep -cE '^luks_[abc]=' "$T/co/escrow/pins-0001.age")" = 3 ] && grep -qx "luks_a=$la" "$T/co/escrow/pins-0001.age" && grep -qx "luks_b=$lb" "$T/co/escrow/pins-0001.age" && grep -qx "luks_c=$lc" "$T/co/escrow/pins-0001.age" \
  && P "and exactly the three luks_<host>=<disk recovery key> lines, dashes included" || F "plaintext: $(cat "$T/co/escrow/pins-0001.age")"
shown=0; for v in "$la" "$lb" "$lc" cbdefghi jklnrtuv vutrnlkj; do grep -qF "$v" <<< "$out" && shown=1; done
[ "$shown" = 0 ] && P "no disk recovery key (of any of the three hosts) appears in the tool's output" || F "a disk recovery key appeared in the tool's output"
grep -q "6 device PIN(s), 3 TPM lockout authorization(s), 3 disk recovery key(s)" <<< "$out" && P "the confirmation counts six device PINs, three TPM lockout authorizations and three disk recovery keys apart" || F "confirmation: $(tail -4 <<< "$out")"
git -C "$T/co" add -A >/dev/null; git -C "$T/co" -c user.name=t -c user.email=t@t commit -qm e >/dev/null
rm -f "$T/out"; [ "$(python3 "$MAC" select "$T/co" "$T/out" <<< "$KEY" 2>/dev/null)" = pins-0001.age ] \
  && P "its MAC verifies with the key" || F "the producer's MAC does not verify"
[ "$(ls /dev/shm)" = "$before" ] && P "nothing left in /dev/shm" || F "left in /dev/shm: $(comm -13 <(echo "$before") <(ls /dev/shm))"
mkdir -p "$T/disc2"; cp "$T/disc/pin-escrow.sh" "$T/disc/pin_escrow_mac.py" "$T/disc2/"
out="$(cd "$T/co" && printf '%s\n' "$fp" "$KEY" $six | PATH="$T/stub:$PATH" bash "$T/disc2/pin-escrow.sh" 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "no age next to this script" <<< "$out" && P "no checked age beside the tool: refused (PATH's age is never used)" || F "rc=$rc: $out"
run_p(){ (cd "$T/co" && printf '%s\n' "$fp" "$KEY" $six | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1); }
ln -s "$T/never-created" "$T/co/escrow/pins-0002.age.mac"   # a dangling symlink on the next .mac name
out="$(run_p)"; rc=$?
[ "$rc" = 0 ] && [ ! -e "$T/never-created" ] && [ ! -L "$T/co/escrow/pins-0002.age.mac" ] && [ -s "$T/co/escrow/pins-0002.age.mac" ] \
  && P "a dangling symlink on the next name is removed, never written through" || F "symlink: rc=$rc $out"
rm -f "$T/co/escrow/pins-0002.age"*
mkdir -p "$T/co/escrow/pins-0002.age.mac"; : > "$T/co/escrow/pins-0002.age.mac/keep"; printf 'evidence' > "$T/co/escrow/pins-0002.age"
out="$(run_p)"; rc=$?
[ "$rc" != 0 ] && grep -q "is a directory" <<< "$out" && [ -e "$T/co/escrow/pins-0002.age.mac/keep" ] && grep -q evidence "$T/co/escrow/pins-0002.age" \
  && P "a directory on the next name is refused; neither path is touched (the file beside it is kept)" || F "directory: rc=$rc $out"
rm -rf "$T/co/escrow/pins-0002.age.mac" "$T/co/escrow/pins-0002.age"
out1="$(run_p)"; out2="$(run_p)"   # two runs, nothing committed in between
[ -s "$T/co/escrow/pins-0002.age" ] && [ -s "$T/co/escrow/pins-0003.age" ] && ! grep -q "does not verify" <<< "$out2" \
  && P "an escrow written but not committed is counted: the next run writes 0003, never over 0002" || F "uncommitted: $out1 / $out2"
rm -f "$T/co/escrow/pins-0002.age"* "$T/co/escrow/pins-0003.age"*
out="$(cd "$T/co" && printf '%s\n' "$fp" "$KEY" 7310048261 7310048262 | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q differ <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] && P "mismatched entries: refused, nothing written" || F "rc=$rc: $out"
out="$(cd "$T/co" && printf '%s\n' "$fp" "$(printf '11%.0s' {1..16})" | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "does not match" <<< "$out" && P "a key that does not match the KCV: refused" || F "rc=$rc: $out"
# The TPM lockout authorizations are required at every escrow, and have a shape.
escrow_with(){ (cd "$T/co" && printf '%s\n' "$fp" "$KEY" $pins_only "$@" | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1); }
out="$(escrow_with)"; rc=$?
[ "$rc" != 0 ] && grep -q "tpm_a lockout authorization must be 16-32" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] \
  && P "PINs with no TPM lockout authorization: refused, nothing written (the newest escrow must be whole)" || F "rc=$rc: $out"
out="$(escrow_with "$ta" "$ta" "$tb" "$tb" SHORTVALUE SHORTVALUE)"; rc=$?
[ "$rc" != 0 ] && grep -q "tpm_c lockout authorization must be 16-32" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] && P "a 10-character lockout authorization: refused, nothing written" || F "rc=$rc: $out"
out="$(escrow_with "$ta" "$ta" "QBQB QBQB QBQB QBQB" "QBQB QBQB QBQB QBQB" "$tc" "$tc")"; rc=$?
[ "$rc" != 0 ] && grep -q "tpm_b lockout authorization must be 16-32 printable characters with no space" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] \
  && P "a lockout authorization written in groups (with spaces): refused, nothing written" || F "rc=$rc: $out"
out="$(escrow_with "$ta" "$ta" "$tb" "$tb" "$ta" "$ta")"; rc=$?
[ "$rc" != 0 ] && grep -q "tpm_c lockout authorization is the same as tpm_a's" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] \
  && P "one lockout authorization typed for two hosts: refused, nothing written (an escrow with a wrong value for a host is worse than none)" || F "rc=$rc: $out"
out="$(escrow_with "$ta" "$tb")"; rc=$?
[ "$rc" != 0 ] && grep -q "two entries for tpm_a differ" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] && P "two different entries for a lockout authorization: refused" || F "rc=$rc: $out"

# The disk recovery keys are required at every escrow too, and have a shape: systemd's, dashes included.
escrow_luks(){ (cd "$T/co" && printf '%s\n' "$fp" "$KEY" $pins_tpm "$@" | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1); }
out="$(escrow_luks)"; rc=$?
[ "$rc" != 0 ] && grep -q "luks_a disk recovery key must be 8 groups of 8 letters" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] \
  && P "PINs and lockout authorizations with no disk recovery key: refused, nothing written (the newest escrow must be whole)" || F "rc=$rc: $out"
nodash="${lb//-/}"
out="$(escrow_luks "$la" "$la" "$nodash" "$nodash" "$lc" "$lc")"; rc=$?
[ "$rc" != 0 ] && grep -q "luks_b disk recovery key must be 8 groups of 8 letters" <<< "$out" && grep -q "the dashes are part of the key" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] \
  && P "a recovery key typed without its dashes: refused, nothing written (it would be escrowed as a key that opens nothing)" || F "rc=$rc: $out"
# 71 characters of the right alphabet are not enough: the dashes are at fixed places.
for bad in "cbdefghij-klnrtuv-${la:18}" "${la%?}-" "${la%?}"; do
  out="$(escrow_luks "$bad" "$bad" "$lb" "$lb" "$lc" "$lc")"; rc=$?
  [ "$rc" != 0 ] && grep -q "luks_a disk recovery key must be 8 groups of 8 letters" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] \
    && P "a ${#bad}-character key with a dash out of place, a trailing dash or a letter missing: refused" || F "accepted a malformed key (${#bad} characters): rc=$rc"
done
out="$(escrow_luks "$la" "$la" "$lb" "$lb" "${lc^^}" "${lc^^}")"; rc=$?
[ "$rc" != 0 ] && grep -q "luks_c disk recovery key must be" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] && P "a recovery key in capitals: refused, nothing written" || F "rc=$rc: $out"
out="$(escrow_luks "$ta" "$ta" "$lb" "$lb" "$lc" "$lc")"; rc=$?
[ "$rc" != 0 ] && grep -q "luks_a disk recovery key must be" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] && P "a lockout authorization typed where a recovery key belongs: refused" || F "rc=$rc: $out"
out="$(escrow_luks "$la" "$la" "$lb" "$lb" "$la" "$la")"; rc=$?
[ "$rc" != 0 ] && grep -q "luks_c disk recovery key is the same as luks_a's" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] \
  && P "one recovery key typed for two hosts: refused, nothing written" || F "rc=$rc: $out"
out="$(escrow_luks "$la" "$lb")"; rc=$?
[ "$rc" != 0 ] && grep -q "two entries for luks_a differ" <<< "$out" && [ ! -e "$T/co/escrow/pins-0002.age" ] && P "two different entries for a recovery key: refused" || F "rc=$rc: $out"
for bad in "$la" "$nodash" "${lc^^}"; do grep -qF "$bad" <<< "$out" && F "a recovery key was printed while refusing"; done

hdr "--new-recovery-key: a replacement key comes from the disc's tool, never from a person"
RK='^([cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}$'
before="$(ls "$T/co/escrow")"
k1="$(cd "$T/co" && PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" --new-recovery-key 2>"$T/gen.err")"; rc=$?
k2="$(cd "$T/co" && bash "$T/disc/pin-escrow.sh" --new-recovery-key 2>/dev/null)"
[ "$rc" = 0 ] && [[ "$k1" =~ $RK ]] && [[ "$k2" =~ $RK ]] && [ "$k1" != "$k2" ] && P "it prints one key in systemd's format, a different one each time" || F "generator: rc=$rc"
[ "$(ls "$T/co/escrow")" = "$before" ] && P "it writes nothing (no escrow file, no state)" || F "the generator wrote to the checkout"
grep -q "recovery-key.sh --replace" "$T/gen.err" && grep -q "Only then run this tool with no argument to escrow it" "$T/gen.err" && ! grep -qF "$k1" "$T/gen.err" \
  && P "it states the order on stderr: card, --replace and --check at the host, only then the escrow (and the key is on stdout only)" || F "the order is not stated: $(cat "$T/gen.err")"
# What it prints is accepted where a key is typed: by this tool as an escrow entry.
out="$(cd "$T/co" && printf '%s\n' "$fp" "$KEY" $pins_tpm "$k1" "$k1" "$lb" "$lb" "$lc" "$lc" | PATH="$T/stub:$PATH" bash "$T/disc/pin-escrow.sh" 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "a generated key is accepted as an escrow entry" || F "a generated key was refused: $out"
rm -f "$T/co/escrow/pins-0002.age"*
# 256 bits, not 128: a generator that used one half-byte twice would make every pair of letters equal.
# Over 40 keys (1280 byte positions) about 80 pairs are equal by chance; all 1280 would be if it did.
pairs="$(for _ in $(seq 1 40); do bash "$T/disc/pin-escrow.sh" --new-recovery-key 2>/dev/null; done | tr -d '\n-' | fold -w2 | awk 'substr($0,1,1)==substr($0,2,1){n++} END{print n+0}')"
[ "$pairs" -gt 20 ] && [ "$pairs" -lt 200 ] && P "the two letters of a byte are independent ($pairs of 1280 pairs equal; about 80 expected)" || F "the generator's letters are not independent: $pairs of 1280 pairs equal"
# ...and the whole alphabet, with no group repeated inside a key: a generator drawing from 8 of the 16
# letters, or repeating its first group, passes the pair test above.
forty="$(for _ in $(seq 1 40); do bash "$T/disc/pin-escrow.sh" --new-recovery-key 2>/dev/null; done)"
[ "$(tr -d '\n-' <<< "$forty" | fold -w1 | sort -u | wc -l)" = 16 ] && P "all sixteen letters turn up across 40 keys" || F "the generator does not use the whole alphabet"
rep=0; while IFS= read -r k; do [ "$(tr '-' '\n' <<< "$k" | sort -u | wc -l)" = 8 ] || rep=1; done <<< "$forty"
[ "$rep" = 0 ] && [ "$(sort -u <<< "$forty" | wc -l)" = 40 ] && P "no group repeats inside a key, and the 40 keys are 40 different keys" || F "a generated key repeats a group, or two keys are equal"
# THE CURRENT DIRECTORY MUST NOT CHOOSE THE KEY. The tool is run from the top of the repository
# checkout, and write access to that checkout alone must not subvert it: a secrets.py there, or one on
# PYTHONPATH, would otherwise be the module the generator imports.
mkdir -p "$T/planted"; printf 'def token_bytes(n):\n    return b"\\x00" * n\n' > "$T/planted/secrets.py"
planted="$(printf 'cccccccc-%.0s' {1..8})"; planted="${planted%-}"
k="$(cd "$T/planted" && bash "$T/disc/pin-escrow.sh" --new-recovery-key 2>/dev/null)"
[[ "$k" =~ $RK ]] && [ "$k" != "$planted" ] && P "a secrets.py in the working directory does not decide the key" || F "the working directory's secrets.py chose the key: $k"
k="$(PYTHONPATH="$T/planted" bash "$T/disc/pin-escrow.sh" --new-recovery-key 2>/dev/null)"
[[ "$k" =~ $RK ]] && [ "$k" != "$planted" ] && P "nor does one on PYTHONPATH" || F "PYTHONPATH's secrets.py chose the key: $k"
grep -q "python3 -I -c 'import secrets" "$SCRIPTS/ceremony.sh" && P "step 0's generator is isolated the same way (python3 -I)" || F "step 0's generator can import a secrets.py from the working directory"
for bad in "--new-recovery-key extra" "--new-recovery-key=1" "--recovery"; do
  # shellcheck disable=SC2086
  out="$(bash "$T/disc/pin-escrow.sh" $bad 2>/dev/null)"; rc=$?
  [ "$rc" != 0 ] && ! [[ "$(head -1 <<< "$out")" =~ $RK ]] && P "refused: $bad" || F "accepted: $bad"
done
out="$(bash "$T/disc/pin-escrow.sh" --help 2>/dev/null)"; rc=$?
[ "$rc" = 0 ] && grep -q -- "--new-recovery-key" <<< "$out" && grep -q "files test-pins-NNNN.age, which recovery never selects" <<< "$out" && ! grep -q "^set -uo pipefail" <<< "$out" \
  && P "--help prints the whole header, to its last line, and no code" || F "--help is cut short or runs into the code"
# ONE SHAPE, three places that must agree: this tool, step 0, and the KMS host's recovery-key.sh.
[ "$(grep -cF "$RK" "$SCRIPTS/escrow/pin-escrow.sh")" = 1 ] && grep -qF "${RK}" "$SCRIPTS/ceremony.sh" \
  && P "the key's shape is defined once in the escrow tool, and step 0 uses the same expression" || F "the recovery-key shape is written differently in step 0 and the escrow tool"

hdr "the hand-edited (e) step 0 template names the escrow MAC key"
body="$( # shellcheck disable=SC1091
  source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1; declare -f step_set_pins )"
grep -q 'escrow_mac_key (32 hex' <<< "$body" \
  && P "the template lists escrow_mac_key and how to make it" || F "the manual template omits escrow_mac_key"
grep -q 'tpm_{a,b,c}_lockout_auth' <<< "$body" && grep -q 'one wrong attempt blocks it for a day' <<< "$body" \
  && P "the template lists the TPM lockout authorizations and the cost of a wrong attempt" || F "the manual template omits the TPM lockout authorizations"
grep -q 'luks_{a,b,c}_recovery_key' <<< "$body" && grep -q 'with a dash between groups' <<< "$body" && grep -q "It opens that host's disk by itself" <<< "$body" \
  && P "the template lists the disk recovery keys, their format and what one opens" || F "the manual template omits the disk recovery keys"
grep -q 'NEVER invent one by hand' <<< "$body" && grep -q 'pin-escrow.sh --new-recovery-key' <<< "$body" \
  && P "and says how a recovery key is made: by the generator, never by hand" || F "the manual template does not say how to make a recovery key"

hdr "the tier-0 payload carries every KMS host's lockout authorization and disk recovery key"
# The payload template is written from PIN_FIELDS, one "name: value" line each. What recovery reads
# from k shares is that template, so the fields must be in the list and the list must be what is written.
fields="$( # shellcheck disable=SC1091
  source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1; printf '%s' "$PIN_FIELDS" )"
ok=1; for t in a b c; do for f in "tpm_${t}_lockout_auth" "luks_${t}_recovery_key"; do case " $fields " in *" $f "*) ;; *) ok=0;; esac; done; done
[ "$ok" = 1 ] && P "PIN_FIELDS holds tpm_{a,b,c}_lockout_auth and luks_{a,b,c}_recovery_key" || F "a KMS host field is missing from PIN_FIELDS: $fields"
# Not a text match: the function the template calls is RUN, with every field set to a value of its own,
# and each must come out as its "name: value" line. A loop that skipped a field would show here.
lines="$( # shellcheck disable=SC1091
  source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1; for k in $PIN_FIELDS; do printf -v "$k" 'value-of-%s' "$k"; done; payload_pin_lines )"
ok=1; for f in $fields; do grep -qx "$f: value-of-$f" <<< "$lines" || ok=0; done
[ "$ok" = 1 ] && [ "$(wc -l <<< "$lines")" = "$(wc -w <<< "$fields")" ] && grep -q '^\$(payload_pin_lines)$' "$SCRIPTS/ceremony.sh" \
  && P "the payload's credential lines, run with a value per field, hold every field once ($(wc -w <<< "$fields") lines), and the template calls that function" \
  || F "the payload's credential lines do not hold every field: $lines"

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
