#!/usr/bin/env bash
# test-hsm-domain.sh — hsm-domain.sh: the revocation key's DKEK domain (regalia-ceremony#111). The domain's
# share is made on its first card, loaded onto both cards (equal key check values), proven disjoint from the
# other domains', and backed up to the break-glass recipient with age, the plaintext then removed.
#
# Runs natively (bash, python3; age when installed). pkcs11-tool, opensc-tool, sc-hsm-tool and the device
# certificate reader are stubbed with a card model: each card is a directory holding its DKEK state; a card is
# ATTACHED when it is linked into $ATTACHED. The model's share binds its DKEK to the password's SHA-256, and a
# wrong password is refused, as OpenSC refuses it; STUB_DECRYPTS_WRONG=1 models #460's other outcome, an import
# that "succeeds" with another key. Every argv is logged, so a password on a command line is caught.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
set -uo pipefail
TESTS="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$TESTS/../../scripts}"
TOOL="$SCRIPTS/hsm-domain.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
FAKE="$ROOT/bin"; CARDS="$ROOT/cards"; ATTACHED="$ROOT/attached"; mkdir -p "$FAKE" "$CARDS" "$ATTACHED"
export CARDS ATTACHED ARGV_LOG="$ROOT/argv.log" CEREMONY_PKCS11_MODULE="$ROOT/opensc-pkcs11.so" CEREMONY_ALLOW_NONTMPFS=1
: > "$CEREMONY_PKCS11_MODULE"; : > "$ARGV_LOG"
export PATH="$FAKE:$PATH"

cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
printf 'pkcs11-tool %s\n' "$*" >> "$ARGV_LOG"
case " $* " in *" --list-token-slots "*) ;; *) echo "TRIPWIRE pkcs11-tool $*" >&2; exit 99;; esac
echo "Available slots:"; i=0
for c in "$ATTACHED"/*; do [ -e "$c" ] || continue
  printf 'Slot %d (0x%x): Nitrokey HSM (%s) 00 00\n  token label        : SmartCard-HSM (UserPIN)\n  serial num         : %s\n' $((i*4)) $((i*4)) "$(basename "$c")" "$(basename "$c")"
  i=$((i+1)); done
STUB
cat > "$FAKE/opensc-tool" <<'STUB'
#!/usr/bin/env bash
printf 'opensc-tool %s\n' "$*" >> "$ARGV_LOG"
[ "$*" = "--list-readers" ] || { echo "TRIPWIRE opensc-tool $*" >&2; exit 99; }
echo "Nr.  Card  Features  Name"; echo "0    No              Lenovo Integrated Smart Card Reader"
i=1; for c in "$ATTACHED"/*; do [ -e "$c" ] && { echo "$i    Yes             Nitrokey HSM ($(basename "$c")) 00 00"; i=$((i+1)); }; done
STUB
cat > "$FAKE/devaut-read.sh" <<'STUB'
#!/usr/bin/env bash
r="" s=""; while [ $# -gt 0 ]; do case "$1" in --reader) r="$2"; shift 2;; --expect-serial) s="$2"; shift 2;; *) shift;; esac; done
i=1; for c in "$ATTACHED"/*; do [ -e "$c" ] || continue; if [ "$i" = "$r" ]; then
  [ "$(basename "$c")" = "$s" ] || exit 2; printf 'DEVAUT_HEX=00\n'; exit 0; fi; i=$((i+1)); done
exit 2
STUB
cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
printf 'sc-hsm-tool %s\n' "$*" >> "$ARGV_LOG"
reader="" create="" import="" password=""
while [ $# -gt 0 ]; do case "$1" in --reader) reader="$2"; shift 2;; --create-dkek-share) create="$2"; shift 2;;
  --import-dkek-share) import="$2"; shift 2;; --password) password="$2"; shift 2;; *) echo "sc-hsm-tool [STUB]: unsupported $1" >&2; exit 2;; esac; done
mapfile -t cards < <(for c in "$ATTACHED"/*; do [ -e "$c" ] && basename "$c"; done)
case "$reader" in [1-9]) ;; *) echo "no --reader: a guess" >&2; exit 9;; esac
[ "$reader" -le "${#cards[@]}" ] || { echo "Failed to connect to card" >&2; exit 0; }   # the real tool: no file, and exit 0
C="$CARDS/${cards[$((reader - 1))]}"
pw(){ case "$password" in env:?*) ;; *) echo "A PASSWORD THAT IS NOT env:NAME [STUB]" >&2; exit 3;; esac; local v="${password#env:}"; printf '%s' "${!v-}"; }
kcv(){ printf '%s' "$1" | sha256sum | cut -c1-16 | tr 'a-f' 'A-F'; }
if [ -n "$create" ]; then
  [ "${STUB_CREATE_NOTHING:-0}" = 1 ] && exit 0
  printf 'pwhash %s\ndkek %s\n' "$(pw | sha256sum | cut -c1-64)" "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')" > "$create"; exit 0
fi
if [ -n "$import" ]; then
  [ "$(cat "$C/state")" = pending ] || { echo "DKEK already complete" >&2; exit 1; }
  [ "$(pw | sha256sum | cut -c1-64)" = "$(sed -n 's/^pwhash //p' "$import")" ] || { echo "Error decrypting DKEK share. Password correct ?" >&2; exit 1; }
  dkek="$(sed -n 's/^dkek //p' "$import")"; [ "${STUB_DECRYPTS_WRONG:-0}" = 1 ] && dkek="other-$dkek"
  printf '%s' "$dkek" > "$C/dkek"; echo complete > "$C/state"; exit 0
fi
printf 'Version              : 4.1\nSO-PIN tries left    : 15\nUser PIN tries left  : 3\n'
case "$(cat "$C/state")" in
  pending) printf 'DKEK shares          : 1\nDKEK import pending, 1 share(s) still missing\n';;
  complete) printf 'DKEK shares          : 1\nDKEK key check value : %s\n' "$(kcv "$(cat "$C/dkek")")";;
esac
STUB
chmod +x "$FAKE"/*
export HSM_DEVAUT_READ_SH="$FAKE/devaut-read.sh"

card(){ mkdir -p "$CARDS/$1"; echo "$2" > "$CARDS/$1/state"; }      # card SERIAL none|pending|complete
attach(){ rm -f "$ATTACHED"/*; local c; for c in "$@"; do ln -s "$CARDS/$c" "$ATTACHED/$c"; done; }
run(){ bash "$TOOL" "$@" 2>&1; }
D="$ROOT/work"; mkdir -p "$D"

hdr "1  create on the domain's first card, load both cards: equal key check values"
card DENK0600001 pending; card DENK0600002 pending
attach DENK0600001
out="$(run create --domain revocation --serial DENK0600001 --dir "$D")"; rc=$?
[ "$rc" = 0 ] && grep -q "^CREATED revocation share $D/revocation.pbe on card DENK0600001" <<< "$out" && [ -s "$D/revocation.pbe" ] && [ -s "$D/revocation.pw" ] \
  && P "the share and its password are made, on the card" || F "create (rc=$rc): $out"
[ "$(stat -c %a "$D/revocation.pbe")" = 600 ] && [ "$(stat -c %a "$D/revocation.pw")" = 600 ] && P "both are 0600" || F "modes: $(stat -c %a "$D/revocation.pbe" "$D/revocation.pw")"
grep -qF -- "$(cat "$D/revocation.pw")" "$ARGV_LOG" && F "the password was on a command line: $(grep -F -- "$(cat "$D/revocation.pw")" "$ARGV_LOG")" \
  || P "the password never appears on any command line"
[ "$(wc -c < "$D/revocation.pw")" = 64 ] && grep -qxE '[0-9a-f]{64}' "$D/revocation.pw" && P "the password is 64 hex digits (256 bits)" || F "password: $(wc -c < "$D/revocation.pw") bytes"
out="$(run create --domain revocation --serial DENK0600001 --dir "$D")"
[ $? = 1 ] && grep -q "revocation.pbe already exists: nothing is overwritten" <<< "$out" && P "a second create does not overwrite the share" || F "re-create: $out"
out="$(run load --domain revocation --serial DENK0600001 --dir "$D" --first)"; rc=$?
KCV_ROOT="$(sed -n 's/^DOMAIN revocation card DENK0600001 KCV \([0-9A-F]\{16\}\)$/\1/p' <<< "$out")"
[ "$rc" = 0 ] && [ -n "$KCV_ROOT" ] && P "card A loaded: DOMAIN revocation card DENK0600001 KCV $KCV_ROOT" || F "load A (rc=$rc): $out"
attach DENK0600002
out="$(run load --domain revocation --serial DENK0600002 --dir "$D")"
[ $? = 1 ] && grep -q -- "--first (the domain's first card) or --expect-kcv KCV" <<< "$out" && [ "$(cat "$CARDS/DENK0600002/state")" = pending ] \
  && P "a card loaded with neither --first nor --expect-kcv: refused before the import" || F "neither: $out"
out="$(run load --domain revocation --serial DENK0600002 --dir "$D" --first --expect-kcv "$KCV_ROOT")"
[ $? = 1 ] && grep -q -- "--first and --expect-kcv" <<< "$out" && P "--first with --expect-kcv: refused" || F "both: $out"
out="$(run load --domain revocation --serial DENK0600002 --dir "$D" --expect-kcv "$KCV_ROOT")"; rc=$?
[ "$rc" = 0 ] && grep -q "^DOMAIN revocation card DENK0600002 KCV $KCV_ROOT$" <<< "$out" && P "card B loaded with the same key check value" || F "load B (rc=$rc): $out"
out="$(run load --domain revocation --serial DENK0600002 --dir "$D" --expect-kcv "$KCV_ROOT")"; rc=$?
[ "$rc" = 0 ] && grep -q "KCV $KCV_ROOT (already loaded)" <<< "$out" && P "a re-run on a loaded card with its own KCV: reported, not imported again" || F "re-run (rc=$rc): $out"
grep -qF -- "$(cat "$D/revocation.pw")" "$ARGV_LOG" && F "the password reached a command line during load" || P "load passes the password through the environment only"

hdr "2  refusals"
out="$(run load --domain revocation --serial DENK0600002 --dir "$D" --first)"
[ $? = 1 ] && grep -q "already holds DKEK $KCV_ROOT: nothing is imported over a complete DKEK" <<< "$out" \
  && P "a complete card without --expect-kcv: refused, not imported over" || F "complete, no expect: $out"
out="$(run load --domain revocation --serial DENK0600002 --dir "$D" --expect-kcv 0011223344556677)"
[ $? = 1 ] && grep -q "already holds DKEK $KCV_ROOT, not 0011223344556677" <<< "$out" && P "a complete card of another domain: refused" || F "other domain: $out"
card DENK0600003 none; attach DENK0600003
out="$(run load --domain revocation --serial DENK0600003 --dir "$D" --expect-kcv "$KCV_ROOT")"
[ $? = 1 ] && grep -q "no DKEK share configured: initialise it with hsm-init-hardened.sh --dkek-shares 1" <<< "$out" && P "a card with no DKEK share configured: refused" || F "none: $out"
card DENK0600004 pending; attach DENK0600004
out="$(STUB_DECRYPTS_WRONG=1 run load --domain revocation --serial DENK0600004 --dir "$D" --expect-kcv "$KCV_ROOT")"
[ $? = 1 ] && grep -q "is NOT in domain revocation" <<< "$out" && P "an import that 'succeeds' with another key (#460): refused by the key check value" || F "#460: $out"
card DENK0600005 pending; attach DENK0600005 DENK0600002
out="$(run load --domain revocation --serial DENK0600005 --dir "$D" --expect-kcv "$KCV_ROOT")"
[ $? = 1 ] && grep -q "2 tokens are attached; attach ONLY card DENK0600005" <<< "$out" && [ "$(cat "$CARDS/DENK0600005/state")" = pending ] \
  && P "two cards attached: refused, nothing imported" || F "two cards: $out"
attach DENK0600002
out="$(run load --domain revocation --serial DENK0600005 --dir "$D" --expect-kcv "$KCV_ROOT")"
[ $? = 1 ] && grep -q "serial DENK0600005 matches 0 tokens" <<< "$out" && P "another card than --serial attached: refused" || F "wrong card: $out"
attach DENK0600005
D2="$ROOT/work2"; mkdir -p "$D2"
out="$(STUB_CREATE_NOTHING=1 run create --domain revocation --serial DENK0600005 --dir "$D2")"
[ $? = 1 ] && grep -q "wrote no DKEK share" <<< "$out" && [ ! -e "$D2/revocation.pw" ] && P "a create that writes no file: refused, and its password removed" || F "no file: $out"
for bad in "--domain other" "--domain root" "--domain signing" "--serial a/b" "--expect-kcv 12AB" "--password x" "--expect-kcv 0000000000000000"; do
  # shellcheck disable=SC2086  # two words on purpose
  out="$(run load --domain revocation --serial DENK0600005 --dir "$D" $bad)"
  [ $? = 1 ] && grep -q REFUSED <<< "$out" && P "bad argument $bad: refused" || F "$bad: $out"
done
if [ "$(stat -f -c %T "$D")" != tmpfs ] && [ "$(stat -f -c %T "$D")" != ramfs ]; then
  out="$(CEREMONY_ALLOW_NONTMPFS=0 run create --domain revocation --serial DENK0600005 --dir "$D2")"
  [ $? = 1 ] && grep -q "not a RAM file system" <<< "$out" && P "a work directory on a disk: refused" || F "non-tmpfs: $out"
else echo "  SKIP the disk-directory refusal ($D is on $(stat -f -c %T "$D"))"; fi

hdr "3  disjoint"
K1=ABCDEF0123456789 K2=2222222222222222 K3=3333333333333333
out="$(run disjoint --kcv revocation=$K1 --kcv hosts-ceremony=$K2 --kcv host-a=$K3)"; rc=$?
[ "$rc" = 0 ] && [ "$(grep -c '^DISJOINT ' <<< "$out")" = 3 ] && P "three different key check values: disjoint, each printed" || F "disjoint (rc=$rc): $out"
out="$(run disjoint --kcv revocation=$K1 --kcv hosts-ceremony=$K2 --kcv host-a=$K1)"
[ $? = 1 ] && grep -q "DOMAINS NOT DISJOINT: host-a and revocation have the same DKEK key check value $K1" <<< "$out" && P "two equal values: refused, both named" || F "equal: $out"
out="$(run disjoint --kcv revocation=${K1,,} --kcv hosts-ceremony=$K2)"
[ $? = 0 ] && grep -q "^DISJOINT revocation $K1$" <<< "$out" && P "a lower-case value is read as the card prints it (upper case)" || F "lower case: $out"
out="$(run disjoint --kcv revocation=$K1 --kcv host-a=${K1,,})"
[ $? = 1 ] && grep -q "NOT DISJOINT" <<< "$out" && P "the same value in lower case is the same value: refused" || F "lowercase dup: $out"
out="$(run disjoint --kcv revocation=$K1)"
[ $? = 1 ] && grep -q "a comparison with nothing proves nothing" <<< "$out" && P "no other domain given: refused" || F "no others: $out"
out="$(run disjoint --kcv revocation=$K1 --kcv host-a=$K2 --hosts-not-yet)"
[ $? = 1 ] && grep -q "unknown argument: --hosts-not-yet" <<< "$out" && P "there is no way to skip the comparison (--hosts-not-yet is gone)" || F "hosts-not-yet: $out"
for bad in "revocation=0000000000000000" "revocation=12AB" "revocation" "Revocation=$K1"; do
  out="$(run disjoint --kcv "$bad" --kcv host=$K2)"
  [ $? = 1 ] && grep -q REFUSED <<< "$out" && P "--kcv $bad: refused" || F "--kcv $bad: $out"
done
out="$(run disjoint --kcv host-a=$K2 --kcv host-b=$K3)"
[ $? = 1 ] && grep -q -- "--kcv revocation=… is required" <<< "$out" && P "revocation missing: refused" || F "revocation missing: $out"

hdr "4  backup: one age file to the break-glass recipient; the plaintext removed"
if command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1; then
  ( umask 077; age-keygen -pq -o "$ROOT/bg.key" 2>/dev/null || age-keygen -o "$ROOT/bg.key" 2>/dev/null )
  age-keygen -y "$ROOT/bg.key" > "$ROOT/bg.recipient"
  pw="$(cat "$D/revocation.pw")"; share="$(base64 -w0 < "$D/revocation.pbe")"
  out="$(run backup --domain revocation --dir "$D" --kcv "$KCV_ROOT" --recipient-file "$ROOT/bg.recipient")"; rc=$?
  [ "$rc" = 0 ] && grep -q "^BACKUP revocation $D/dkek-revocation.age sha256 $(sha256sum "$D/dkek-revocation.age" 2>/dev/null | cut -d' ' -f1)$" <<< "$out" \
    && P "backed up ($(head -c 4 "$ROOT/bg.recipient")… recipient), its SHA-256 printed" || F "backup (rc=$rc): $out"
  [ ! -e "$D/revocation.pbe" ] && [ ! -e "$D/revocation.pw" ] && P "the plaintext share and password are gone" || F "plaintext left: $(ls "$D")"
  plain="$(age -d -i "$ROOT/bg.key" "$D/dkek-revocation.age" 2>/dev/null)"
  [ "$(sed -n 1p <<< "$plain")" = regalia.dkek-share/v1 ] && grep -qx "domain revocation" <<< "$plain" && grep -qx "kcv $KCV_ROOT" <<< "$plain" \
    && grep -qxF "password $pw" <<< "$plain" && grep -qxF "share $share" <<< "$plain" \
    && P "the break-glass key opens it: the domain, its KCV, the password and the share" || F "decrypted: $(sed -n 1,3p <<< "$plain")"
  grep -qaF -- "$pw" "$D/dkek-revocation.age" && F "the password is in the file in the clear" || P "the file does not hold the password in the clear"
  out="$(run backup --domain revocation --dir "$D" --kcv "$KCV_ROOT" --recipient-file "$ROOT/bg.recipient")"
  [ $? = 1 ] && grep -q "revocation.pbe is missing" <<< "$out" && P "a second backup: refused (the share is gone)" || F "second backup: $out"
  attach DENK0600005; card DENK0600005 pending
  rm -rf "$D2"; mkdir -p "$D2"; run create --domain revocation --serial DENK0600005 --dir "$D2" >/dev/null
  echo "not a recipient" > "$ROOT/bad.recipient"
  out="$(run backup --domain revocation --dir "$D2" --kcv "$K2" --recipient-file "$ROOT/bad.recipient")"
  [ $? = 1 ] && grep -q "does not hold an age recipient" <<< "$out" && [ -e "$D2/revocation.pbe" ] && P "no recipient: refused, the share kept" || F "bad recipient: $out"
  out="$(run backup --domain revocation --dir "$D2" --kcv 12 --recipient-file "$ROOT/bg.recipient")"
  [ $? = 1 ] && grep -q -- "--kcv is the domain's key check value" <<< "$out" && P "a malformed --kcv: refused" || F "bad kcv: $out"
else
  echo "  SKIP backup: age is not installed here (the emulator job installs age 1.3.2)"
fi

hdr "5  one definition of the card rules"
[ "$(grep -rlE '^find_reader\(\)' "$SCRIPTS" | wc -l)" = 1 ] && grep -qE '^find_reader\(\)' "$SCRIPTS/hsm-card.sh" \
  && P "find_reader is defined once, in hsm-card.sh" || F "find_reader is defined in: $(grep -rlE '^find_reader\(\)' "$SCRIPTS")"
grep -q 'hsm-card.sh' "$SCRIPTS/hsm-signing-key.sh" && grep -q 'hsm-card.sh' "$SCRIPTS/hsm-domain.sh" \
  && P "hsm-signing-key.sh and hsm-domain.sh both source it" || F "a script does not source hsm-card.sh"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
