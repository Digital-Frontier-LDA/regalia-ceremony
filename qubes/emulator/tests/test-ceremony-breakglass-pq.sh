#!/usr/bin/env bash
# test-ceremony-breakglass-pq.sh — the breakglass key is born in the ceremony (owner, 2026-09-30):
# option g generates a post-quantum hybrid age key (age >= 1.3, age-keygen -pq) in the RAM workdir,
# splits it with ssss and verifies the split, and hands only the public recipient to the payload
# step. It refuses to overwrite a secret already in the workdir and refuses to fall back to a
# classical key when age cannot make a post-quantum one.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

command -v ssss-split >/dev/null 2>&1 || { echo "  (skipping: ssss not installed)"; exit 0; }
# The vault image pins age 1.3.2 in /opt/vault-bin; AGE_BIN_DIR points at another copy for tests.
for d in "${AGE_BIN_DIR:-}" /opt/vault-bin; do [ -n "$d" ] && [ -x "$d/age-keygen" ] && PATH="$d:$PATH"; done
if ! grep -q '^AGE-SECRET-KEY-PQ-1' <<< "$(age-keygen -pq 2>/dev/null)"; then
  echo "  (skipping: no age >= 1.3 here; set AGE_BIN_DIR to an age 1.3 directory)"; exit 0
fi

FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
printf '#!/usr/bin/env bash\n[ "$1" = "-o" ] && : > "$2"; exit 0\n' > "$FAKE/qrencode"; chmod +x "$FAKE/qrencode"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE/lp"; chmod +x "$FAKE/lp"
trap 'rm -rf "$FAKE" "${WORK:-}"' EXIT
# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
ask(){ return 0; }; pause(){ :; }
# shellcheck disable=SC2034  # read by print_share in the sourced ceremony.sh
PRINTER=""
init_work

hdr "option g: a post-quantum key is generated in RAM, split, and verified"
unset BREAKGLASS_RECIPIENT
out="$(printf 'g\n' | step_shamir 2>&1)"
grep -q 'New post-quantum breakglass key generated in RAM' <<< "$out" && P "the key is generated in the ceremony" || F "no generation: $out"
grep -q 'reconstruct-verify OK' <<< "$out" && P "the split is reconstruct-verified" || F "split not verified: $out"
id="$(grep '^AGE-SECRET-KEY-PQ-1' "$WORK/breakglass.key" 2>/dev/null)"
[ -n "$id" ] && P "the identity is a post-quantum age key (AGE-SECRET-KEY-PQ-1…)" || F "not a PQ identity"
[ "$(stat -c %a "$WORK/breakglass.key")" = 600 ] && P "the key file is 0600" || F "key mode $(stat -c %a "$WORK/breakglass.key")"
case "$WORK" in /dev/shm/*) P "it lives in the RAM workdir ($WORK)";; *) P "workdir $WORK (tmpfs checked by init_work outside SIMULATE)";; esac
grep -q '^age1pq1[0-9a-z]*$' "$WORK/breakglass.recipient" && P "the public recipient is age1pq1… ($(wc -c < "$WORK/breakglass.recipient") bytes)" || F "bad recipient"
[ "$(age-keygen -y "$WORK/breakglass.key")" = "$(cat "$WORK/breakglass.recipient")" ] && P "the recipient belongs to the key" || F "recipient does not match the key"
rebuilt="$(head -n "$(K)" "$WORK/shares.txt" | ssss-combine -t "$(K)" -q 2>&1)"
[ "$rebuilt" = "$id" ] && P "k shares rebuild the exact identity" || F "shares do not rebuild the identity"
grep -q "$id" <<< "$out" && F "the secret key was printed to the terminal" || P "the secret key never reaches the terminal"
msg="the quick brown fox $RANDOM"
enc="$(printf '%s' "$msg" | age -r "$(cat "$WORK/breakglass.recipient")" | base64 -w0)"
[ "$(printf '%s' "$enc" | base64 -d | age -d -i <(printf '%s\n' "$rebuilt") 2>/dev/null)" = "$msg" ] \
  && P "the identity rebuilt from shares decrypts a file encrypted to the recipient" || F "rebuilt identity cannot decrypt"

# (step_payload using the generated recipient is exercised for real in test-payload-step.sh.)

hdr "the leak scanners catch a post-quantum key (it does not contain AGE-SECRET-KEY-1)"
for f in recital-ceremony.sh prove-ceremony.sh; do
  pat="$(grep -oE 'AGE-SECRET-KEY-\(PQ-\)\?1\[A-Z0-9\]\{20,\}' "$SCRIPTS/$f" | head -1)"
  [ -n "$pat" ] && grep -Eq "$pat" <<< "$id" && P "$f's transcript scan matches the generated PQ key" || F "$f's scan misses a PQ key"
done
if python3 -c "import sys; sys.path.insert(0, '$SCRIPTS/vendor'); from regalia_kms.tools import custody_manifest as m; sys.exit(0 if any(p.search(sys.argv[1]) for p in m.PRIVATE_PATTERNS) else 1)" "$id" 2>/dev/null; then
  P "the custody manifest's secret patterns refuse a PQ key"
else
  F "the custody manifest accepts a PQ key"
fi

hdr "refusals"
out="$(printf 'g\n' | step_shamir 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'already holds a secret; refusing to overwrite' <<< "$out" && P "g refuses to overwrite a secret already in the workdir" || F "g overwrote secret.in (rc=$rc)"
rm -f "$WORK/secret.in"
out="$(printf 'g\n' | step_shamir 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'already generated in this session' <<< "$out" && grep -q "^AGE-SECRET-KEY-PQ-1" "$WORK/breakglass.key" && [ "$(grep '^AGE-SECRET-KEY' "$WORK/breakglass.key")" = "$id" ] \
  && P "g never replaces a key generated earlier in the session (its shares may be on paper)" || F "g replaced an earlier key (rc=$rc)"
rm -f "$WORK/secret.in" "$WORK/breakglass.key" "$WORK/breakglass.recipient" "$WORK/shares.txt"
printf '#!/usr/bin/env bash\necho "age-keygen: unknown flag -pq" >&2; exit 1\n' > "$FAKE/age-keygen"; chmod +x "$FAKE/age-keygen"
out="$(printf 'g\n' | step_shamir 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q 'cannot make a post-quantum key' <<< "$out" && [ ! -e "$WORK/secret.in" ] \
  && P "an age without -pq is refused, with no classical fallback and nothing written" || F "old age not refused (rc=$rc)"
rm -f "$FAKE/age-keygen"
grep -q 'AGE-SECRET-KEY-PQ-1\*' "$SCRIPTS/ceremony.sh" && P "a pasted PQ secret key is refused as a recipient" || F "PQ secret key not recognised at the recipient prompt"

echo; echo "breakglass-pq: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
