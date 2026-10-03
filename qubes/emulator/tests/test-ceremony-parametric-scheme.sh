#!/usr/bin/env bash
# test-ceremony-parametric-scheme.sh — the Shamir scheme is a PARAMETER (owner, 2026-09-29: "maybe a
# user wants 3 of 5 or 3 of 4"). CEREMONY_THRESHOLD / CEREMONY_SHARES (default 4 / 6) drive every split,
# its reconstruct-verify, the share forms and the recovery card; nonsense schemes are refused before
# anything is split. Runs natively (ssss; SLIP-39 cases when shamir_mnemonic imports).
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
command -v ssss-split >/dev/null 2>&1 || { echo "ssss not installed — skipping"; exit 0; }
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
printf '#!/usr/bin/env bash\n[ "$1" = "-o" ] && : > "$2"; exit 0\n' > "$FAKE/qrencode"; chmod +x "$FAKE/qrencode"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE/lp"; chmod +x "$FAKE/lp"
trap 'rm -rf "$FAKE" "${WORK:-}"' EXIT
source "$SCRIPTS/ceremony.sh"
ask(){ return 0; }; pause(){ :; }
# shellcheck disable=SC2034  # PRINTER is read by the sourced ceremony.sh
PRINTER=""
init_work

hdr "valid schemes are accepted; nonsense is refused before anything is split"
for kn in "4 6" "3 5" "3 4" "2 3" "16 16"; do set -- $kn
  CEREMONY_THRESHOLD=$1 CEREMONY_SHARES=$2 check_scheme >/dev/null 2>&1 && P "$1-of-$2 accepted" || F "$1-of-$2 refused"
done
out="$(CEREMONY_THRESHOLD=3 CEREMONY_SHARES=3 check_scheme 2>&1)"; grep -q "losing ONE share loses the secret" <<< "$out" && P "3-of-3 warns: no loss tolerance" || F "k = n not warned"
for kn in "1 6" "7 6" "4 17" "x 6" "4 " "0 0"; do set -- $kn
  out="$(CEREMONY_THRESHOLD="${1:-}" CEREMONY_SHARES="${2:-}" check_scheme 2>&1)" && F "'$kn' accepted" || P "'$kn' refused"
done
printf 'AGE-SECRET-KEY-1EXAMPLE0param0scheme0test' > "$WORK/secret.in"
rm -f "$WORK/shares.txt"; out="$(CEREMONY_THRESHOLD=1 CEREMONY_SHARES=6 step_shamir <<< 'a' 2>&1)"
[ ! -e "$WORK/shares.txt" ] && grep -q "not allowed" <<< "$out" && P "step_shamir refuses 1-of-6 and splits nothing" || F "1-of-6 split: $(tail -3 <<< "$out")"

for kn in "3 5" "3 4" "2 3" "5 8"; do set -- $kn; k=$1; n=$2
  hdr "ssss path, $k-of-$n: n shares, verified; any k recover, k-1 do not"
  rm -f "$WORK/shares.txt"
  out="$(CEREMONY_THRESHOLD=$k CEREMONY_SHARES=$n step_shamir <<< 'a' 2>&1)"
  grep -qi "reconstruct-verify OK" <<< "$out" && P "reconstruct-verified" || F "not verified: $(tail -4 <<< "$out")"
  [ "$(grep -c . "$WORK/shares.txt" 2>/dev/null)" = "$n" ] && P "$n shares" || F "expected $n shares, got $(grep -c . "$WORK/shares.txt" 2>/dev/null)"
  secret="$(cat "$WORK/secret.in")"
  [ "$(sed -n "2,$((k + 1))p" "$WORK/shares.txt" | ssss-combine -t "$k" -q 2>&1)" = "$secret" ] && P "shares 2..$((k + 1)) recover it" || F "$k shares did not recover"
  [ "$(head -n $((k - 1)) "$WORK/shares.txt" | ssss-combine -t $((k - 1)) -q 2>&1)" != "$secret" ] && P "$((k - 1)) shares do not" || F "$((k - 1)) shares recovered the secret"
  grep -q "Shamir share 1 of $n (need $k)" <<< "$out" && P "share labels say 'of $n (need $k)'" || F "labels not parametric: $(grep -o 'share 1 of [0-9]* (need [0-9]*)' <<< "$out" | head -1)"
done

hdr "the printed share form follows the scheme (3-of-5)"
f="$(ls "$WORK"/form-*.ps 2>/dev/null | head -1)"
if [ -n "$f" ]; then
  rm -f "$WORK"/form-*.ps; CEREMONY_THRESHOLD=3 CEREMONY_SHARES=5 step_shamir <<< 'a' >/dev/null 2>&1
  f="$(ls "$WORK"/form-*.ps 2>/dev/null | head -1)"
  grep -q "ONE of 5 shares" "$f" && grep -q "any 3 of them" "$f" && P "form says 'ONE of 5', 'any 3'" || F "form not parametric"
else
  # record_share builds the form only when it runs; build one exactly as it does
  CEREMONY_THRESHOLD=3 CEREMONY_SHARES=5; python3 "$SCRIPTS/share-form.py" --label t --kind chars --count 40 --threshold "$(K)" --total "$(N)" -o "$WORK/f.ps"
  grep -q "ONE of 5 shares" "$WORK/f.ps" && grep -q "any 3 of them" "$WORK/f.ps" && P "form says 'ONE of 5', 'any 3'" || F "form not parametric"
  # shellcheck disable=SC2034  # read by the sourced K/N
  CEREMONY_THRESHOLD=4 CEREMONY_SHARES=6
fi

hdr "the recovery card follows the scheme (3-of-4); an impossible one is refused"
python3 "$SCRIPTS/make-recovery-card.py" -o "$WORK/c.ps" --threshold 3 --shares 4 >/dev/null
grep -q "SCHEME 3-of-4: you need 3 of the 4 cases" "$WORK/c.ps" && grep -q "ssss-combine -t 3" "$WORK/c.ps" && P "card says 3-of-4" || F "card not parametric"
python3 "$SCRIPTS/make-recovery-card.py" -o "$WORK/c2.ps" --threshold 5 --shares 4 >/dev/null 2>&1 && F "5-of-4 card made" || P "5-of-4 card refused"

hdr "SLIP-39 mint path, 3-of-4"
if python3 -c "import shamir_mnemonic" 2>/dev/null; then
  rm -f "$WORK/slip39.txt"
  out="$(CEREMONY_THRESHOLD=3 CEREMONY_SHARES=4 step_shamir <<< 'b' 2>&1)"
  grep -q "every 3-of-4 subset recovers" <<< "$out" && P "minted and verified 3-of-4" || F "mint not verified: $(tail -4 <<< "$out")"
  [ "$(grep -cE '^[a-z]+( [a-z]+){15,}$' "$WORK/slip39.txt" 2>/dev/null)" = 4 ] && P "4 SLIP-39 shares" || F "expected 4 SLIP-39 shares"
else
  echo "  (shamir_mnemonic not importable here: SLIP-39 cases skipped; CI's emulator job has it)"
fi

hdr "no fixed 4 or 6 left in what the operator or a recoverer reads"
msgs="$(grep -v '^\s*#' "$SCRIPTS/ceremony.sh" | grep -E '^\s*(info|warn|err|b|show) ' || true)"
fixed="$(grep -E -i '\b4 of (the )?6\b|\b6 shares\b|\bsix (dkek|new|shares)|into 6 slip|any 4 (of|recover|reconstruct)|lose up to 2\b|4-of-6' <<< "$msgs" || true)"
[ -z "$fixed" ] && P "wizard messages carry no fixed 4/6" || F "fixed numbers in wizard messages: $fixed"
grep -q 'printf .SCHEME: %s-of-%s' "$SCRIPTS/ceremony.sh" && grep -q '"$(K)" "$(N)" "$(K)" "$(N)"' "$SCRIPTS/ceremony.sh" && P "the archive step writes SCHEME.txt from K and N" || F "SCHEME.txt not written from the scheme"
grep -q "payload-qr.py' --split '\$enc' --outdir '\$qrdir' --threshold \$(K) --shares \$(N)" "$SCRIPTS/ceremony.sh" && P "the QR split is given the scheme" || F "the QR split is not given the scheme"
if command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1; then
  age-keygen -o "$WORK/qk" 2>/dev/null; head -c 2000 /dev/urandom | age -r "$(age-keygen -y "$WORK/qk")" -a -o "$WORK/q.age"
  python3 "$SCRIPTS/payload-qr.py" --split "$WORK/q.age" --outdir "$WORK/qr35" --threshold 3 --shares 5 >/dev/null 2>&1
  grep -q "any 3 of the 5 Shamir shares" "$WORK/qr35/INSTRUCTIONS.txt" && P "the QR sheet says 'any 3 of the 5' for 3-of-5" || F "QR instructions not parametric"
fi
docs="$(cat "$SCRIPTS/../recovery/RECOVERY-TECHNICAL.md" "$SCRIPTS/../recovery/RECOVERY-START-HERE.txt" 2>/dev/null)"
grep -qE 'four-shares|any \*\*4\*\*|\*\*4\*\* cases|YOU NEED 4 OF 6|4 of the 6 sealed' <<< "$docs" && F "a recovery document still assumes 4-of-6" || P "recovery documents read k-of-n (SCHEME.txt)"

hdr "no share-count LOGIC fixed at 4 or 6 in the ceremony scripts (the message check above missed these)"
logic="$(cd "$SCRIPTS" && grep -n -E '"?\$\(grep -c[^)]*Share ID[^)]*\)"? *!= *6\b|w\[1-9\]|sh\[1-9\]|feed_shares [^|]* 4\b|--pwd-shares-total 4\b|--pwd-shares-threshold 4\b|ssss-(split|combine) [^|]*-t 4\b|for i in 1 2 3 4 5 6; do$' \
         ceremony.sh prove-ceremony.sh recital-ceremony.sh test-ceremony.sh simulate-ceremony.sh hsm-recovery-drill.sh 2>/dev/null \
         | grep -v -E '^[^:]*:[0-9]+:\s*#' || true)"
[ -z "$logic" ] && P "no fixed share-count logic (guards, globs, imports, stubs)" || F "fixed share-count logic: $logic"
docs2="$(cat "$SCRIPTS/../recovery/RECOVERY-TECHNICAL.md" 2>/dev/null)"
grep -qE -- '--pwd-shares-total 4($|[^0-9])|ssss-combine -t 4\b|the 4 full word-shares' <<< "$docs2" && F "a recovery command still fixes k at 4" || P "recovery commands take k from SCHEME.txt"

hdr "the default is unchanged: 4-of-6"
unset CEREMONY_THRESHOLD CEREMONY_SHARES
( source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1; [ "$(K)-of-$(N)" = 4-of-6 ] ) && P "default 4-of-6" || F "default changed"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
