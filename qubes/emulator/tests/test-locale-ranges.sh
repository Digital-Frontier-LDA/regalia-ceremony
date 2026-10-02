#!/usr/bin/env bash
# test-locale-ranges.sh — a bracket range in a validator means ASCII, whatever the operator's locale.
#
# In a UTF-8 locale bash matches a range by the locale's collation: [0-9] also takes full-width and
# Arabic-Indic digits, [a-z0-9] takes accented letters, and a negated range such as *[!0-9]* stops
# catching them (measured: bash 5.2, glibc 2.41, en_US.UTF-8). Scripts here accepted a release tag
# with an accented letter, a PKCS#11 object id and a YubiKey serial in full-width digits. Every
# script that validates input with a range now pins the collation; this runs two of them under
# en_US.UTF-8 and checks the pin is in all of them.
#
# No hardware: the token tools and qvm-* are replaced by stubs that say they were reached and fail.
# REQUIRE_UTF8_LOCALE=1 (CI) turns a missing en_US.UTF-8 into a failure instead of a skip.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$ROOT/qubes/scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
LOC=en_US.UTF-8
# Not `locale -a | grep -q`: under pipefail a grep that stops reading early can fail the producer.
locales="$(locale -a 2>/dev/null)"
if ! grep -qiE '^en_US\.utf-?8$' <<< "$locales"; then
  if [ "${REQUIRE_UTF8_LOCALE:-0}" = 1 ]; then echo "test-locale-ranges: $LOC is not installed and REQUIRE_UTF8_LOCALE=1"; exit 1; fi
  echo "test-locale-ranges: SKIP: $LOC is not installed (locale-gen $LOC); REQUIRE_UTF8_LOCALE=1 makes this a failure"; exit 0
fi
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir "$T/stub"
for t in pkcs11-tool opensc-tool sc-hsm-tool ykman pcsc_scan opensc-explorer qvm-run qvm-create qvm-kill qvm-remove; do
  printf '#!/bin/sh\necho "STUB: %s was reached" >&2\nexit 97\n' "$t" > "$T/stub/$t"; chmod +x "$T/stub/$t"; done
: > "$T/module.so"
# last <locale> <script> [args]: the last line the script says, under that locale.
last(){ local loc="$1"; shift; env LC_ALL="$loc" LANG="$loc" PATH="$T/stub:$PATH" WORK="$T" bash "$@" 2>&1 | tail -1; }
# refused <what> <text the validator says> <script> [args]: under en_US.UTF-8 the validator itself refuses.
refused(){ local what="$1" want="$2" out; shift 2; out="$(last "$LOC" "$@")"
  grep -qF -- "$want" <<< "$out" && P "$what: refused by its validator" || F "$what: not refused by its validator; the script went on to: $out"; }

hdr "0  the instrument: this locale does widen a range, and the pin undoes it"
widened="$(LC_ALL=$LOC bash -c '[[ "７" =~ ^[0-9]$ ]] && echo yes || echo no')"
[ "$widened" = yes ] && P "under $LOC, bash's [0-9] takes a full-width digit" || F "under $LOC [0-9] does not take a full-width digit: the checks below would prove nothing"
pinned="$(LC_ALL=$LOC bash -c 'if [ -n "${LC_ALL:-}" ]; then export LANG="$LC_ALL" LC_CTYPE="$LC_ALL"; unset LC_ALL; fi; export LC_COLLATE=C
  s="héllo"; [[ "７" =~ ^[0-9]$ ]] && echo "digit-yes ${#s}" || echo "digit-no ${#s}"')"
[ "$pinned" = "digit-no 5" ] && P "with the collation pinned it does not, and a 5-character string with a two-byte letter is still 5 long" || F "the pin: got '$pinned', want 'digit-no 5'"

hdr "1  dom0/vault-tools-update.sh: the release tag and the sha256"
V="$ROOT/qubes/dom0/vault-tools-update.sh"; HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
refused "a tag with an accented letter" "has characters a release tag never has" "$V" 'v1.0é' "$HEX"
refused "a sha256 in full-width digits" "the sha256 must be 16 to 64 hex characters" "$V" v1.0 '０１２３４５６７８９０１２３４５６７'
out="$(last "$LOC" "$V" v1.0 "$HEX")"
grep -qE 'release tag never has|must be 16 to 64' <<< "$out" && F "control: a plain tag and sha256 were refused: $out" || P "control: a plain ASCII tag and sha256 pass both checks"

hdr "2  operation-proof.sh: the object id and the serial"
O="$SCRIPTS/operation-proof.sh"; base=(--operation sign --out "$T/out" --module "$T/module.so")
refused "a PKCS#11 object id in full-width digits" "is not a PKCS#11 hex id" "$O" "${base[@]}" --backend nitrokey-pkcs11 --serial DENK0404144 --object-id '０１'
refused "a YubiKey serial in full-width digits" "is not a serial" "$O" "${base[@]}" --backend yubikey-piv --serial '３６３４５４７１' --object-id 9a
refused "a serial with an accented letter" "is not a serial" "$O" "${base[@]}" --backend nitrokey-pkcs11 --serial 'DENKé404144' --object-id 01
out="$(last "$LOC" "$O" "${base[@]}" --backend nitrokey-pkcs11 --serial DENK0404144 --object-id 01)"
grep -qE 'is not a serial|is not a PKCS#11 hex id' <<< "$out" && F "control: plain ASCII values were refused: $out" || P "control: a plain ASCII serial and object id pass both checks"

hdr "3  every script that validates input with a range pins the collation, before its first check"
for s in qubes/scripts/ceremony.sh qubes/scripts/go-nogo.sh qubes/scripts/hsm-fleet-drill.sh qubes/scripts/hsm-init-hardened.sh \
         qubes/scripts/hsm-recovery-drill.sh qubes/scripts/hsm-staging-e2e.sh qubes/scripts/nitrokey-acceptance.sh \
         qubes/scripts/operation-proof.sh qubes/scripts/hsm-import-key.sh qubes/scripts/hsm-unwrap-key.sh \
         qubes/dom0/vault-tools-update.sh hsm-host-role/files/commission-card.sh tools/hsm-dkek-refusal-probe.sh; do
  f="$ROOT/$s"
  pin="$(grep -n '^export LC_COLLATE=C$' "$f" | head -1 | cut -d: -f1)"
  move="$(grep -n '^if \[ -n "${LC_ALL:-}" \]; then export LANG="$LC_ALL" LC_CTYPE="$LC_ALL"; unset LC_ALL; fi$' "$f" | head -1 | cut -d: -f1)"
  # the first pattern match or range case in code (comment lines aside)
  first="$(grep -nE '=~|case .* in .*\[' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 | cut -d: -f1)"
  if [ -n "$pin" ] && [ -n "$move" ] && [ "$move" -lt "$pin" ] && { [ -z "$first" ] || [ "$pin" -lt "$first" ]; }; then
    P "$s (line $pin)"
  else F "$s: collation pin at line '${pin:-none}', LC_ALL moved at '${move:-none}', first pattern at '${first:-none}'"; fi
done

echo; echo "test-locale-ranges: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
