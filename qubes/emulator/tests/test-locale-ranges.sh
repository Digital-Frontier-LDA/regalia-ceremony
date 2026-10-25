#!/usr/bin/env bash
# test-locale-ranges.sh — a bracket range in a validator means ASCII, whatever the operator's locale.
#
# In a UTF-8 locale bash matches a range by the locale's collation: [0-9] also takes full-width and
# Arabic-Indic digits, [a-z0-9] takes accented letters, and a negated range such as *[!0-9]* stops
# catching them (measured: bash 5.2, glibc 2.41, en_US.UTF-8). Scripts here accepted a release tag
# with an accented letter, a PKCS#11 object id and a YubiKey serial in full-width digits, and forty
# full-width digits as a "commit id" for the file that decides what root installs. Every script whose
# ranges check what a caller supplies now pins the collation; this runs several of them under
# en_US.UTF-8 and checks the pin is in all of them.
#
# No hardware: the token tools and qvm-* are replaced by stubs that say they were reached and fail.
# REQUIRE_UTF8_LOCALE=1 (CI) turns a missing en_US.UTF-8 into a failure instead of a skip.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
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
for t in pkcs11-tool opensc-tool sc-hsm-tool ykman pcsc_scan opensc-explorer pkcs15-tool qvm-run qvm-create qvm-kill qvm-remove; do
  printf '#!/bin/sh\necho "STUB: %s was reached" >&2\nexit 97\n' "$t" > "$T/stub/$t"; chmod +x "$T/stub/$t"; done
: > "$T/module.so"
# The scripts' own pin, lifted from one of them, so the checks below run the shipped lines.
PIN_SNIPPET="$(sed -n '/^if \[ -n "\${LC_ALL:-}" \]; then$/,/^export LC_COLLATE=C$/p' "$SCRIPTS/operation-proof.sh")"
[ -n "$PIN_SNIPPET" ] || { echo "test-locale-ranges: cannot find the collation pin in operation-proof.sh"; exit 1; }
# last <locale> <script> [args]: the last line the script says, under that locale.
last(){ local loc="$1"; shift; env LC_ALL="$loc" LANG="$loc" PATH="$T/stub:$PATH" WORK="$T" bash "$@" 2>&1 | tail -1; }
# refused <what> <text the validator says> <script> [args]: under en_US.UTF-8 the validator itself refuses.
refused(){ local what="$1" want="$2" out; shift 2; out="$(last "$LOC" "$@")"
  grep -qF -- "$want" <<< "$out" && P "$what: refused by its validator" || F "$what: not refused by its validator; the script went on to: $out"; }

hdr "0  the instrument: this locale does widen a range, and the scripts' pin undoes it"
widened="$(LC_ALL=$LOC bash -c '[[ "７" =~ ^[0-9]$ ]] && echo yes || echo no')"
[ "$widened" = yes ] && P "under $LOC, bash's [0-9] takes a full-width digit" || F "under $LOC [0-9] does not take a full-width digit: the checks below would prove nothing"
probe='s="héllo"; [[ "７" =~ ^[0-9]$ ]] && d=yes || d=no; printf "%s %s %s %s" "$d" "${#s}" "${LC_ALL:-unset}" "$LC_MESSAGES"'
pinned="$(LC_ALL=$LOC LC_CTYPE=C LC_MESSAGES=C bash -c "$PIN_SNIPPET"$'\n'"$probe")"
[ "$pinned" = "no 5 unset $LOC" ] \
  && P "with the pin: no full-width digit, a 5-character string is still 5 long, and a category LC_ALL was overriding does not come back" \
  || F "the pin: got '$pinned', want 'no 5 unset $LOC'"

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

hdr "3  dev-image-bootstrap.sh: what counts as a commit id for the file root installs from"
# The decision itself, lifted from the script (it sits in the middle of an installer that needs root
# and a network): REQ_REF pins the requirements file only when it is 40 HEX digits.
DECISION="$(sed -n '/^  pinned_by_ref=0$/,/^  esac$/p' "$SCRIPTS/dev-image-bootstrap.sh")"
grep -q 'pinned_by_ref=1' <<< "$DECISION" || F "cannot find the REQ_REF decision in dev-image-bootstrap.sh"
WIDE40="$(printf '７%.0s' {1..40})"
decide(){ LC_ALL=$LOC REQ_REF="$1" bash -c "$2"$'\n'"$DECISION"$'\n''echo "$pinned_by_ref"' 2>/dev/null; }
[ "$(decide "$WIDE40" "")" = 1 ] && P "the instrument: unpinned, forty full-width digits pass as a commit id" || F "unpinned, forty full-width digits were not taken as a commit id: this locale does not reproduce the bug"
[ "$(decide "$WIDE40" "$PIN_SNIPPET")" = 0 ] && P "with the script's pin, forty full-width digits are NOT a commit id (the install is refused)" || F "forty full-width digits still pass as a commit id"
[ "$(decide 0123456789abcdef0123456789ABCDEF01234567 "$PIN_SNIPPET")" = 1 ] && P "control: forty hex digits are a commit id" || F "a real commit id is refused"
[ "$(decide main "$PIN_SNIPPET")" = 0 ] && P "control: a branch name is not" || F "a branch name passed as a commit id"
pin_line="$(grep -n '^export LC_COLLATE=C$' "$SCRIPTS/dev-image-bootstrap.sh" | head -1 | cut -d: -f1)"
dec_line="$(grep -n '^  pinned_by_ref=0$' "$SCRIPTS/dev-image-bootstrap.sh" | head -1 | cut -d: -f1)"
[ -n "$pin_line" ] && [ -n "$dec_line" ] && [ "$pin_line" -lt "$dec_line" ] && P "and the script pins the collation before that decision (line $pin_line < $dec_line)" || F "dev-image-bootstrap.sh does not pin before the REQ_REF decision"

hdr "4  two more validators over caller input"
refused "hsm-key-attestation-read.sh --key-ref in full-width digits" "is not a decimal key reference" "$SCRIPTS/hsm-key-attestation-read.sh" --reader 0 --key-ref '７'
out="$(HSM_SLOT_ID='７' last "$LOC" "$ROOT/tools/hsm-capacity-check.sh")"
grep -qF "is not a numeric PKCS#11 slot id" <<< "$out" && P "hsm-capacity-check.sh HSM_SLOT_ID in full-width digits: refused by its validator" || F "hsm-capacity-check.sh: not refused; it went on to: $out"

hdr "5  every script whose ranges check caller input pins the collation, before its first check"
for s in qubes/scripts/ceremony.sh qubes/scripts/go-nogo.sh qubes/scripts/hsm-fleet-drill.sh qubes/scripts/hsm-init-hardened.sh \
         qubes/scripts/hsm-recovery-drill.sh qubes/scripts/hsm-staging-e2e.sh qubes/scripts/nitrokey-acceptance.sh \
         qubes/scripts/operation-proof.sh qubes/scripts/hsm-import-key.sh qubes/scripts/hsm-unwrap-key.sh \
         qubes/scripts/hsm-signing-key.sh \
         qubes/scripts/dev-image-bootstrap.sh qubes/scripts/hsm-key-attestation-read.sh qubes/scripts/hsm-staging-ci.sh \
         qubes/dom0/vault-tools-update.sh hsm-host-role/files/commission-card.sh tools/hsm-dkek-refusal-probe.sh \
         tools/hsm-capacity-check.sh debian/offline-bundle/build.sh debian/offline-bundle/verify-release.sh; do
  f="$ROOT/$s"
  pin="$(grep -n '^export LC_COLLATE=C$' "$f" | head -1 | cut -d: -f1)"
  move="$(grep -n '^  unset LC_ALL _lc$' "$f" | head -1 | cut -d: -f1)"
  # the first pattern bash evaluates in code: a =~, or a case arm made of a range (comment lines aside)
  first="$(grep -nE '=~|^[[:space:]]*case .* in|^[[:space:]]*[^#]*\[!?[0-9A-Za-z]-[0-9A-Za-z][^]]*\][^)]*\)' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' \
           | awk -F: -v p="${pin:-0}" '$1 != p' | head -1 | cut -d: -f1)"
  if [ -n "$pin" ] && [ -n "$move" ] && [ "$move" -lt "$pin" ] && { [ -z "$first" ] || [ "$pin" -lt "$first" ]; }; then
    P "$s (line $pin)"
  else F "$s: collation pin at line '${pin:-none}', LC_ALL moved at '${move:-none}', first pattern at '${first:-none}'"; fi
done
# And nothing else: a script outside the list that lets bash evaluate a range over a value must be
# looked at. Lines that only hand a pattern to grep, sed, awk, tr or jq are another matter, and so is
# Python embedded in a script: its `re` reads [0-9] as those ten code points in any locale.
others="$(cd "$ROOT" && find . -name '*.sh' -not -path './.git/*' -not -path './qubes/emulator/tests/*' | sort | while read -r f; do
    grep -q '^export LC_COLLATE=C$' "$f" && continue
    grep -nE '(=~|case .* in|\)[[:space:]]).*\[!?[0-9A-Za-z]-[0-9A-Za-z][^]]*\]|^[[:space:]]*\*?\[!?[0-9A-Za-z]-[0-9A-Za-z][^]]*\][^)]*\)' "$f" \
      | grep -vE '^[0-9]+:[[:space:]]*#|grep|sed |awk|\btr\b|python|jq |re\.(fullmatch|match|search|sub|compile)' | sed "s|^|$f:|"
  done)"
# Known and left alone: the bench lock reads back a pid it wrote itself; pin-escrow.sh sets LC_ALL=C
# around its own check.
others="$(grep -vE '^\./tools/hsm-bench-lock\.sh:|^\./qubes/scripts/escrow/pin-escrow\.sh:' <<< "$others" || true)"
[ -z "$others" ] && P "no other script lets bash evaluate a range over a value" || F "unpinned scripts with a bash-evaluated range: $others"

echo; echo "test-locale-ranges: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
