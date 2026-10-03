#!/usr/bin/env bash
# ADR-0002 D12 (owner, 2026-09-29): a Shamir share is written BY HAND, never printed. record_share
# prints only a blank form, shows the share on the terminal, clears it, and requires the operator
# to type it back from the paper. Driven through a real pseudo-terminal (script), as in the vault's
# xterm; a stub lp records everything sent to the printer.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
command -v script >/dev/null || { echo "  SKIP: util-linux 'script' not available"; exit 0; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/spool"
cat > "$T/bin/lp" <<'SH'
#!/usr/bin/env bash
for a in "$@"; do [ -f "$a" ] && cp "$a" "$SPOOL/$(date +%s%N)-$(basename "$a")"; done; exit 0
SH
chmod +x "$T/bin/lp"
SHARE="academic acid acrobat romp beam husband pharmacy"
printf '%s' "$SHARE" > "$T/share"
cat > "$T/drive.sh" <<DRIVE
export PATH="$T/bin:\$PATH" SPOOL="$T/spool"
source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1
W=\$(mktemp -d); HERE="$SCRIPTS"; WORK=\$W; PRINTER=fakeq
record_share "Wallet seed — SLIP-0039 share 1 of 6 (need 4)" "$T/share"; echo "RC=\$?"
DRIVE
drive(){ printf "$1" | timeout 60 script -qec "bash $T/drive.sh" /dev/null 2>&1 | sed $'s/\033\\[[0-9;]*[A-Za-z]//g' | tr -d '\r'; }

hdr "an exact handwritten copy is accepted"
out="$(drive "y\n\n\n$SHARE\n")"
grep -q "RC=0" <<< "$out" && grep -q "MATCHES" <<< "$out" && P "verified" || F "exact copy not accepted"

hdr "the printer received a blank form and NOT the share"
n="$(ls "$T/spool" | wc -l)"
[ "$n" -ge 1 ] && P "a form was printed ($n file(s))" || F "nothing was printed"
if grep -rqiE "academic|pharmacy|husband" "$T/spool"; then F "a share word reached the printer"; else P "no share word in anything sent to the printer"; fi

hdr "capitals and extra spaces in the copy are the same words"
out="$(drive "y\n\n\nAcademic  acid ACROBAT romp beam   husband pharmacy\n")"
grep -q "RC=0" <<< "$out" && P "accepted" || F "sloppy-but-same copy rejected"

hdr "a wrong copy is caught, the share re-shown, and a corrected copy accepted"
out="$(drive "y\n\n\nacademic acid acrobat romp beam husband\n\n\n$SHARE\n")"
grep -q "does NOT match" <<< "$out" && grep -q "RC=0" <<< "$out" && P "mismatch caught, then verified" || F "mismatch handling wrong"

hdr "three wrong copies: NOT verified (RC=1)"
out="$(drive "y\n\n\nx\n\n\ny\n\n\nz\n")"
grep -q "NOT verified" <<< "$out" && grep -q "RC=1" <<< "$out" && P "refused after three mismatches" || F "three mismatches not refused"

hdr "inside 'while read … done < shares' (as step 3 calls it): no prompt swallows a share"
printf '%s\n' "academic acid acrobat romp beam husband pharmacy" "zero zoo zone zinc zeal zest zeta" "sock sofa soft soil solo some song" > "$T/three"
cat > "$T/loop.sh" <<LOOP
export PATH="$T/bin:\$PATH" SPOOL="$T/spool"
source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1
W=\$(mktemp -d); HERE="$SCRIPTS"; WORK=\$W; PRINTER=fakeq; n=0
while IFS= read -r line; do n=\$((n+1)); printf '%s' "\$line" > "\$W/s\$n"; record_share "share \$n" "\$W/s\$n" && echo "OK \$n"; done < "$T/three"
echo "PROCESSED \$n"
LOOP
out="$(printf 'y\n\n\nacademic acid acrobat romp beam husband pharmacy\ny\n\n\nzero zoo zone zinc zeal zest zeta\ny\n\n\nsock sofa soft soil solo some song\n' | timeout 60 script -qec "bash $T/loop.sh" /dev/null 2>&1 | tr -d '\r')"
grep -q "PROCESSED 3" <<< "$out" && grep -c "^OK " <<< "$out" | grep -qx 3 && P "all three shares processed and verified in the loop" || F "a share was swallowed or unverified: $(grep -E 'PROCESSED|^OK' <<< "$out" | tr '\n' ' ')"

hdr "the blank form was not printed, and not confirmed printed another way: the share is NOT shown"
out="$(drive "n\nn\n")"
grep -q "no blank form" <<< "$out" && grep -q "RC=1" <<< "$out" && ! grep -q "academic" <<< "$(grep -v '^   run' <<< "$out")" && P "stopped without showing the share" || F "went on without a form"

hdr "no terminal (scripted run): the share is not shown"
out="$(setsid bash -c "export PATH='$T/bin':\$PATH SPOOL='$T/spool'; source '$SCRIPTS/ceremony.sh' >/dev/null 2>&1; W=\$(mktemp -d); HERE='$SCRIPTS'; WORK=\$W; PRINTER=fakeq; run(){ eval \"\$@\"; }; record_share 'x' '$T/share' </dev/null; echo RC=\$?" 2>&1 < /dev/null)"
grep -q "NOT shown or verified" <<< "$out" && P "says it was not shown or verified" || F "no-terminal case not reported: $out"
grep -q "academic" <<< "$out" && F "the share was shown without a terminal" || P "the share was not shown"

hdr "share-form.py builds a blank form for both kinds"
python3 "$SCRIPTS/share-form.py" --label t --kind words --count 33 -o "$T/w.ps" && grep -q "showpage" "$T/w.ps" && P "word form" || F "word form"
python3 "$SCRIPTS/share-form.py" --label t --kind chars --count 150 -o "$T/c.ps" && grep -q "showpage" "$T/c.ps" && P "character form" || F "character form"

hdr "the form: label, handwrite fields, and the holder/recovery instructions on every page"
python3 "$SCRIPTS/share-form.py" --label "Wallet seed - share 3 of 6 (need 4)" --kind words --count 33 -o "$T/l.ps"
for want in "Case ID:" "Seal serial:" "Date sealed:" "Share number:" "Witness" "IF YOU HOLD THIS SHEET" "TO RECOVER" "any 4 of them together" "offline" "Wallet seed - share 3 of 6" \
            "Principal \(full name\):" "WHEN TO ACT" "ORIGINAL official death certificate" "certificate of incapacity" \
            "IN PERSON - never by phone, message, e-mail or video call" "only the two of you know" "contact the police" \
            "Nobody can authorize its release remotely"; do
  grep -qF "$want" "$T/l.ps" && P "form has: $want" || F "form lacks: $want"
done
grep -q "the threshold" "$T/l.ps" && F "the old 'any the threshold' wording is back" || P "no 'any the threshold' wording"
python3 "$SCRIPTS/share-form.py" --label t --kind words --count 20 --threshold 3 --total 5 -o "$T/t.ps" && grep -qF "any 3 of them" "$T/t.ps" && grep -qF "ONE of 5 shares" "$T/t.ps" && P "--threshold/--total reach the instructions" || F "threshold/total not printed"

hdr "the page size is declared (an undeclared A4 page lost its title under a Letter default)"
python3 "$SCRIPTS/share-form.py" --label t --kind chars --count 148 --paper a4 -o "$T/a4.ps"
grep -q "/PageSize \[595.28 841.89\]" "$T/a4.ps" && P "A4 declared" || F "A4 page size not declared"
grep -q "/PageSize \[612.00 792.00\]" "$T/w.ps" && P "Letter declared" || F "Letter page size not declared"

hdr "a share too long to fit above the instructions: refused, nothing written (never printed without them)"
rm -f "$T/big.ps"; o="$(python3 "$SCRIPTS/share-form.py" --label t --kind chars --count 400 -o "$T/big.ps" 2>&1)"; rc=$?
[ "$rc" != 0 ] && grep -q "do not fit" <<< "$o" && [ ! -e "$T/big.ps" ] && P "refused, no file" || F "oversize share: rc=$rc $o"

if command -v gs >/dev/null 2>&1; then
  hdr "the forms render (ghostscript)"
  for f in w c l a4; do gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=nullpage "$T/$f.ps" >/dev/null 2>&1 && P "$f.ps renders" || F "$f.ps does not render"; done
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
