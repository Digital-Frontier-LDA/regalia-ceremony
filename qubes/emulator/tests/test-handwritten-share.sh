#!/usr/bin/env bash
# ADR-0002 D12 (owner, 2026-09-29): a Shamir share is written BY HAND, never printed. record_share
# prints only a blank form, shows the share on the terminal, clears it, and requires the operator
# to type it back from the paper. Driven through a real pseudo-terminal (script), as in the vault's
# xterm; a stub lp records everything sent to the printer.
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
run(){ eval "\$@"; }
record_share "Wallet seed — SLIP-0039 share 1 of 6 (need 4)" "$T/share"; echo "RC=\$?"
DRIVE
drive(){ printf "$1" | timeout 60 script -qec "bash $T/drive.sh" /dev/null 2>&1 | sed $'s/\033\\[[0-9;]*[A-Za-z]//g' | tr -d '\r'; }

hdr "an exact handwritten copy is accepted"
out="$(drive "\n\n$SHARE\n")"
grep -q "RC=0" <<< "$out" && grep -q "MATCHES" <<< "$out" && P "verified" || F "exact copy not accepted"

hdr "the printer received a blank form and NOT the share"
n="$(ls "$T/spool" | wc -l)"
[ "$n" -ge 1 ] && P "a form was printed ($n file(s))" || F "nothing was printed"
if grep -rqiE "academic|pharmacy|husband" "$T/spool"; then F "a share word reached the printer"; else P "no share word in anything sent to the printer"; fi

hdr "capitals and extra spaces in the copy are the same words"
out="$(drive "\n\nAcademic  acid ACROBAT romp beam   husband pharmacy\n")"
grep -q "RC=0" <<< "$out" && P "accepted" || F "sloppy-but-same copy rejected"

hdr "a wrong copy is caught, the share re-shown, and a corrected copy accepted"
out="$(drive "\n\nacademic acid acrobat romp beam husband\n\n\n$SHARE\n")"
grep -q "does NOT match" <<< "$out" && grep -q "RC=0" <<< "$out" && P "mismatch caught, then verified" || F "mismatch handling wrong"

hdr "three wrong copies: NOT verified (RC=1)"
out="$(drive "\n\nx\n\n\ny\n\n\nz\n")"
grep -q "NOT verified" <<< "$out" && grep -q "RC=1" <<< "$out" && P "refused after three mismatches" || F "three mismatches not refused"

hdr "no terminal (scripted run): the share is not shown"
out="$(setsid bash -c "export PATH='$T/bin':\$PATH SPOOL='$T/spool'; source '$SCRIPTS/ceremony.sh' >/dev/null 2>&1; W=\$(mktemp -d); HERE='$SCRIPTS'; WORK=\$W; PRINTER=fakeq; run(){ eval \"\$@\"; }; record_share 'x' '$T/share' </dev/null; echo RC=\$?" 2>&1 < /dev/null)"
grep -q "NOT shown or verified" <<< "$out" && P "says it was not shown or verified" || F "no-terminal case not reported: $out"
grep -q "academic" <<< "$out" && F "the share was shown without a terminal" || P "the share was not shown"

hdr "share-form.py builds a blank form for both kinds"
python3 "$SCRIPTS/share-form.py" --label t --kind words --count 33 -o "$T/w.ps" && grep -q "showpage" "$T/w.ps" && P "word form" || F "word form"
python3 "$SCRIPTS/share-form.py" --label t --kind chars --count 150 -o "$T/c.ps" && grep -q "showpage" "$T/c.ps" && P "character form" || F "character form"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
