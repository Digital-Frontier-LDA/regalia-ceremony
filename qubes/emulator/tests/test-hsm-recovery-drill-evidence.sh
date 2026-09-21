#!/usr/bin/env bash
# test-hsm-recovery-drill-evidence.sh — when the recovery drill's wrong-share negative control
# FAILS, the drill must keep what sc-hsm-tool said, and must not leak share material doing it.
#
# WHY. In the #397 repro loop the card accepted a deliberately corrupted DKEK share once, and the
# drill threw the tool's output away on exactly that branch (it printed output only on refusal). So
# the one occurrence could not say whether sc-hsm-tool's host-side decrypt accepted a wrong password
# or the card accepted a share. The drill's transcript is pasted into doc/drills, so the evidence
# must go through elide_hex first.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRILL="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/hsm-recovery-drill.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -f "$DRILL" ] || { echo "missing $DRILL" >&2; exit 1; }

hdr "elide_hex is defined once, on one line, in the drill"
defs="$(grep -c '^elide_hex(){' "$DRILL" || true)"
if [ "$defs" = 1 ]; then
  eval "$(grep '^elide_hex(){' "$DRILL")"
  P "elide_hex found"
else
  F "expected exactly one one-line elide_hex definition in the drill, found $defs"
  printf '  1 passed, %s failed\n' "$((fail))"; exit 1
fi

hdr "elide_hex removes share-shaped material and keeps the prose"
# Shaped like the lines feed_shares parses out of --create-dkek-share output, plus the import's
# own output. The values are made up; the SHAPES are what the drill handles. The bare hex runs are
# built at run time so the secret scanner does not read a literal fixture as a committed key.
rep(){ local out='' n=0; while [ "$n" -lt "$2" ]; do out="$out$1"; n=$((n+1)); done; printf '%s' "$out"; }
sample="Using reader with a card: Pico Key CCID Interface
Please enter prime: 
Prime       : 00:C3:F1:A2:B4:9D:8E:7F:60:11:22:33:44:55:66:77
Share ID    : 1
Share value : 8a:3f:00:12:9c:44:01:fe:10:20:30:40:50:60:70:80
Password    : $(rep 5a 16)
DKEK share imported
DKEK key check value : $(rep C0 8)
DKEK shares          : 1"
got="$(printf '%s\n' "$sample" | elide_hex)"
left="$(grep -E '[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){3,}|[0-9A-Fa-f]{16,}' <<< "$got" || true)"
if [ -z "$left" ]; then
  P "no colon-separated byte run and no 16+ hex run survives"
else
  F "hex material survived elide_hex:"; printf '    | %s\n' "$left"
fi
elided="$(grep -c '<hex elided>' <<< "$got" || true)"
if [ "$elided" = 4 ]; then
  P "exactly the 4 hex-bearing lines were elided"
else
  F "expected 4 elided lines, got $elided"; printf '    | %s\n' "$got"
fi
for keep in 'DKEK share imported' 'Share ID    : 1' 'DKEK shares          : 1' 'Pico Key CCID Interface'; do
  if grep -qF -- "$keep" <<< "$got"; then P "kept: $keep"; else F "lost prose: $keep"; fi
done

hdr "the accepted-wrong-share branch prints the tool output, through elide_hex"
# The branch between the rc=0 FAIL and the refusal elif of the AUTO negative control.
# The closing elif line itself is excluded: it reads $out to test for the refusal message.
branch="$(awk '/ACCEPTED a wrong DKEK share/ && !seen {inb=1; seen=1} inb && /^  elif / {inb=0} inb {print}' "$DRILL")"
if [ -z "$branch" ]; then
  F "could not find the accepted-wrong-share branch; this check cannot be evaluated"
elif grep -qE 'printf .%s\\n. "\$out" \| elide_hex' <<< "$branch"; then
  P "the rc=0 branch pipes \$out through elide_hex"
else
  F "the rc=0 branch does not print \$out through elide_hex — the evidence is discarded or unredacted:"
  printf '    | %s\n' "$branch"
fi
if grep -qE '"\$out"' <<< "$(grep -v 'elide_hex' <<< "$branch")"; then
  F "the rc=0 branch also prints \$out WITHOUT elide_hex"
else
  P "no unredacted use of \$out in the rc=0 branch"
fi

hdr "the transcript names the device it actually ran on"
# THE TRANSCRIPT IS EVIDENCE. It is pasted into doc/drills and read later by someone deciding
# whether a requirement is met, so a line asserting the wrong device is worse than no line: the
# closing caveat said "This is a Pico standing in for the Nitrokey HSM 2" unconditionally, which on
# a Nitrokey run throws away exactly what that run was worth (regalia#481 made such a run possible,
# and the first one passed 25/0/2 on DENK0404144).
eval "$(sed -n '/^device_kind(){/,/^}/p' "$DRILL")"
slot_serial(){ printf '%s\n' "${FAKE_SERIAL:-}"; }
SLOT=0

for pair in "DENK0404144:nitrokey-hsm2" "ESP41D722E2:pico-hsm2" ":unknown" "XYZ123:unknown"; do
  FAKE_SERIAL="${pair%%:*}"; want="${pair##*:}"
  got="$(device_kind)"
  if [ "$got" = "$want" ]; then P "serial '${FAKE_SERIAL:-<none>}' reads as $want"
  else F "serial '${FAKE_SERIAL:-<none>}' read as '$got', wanted '$want'"; fi
done
unset FAKE_SERIAL

# The claim itself: one branch per kind, and the Pico caveat may not be printed unconditionally.
if grep -q 'D1 IS STILL OPEN' "$DRILL" && grep -q 'nitrokey-hsm2)' "$DRILL"; then
  P "the closing caveat is branched on the device kind"
else
  F "the closing caveat does not branch on the device kind"
fi
if grep -qE "^printf .*D1 IS STILL OPEN" "$DRILL"; then
  F "the Pico caveat is still printed unconditionally"
else
  P "the Pico caveat is not printed unconditionally"
fi
grep -q 'DEVICE UNIDENTIFIED' "$DRILL" \
  && P "an unidentified device is said to be unidentified, not assumed" \
  || F "a card whose serial does not identify it is silently attributed"

printf '\n  %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
