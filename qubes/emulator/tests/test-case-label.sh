#!/usr/bin/env bash
# test-case-label.sh — the label on the OUTSIDE of each sealed case (owner, 2026-09-29): the release
# rules, readable without breaking the seal; the size of a DVD case front with a 0.5 inch safety
# border; and NOTHING that says what is inside (a burglar or a curious relative must not learn it).
# The distress answer itself is never printed.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" && pwd):$PATH"   # the emulator stand-ins (ykman, pkcs11-tool, sc-hsm-tool) first, as under run-tests.sh (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
python3 "$SCRIPTS/case-label.py" -o "$T/l.ps" && P "built (Letter)" || F "not built"
python3 "$SCRIPTS/case-label.py" -o "$T/a4.ps" --paper a4 && P "built (A4)" || F "A4 not built"
text="$(grep -oE '\(([^()\\]|\\.)*\) show' "$T/l.ps" | sed 's/) show$//; s/^(//' | tr '\n' ' ')"

hdr "the release rules are on it"
for w in "DO NOT OPEN" "To the OWNER, in person" "check question" "DISTRESS" "contact the police" "EXECUTOR" "ORIGINAL official death certificate" "court decision" "NEVER on a phone call" "technical staff on their own" "never written down" "Case ID:" "Seal serial:"; do
  grep -qF "$w" <<< "$text" && P "says: $w" || F "missing: $w"
done

hdr "it says nothing about what is inside"
for w in wallet crypto bitcoin akash seed share mnemonic "private key" funds money; do
  grep -qiw "$w" <<< "$text" && F "the label mentions '$w'" || P "no '$w'"
done

hdr "a DVD case front (135 x 190 mm) with every word at least 0.5 inch inside the cut line"
box="$(grep -oE '^\[4 3\] 0 setdash [0-9.]+ [0-9.]+ [0-9.]+ [0-9.]+ rectstroke' "$T/l.ps" | awk '{print $5, $6, $7, $8}')"
read -r bx by bw bh <<< "$box"
python3 -c "import sys; mm=72/25.4; w,h=float(sys.argv[1]),float(sys.argv[2]); sys.exit(0 if abs(w-135*mm)<1 and abs(h-190*mm)<1 else 1)" "$bw" "$bh" \
  && P "the cut line is 135 x 190 mm" || F "cut line is ${bw}x${bh} pt"
# The border is checked on the RENDERED page, not estimated from character counts: at 72 dpi one
# pixel is one point, and the 0.5 inch (36 pt) band inside the cut line must hold no ink except
# the dashed cut line itself (skip 3 px at the edge).
if command -v gs >/dev/null 2>&1; then
  gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=pgmraw -r72 -sOutputFile="$T/l.pgm" "$T/l.ps" >/dev/null 2>&1
  python3 - "$T/l.pgm" "$bx" "$by" "$bw" "$bh" <<'PY' && P "the 0.5 inch border is blank on the rendered page" || F "ink inside the 0.5 inch border"
import sys
data = open(sys.argv[1], "rb").read()
# PGM header: "P5", width, height, maxval, as whitespace-separated tokens; lines starting with "#"
# are comments (Ghostscript writes one). One whitespace byte follows maxval, then the pixels.
tokens, i = [], 0
while len(tokens) < 4:
    while data[i:i + 1].isspace(): i += 1
    if data[i:i + 1] == b"#":
        i = data.index(b"\n", i) + 1; continue
    j = i
    while not data[j:j + 1].isspace(): j += 1
    tokens.append(data[i:j]); i = j
px = data[i + 1:]
W, H = int(tokens[1]), int(tokens[2])
x, y, w, h = map(float, sys.argv[2:6]); b = 36
def dark(cx, cy):                                  # PostScript y grows up; image rows grow down
    return px[(H - 1 - cy) * W + cx] < 128
bad = [(cx, cy) for cx in range(int(x) + 3, int(x + w) - 2) for cy in range(int(y) + 3, int(y + h) - 2)
       if not (x + b <= cx <= x + w - b and y + b <= cy <= y + h - b) and dark(cx, cy)]
if bad:
    print("ink in the border at", bad[:5]); sys.exit(1)
PY
else
  echo "  (ghostscript absent: rendered border check skipped)"
fi
grep -q "/PageSize \[612.00 792.00\]" "$T/l.ps" && grep -q "/PageSize \[595.28 841.89\]" "$T/a4.ps" && P "page size declared" || F "page size not declared"
if command -v gs >/dev/null 2>&1; then
  for f in l a4; do gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=nullpage "$T/$f.ps" >/dev/null 2>&1 && P "$f.ps renders" || F "$f.ps does not render"; done
fi

hdr "the wizard prints it with each recovery card"
grep -q 'case-label.py" -o "$label"' "$SCRIPTS/ceremony.sh" && P "step_recovery_card builds the label" || F "the wizard does not build the label"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
