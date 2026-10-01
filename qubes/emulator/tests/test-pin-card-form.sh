#!/usr/bin/env bash
# test-pin-card-form.sh — the blank paper PIN card (ADR-0002 D16): a row per device with a box per
# digit and a handwritten serial, the rules printed on it, and no PIN anywhere (the printer sees only
# the blank form). Step 0 prints it before showing the day-to-day PINs.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
F_="$SCRIPTS/pin-card-form.py"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
boxes(){ grep -c "rectstroke" "$1"; }

hdr "default: HSM A, B, C (10 boxes each) and YubiKey A, B, C (8 each), plus the rules box"
python3 "$F_" -o "$T/d.ps" && P "built" || F "not built"
for r in "HSM A - user PIN" "HSM B - user PIN" "HSM C - user PIN" "YubiKey A - PIV PIN" "YubiKey C - PIV PIN"; do
  grep -qF "$r" "$T/d.ps" && P "row: $r" || F "missing row: $r"
done
[ "$(boxes "$T/d.ps")" = $((3 * 10 + 3 * 8 + 16 + 32 + 1)) ] && P "103 boxes (30 + 24 digits + 16 breakglass fingerprint + 32 escrow MAC key + the rules)" || F "boxes: $(boxes "$T/d.ps")"
grep -q "ESCROW MAC KEY - 32 hex" "$T/d.ps" && P "the card has the escrow MAC key rows" || F "no escrow MAC key row"
grep -q "Breakglass recipient - first 16 hex of sha256" "$T/d.ps" && P "the card has the breakglass recipient fingerprint row" || F "no breakglass fingerprint row"
for w in "RULES FOR THIS CARD" "APART from the tokens" "NOT the backup" "seal-hsm-pin.sh" "Never write the SO-PINs" "rotate them"; do
  grep -qF "$w" "$T/d.ps" && P "rule: $w" || F "rule missing: $w"
done
grep -q "/PageSize \[612.00 792.00\]" "$T/d.ps" && P "page size declared" || F "page size not declared"

hdr "the rows follow the fleet and the PIN lengths"
python3 "$F_" -o "$T/s.ps" --hsms a,b --yubikeys a --hsm-digits 12 --yubikey-digits 6 --paper a4
grep -qF "HSM C" "$T/s.ps" && F "HSM C drawn for a two-HSM fleet" || P "two HSMs, one YubiKey"
[ "$(boxes "$T/s.ps")" = $((2 * 12 + 6 + 16 + 32 + 1)) ] && P "79 boxes (2x12 + 6 + 16 fingerprint + 32 escrow MAC key + rules)" || F "boxes: $(boxes "$T/s.ps")"

hdr "bad input refused, nothing written"
for args in "--hsms ab" "--hsms a,b,c,d" "--yubikeys 1" "--hsm-digits 5" "--yubikey-digits 9"; do
  rm -f "$T/x.ps"; python3 "$F_" -o "$T/x.ps" $args >/dev/null 2>&1 && F "accepted: $args" || { [ ! -e "$T/x.ps" ] && P "refused: $args" || F "file written for: $args"; }
done

if command -v gs >/dev/null 2>&1; then
  hdr "renders"
  for f in d s; do gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=nullpage "$T/$f.ps" >/dev/null 2>&1 && P "$f.ps renders" || F "$f.ps does not render"; done
fi

hdr "step 0 builds the card for its own fleet before showing the PINs"
grep -q 'pin-card-form.py" -o "$card" --hsms "$(tr' "$SCRIPTS/ceremony.sh" && P "called with the HSM and YubiKey lists" || F "step 0 does not build the card"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
