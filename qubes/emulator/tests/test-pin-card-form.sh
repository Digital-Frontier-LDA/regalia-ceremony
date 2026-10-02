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
[ "$(boxes "$T/d.ps")" = $((3 * 10 + 3 * 8 + 16 + 32 + 1 + 3 * 20 + 1)) ] && P "164 boxes (30 + 24 digits + 16 breakglass fingerprint + 32 escrow MAC key + the rules; page 2: 3 x 20 + its rules)" || F "boxes: $(boxes "$T/d.ps")"
# Page 2, the KMS host card (regalia-ceremony#92): a 20-box row per KMS host for its TPM lockout authorization.
grep -q "^%%Pages: 2$" "$T/d.ps" && [ "$(grep -c '^showpage$' "$T/d.ps")" = 2 ] && P "two pages" || F "not two pages"
for r in "KMS HOST CARD - WRITE BY HAND" "KMS host A - TPM lockout authorization" "KMS host B - TPM lockout authorization" "KMS host C - TPM lockout authorization"; do
  grep -qF "$r" "$T/d.ps" && P "page 2: $r" || F "page 2 missing: $r"
done
for w in "RULES FOR THIS PAGE" "never guess at the host" "after ONE wrong attempt" "24 hours" "never contains 0, 1, I, L or O" "tpm-lockout.sh --set" \
         "WITHOUT spaces" "KEEP this page" "for all of these values again"; do
  grep -qF "$w" "$T/d.ps" && P "page 2 rule: $w" || F "page 2 rule missing: $w"
done
# The page must not tell the operator to destroy what escrow/pin-escrow.sh will ask for again.
# NEITHER page may tell the operator to destroy what escrow/pin-escrow.sh will ask for again: it
# needs every PIN and the escrow MAC key (page 1) and every TPM lockout authorization (page 2).
form="$(cat "$T/d.ps")"
grep -qiE "destroy|shred|burn" <<< "$form" && F "the form tells the operator to destroy a card that every later escrow needs" || P "neither page tells the operator to destroy it"
grep -qF "KEEP the card after" <<< "$form" && grep -qF "the next PIN escrow asks for every PIN and the escrow MAC key" <<< "$form" && P "page 1 says to keep the card, and why" || F "page 1 does not say to keep the card"
# Owner, 2026-10-02: the card is kept because it is how the KMS servers are resuscitated.
grep -qF "It is how a KMS server is BROUGHT BACK" <<< "$form" && grep -qF "the PIN is sealed again from this card" <<< "$form" \
  && P "page 1 gives the first reason: a server whose TPM has lost the sealed PIN is brought back from this card" || F "page 1 does not say the card brings a KMS server back"
# A TPM in lockout has NOT lost the PIN: sealing it again there would expose the PIN for nothing.
grep -qF "only in LOCKOUT still holds it: clear the lockout with page 2, do not seal again" <<< "$form" \
  && P "page 1 sends a TPM lockout to page 2 and says not to seal again" || F "page 1 does not tell a lockout apart from a lost PIN"
grep -qE "TPM reset or lockout" <<< "$form" && F "page 1 lists a lockout as a reason to seal the PIN again" || P "a lockout is not listed as a reason to seal again"
grep -qF "It is what clears" <<< "$form" && grep -qF "a server's TPM lockout when that server has to be brought back" <<< "$form" \
  && P "page 2 says the same of the lockout authorizations" || F "page 2 does not say what the values are kept for"
for paper in letter a4; do python3 "$F_" -o "$T/fit-$paper.ps" --paper "$paper" 2>"$T/fit.err" && P "three HSMs, three YubiKeys and three hosts still fit on $paper with the longer rules" || F "does not fit on $paper: $(cat "$T/fit.err")"; done
python3 "$F_" -o "$T/nohost.ps" --hosts "" && grep -q "^%%Pages: 1$" "$T/nohost.ps" && ! grep -q "KMS HOST CARD" "$T/nohost.ps" \
  && [ "$(boxes "$T/nohost.ps")" = 103 ] && P "--hosts '' prints the PIN card alone (103 boxes, one page)" || F "--hosts '' did not drop page 2"
grep -q "ESCROW MAC KEY - 32 hex" "$T/d.ps" && P "the card has the escrow MAC key rows" || F "no escrow MAC key row"
grep -q "Breakglass recipient - first 16 hex of sha256" "$T/d.ps" && P "the card has the breakglass recipient fingerprint row" || F "no breakglass fingerprint row"
for w in "RULES FOR THIS CARD" "APART from the tokens" "NOT the backup" "seal-hsm-pin.sh" "Never write the SO-PINs" "rotate them"; do
  grep -qF "$w" "$T/d.ps" && P "rule: $w" || F "rule missing: $w"
done
grep -q "/PageSize \[612.00 792.00\]" "$T/d.ps" && P "page size declared" || F "page size not declared"

hdr "the rows follow the fleet and the PIN lengths"
python3 "$F_" -o "$T/s.ps" --hsms a,b --yubikeys a --hsm-digits 12 --yubikey-digits 6 --paper a4
grep -qF "HSM C" "$T/s.ps" && F "HSM C drawn for a two-HSM fleet" || P "two HSMs, one YubiKey"
[ "$(boxes "$T/s.ps")" = $((2 * 12 + 6 + 16 + 32 + 1 + 3 * 20 + 1)) ] && P "140 boxes (2x12 + 6 + 16 fingerprint + 32 escrow MAC key + rules; page 2: 3 x 20 + its rules)" || F "boxes: $(boxes "$T/s.ps")"
python3 "$F_" -o "$T/h.ps" --hosts a,b && ! grep -qF "KMS host C" "$T/h.ps" && grep -qF "KMS host B" "$T/h.ps" && P "page 2 follows the host list (two hosts, no C)" || F "page 2 does not follow --hosts"

hdr "bad input refused, nothing written"
for args in "--hsms ab" "--hsms a,b,c,d" "--yubikeys 1" "--hsm-digits 5" "--yubikey-digits 9" "--hosts ab" "--hosts a,b,c,d" "--hosts 1"; do
  rm -f "$T/x.ps"; python3 "$F_" -o "$T/x.ps" $args >/dev/null 2>&1 && F "accepted: $args" || { [ ! -e "$T/x.ps" ] && P "refused: $args" || F "file written for: $args"; }
done

if command -v gs >/dev/null 2>&1; then
  hdr "renders"
  for f in d s h nohost; do gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=nullpage "$T/$f.ps" >/dev/null 2>&1 && P "$f.ps renders" || F "$f.ps does not render"; done
fi

hdr "step 0 builds the card for its own fleet before showing the PINs"
grep -q 'pin-card-form.py" -o "$card" --hsms "$(tr' "$SCRIPTS/ceremony.sh" && P "called with the HSM and YubiKey lists" || F "step 0 does not build the card"
grep -q -- '--hosts "$(tr .* <<< "$KMS_HOSTS")"' "$SCRIPTS/ceremony.sh" && P "and with the KMS host list, for page 2" || F "step 0 does not pass the KMS hosts to the card"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
