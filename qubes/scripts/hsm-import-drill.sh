#!/usr/bin/env bash
# hsm-import-drill.sh — prove, on a THROWAWAY device with a THROWAWAY seed, that a
# seed-derived secp256k1 key can be imported into a SmartCard-HSM and used.
#
# THE QUESTION IT ANSWERS: Nitrokey document PKCS#12 import for "RSA and ECC keys" and list
# secp256k1 among supported curves — but no public source shows the two COMBINED. Until that is
# demonstrated, step_hsm_import stays gated, because the whole custody model rests on the
# funding key being seed-derived rather than born on the card.
#
# RUN IT ON A PICO HSM FIRST. Pico HSM is an open-source SmartCard-HSM reimplementation on a
# ~EUR 5 board: same protocol, same sc-hsm-tool, same Smart Card Shell, and reflashable when you
# brick it. A real Nitrokey gives you fifteen wrong SO-PIN attempts before it is scrap (the
# user-PIN retry counter defaults to three — don't confuse the two counters). If the
# Smart Card Shell converter cannot encode secp256k1 at all — the likelier failure, since it is
# a software limit rather than a firmware one — the Pico reveals that for the price of a coffee.
#
#   qubes/scripts/hsm-import-drill.sh --check      # what is attached, no writes
#   qubes/scripts/hsm-import-drill.sh --prepare    # build the throwaway container
#   qubes/scripts/hsm-import-drill.sh --verify     # after importing via scsh
#
# NOTHING HERE TOUCHES A REAL SEED. The mnemonic is a published BIP39 test vector with no funds,
# and the drill refuses to run against a file that is not its own throwaway.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

b()    { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
info() { printf '   %s\n' "$1"; }
warn() { printf '   \033[33m! %s\033[0m\n' "$1"; }
err()  { printf '   \033[31mFAIL %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32mOK\033[0m   %s\n' "$1"; }
show() { printf '   \033[36m$ %s\033[0m\n' "$1"; }

# A PUBLISHED BIP39 test vector. Deliberately hard-coded and deliberately worthless: a drill
# that reads the operator's real mnemonic file would put the funding seed through an unproven
# import path on a device that may be a EUR 5 microcontroller.
DRILL_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
DRILL_DIR="${HSM_DRILL_DIR:-${TMPDIR:-/tmp}/hsm-import-drill}"
P12="$DRILL_DIR/drill.p12"
PWF="$DRILL_DIR/drill.pw"
ADDRF="$DRILL_DIR/expected-address.txt"
MNF="$DRILL_DIR/drill.mnemonic"

need() { command -v "$1" >/dev/null 2>&1 || { err "$1 is required but not on PATH"; return 1; }; }

# Report which card is present WITHOUT writing anything. The ATR is NOT a make/model
# fingerprint: a genuine SmartCard-HSM carries ASCII 'THSM1' — and a Pico HSM DOES TOO
# (measured 2026-07-29, firmware 6.6; see the correction in PICO-DRILL-RUNBOOK.md). All this
# check can say is "carries THSM1 / does not"; it CANNOT prove which board is attached.
# Identify the exact device by its PKCS#11 token serial (pkcs11-tool --list-slots) instead —
# the ceremony pins CEREMONY_EXPECT_ATR (a FULL ATR) for the same reason. This only reports,
# so an operator can tell at a glance what they might be about to write to.
identify() {
  local atr ascii
  need opensc-tool || return 1
  atr="$(opensc-tool --atr 2>/dev/null | tr -d ' \n' | grep -oiE '[0-9a-f:]{20,}' | tr -d ':' | tr 'A-F' 'a-f')"
  if [ -z "$atr" ]; then
    err "no card detected. Plug the device in and check pcscd is running."
    show "opensc-tool --list-readers"
    return 1
  fi
  ascii="$(printf '%s' "$atr" | python3 -c "
import sys
raw = bytes.fromhex(sys.stdin.read().strip())
print(''.join(chr(b) if 32 <= b < 127 else '.' for b in raw))
" 2>/dev/null || true)"
  info "ATR   : $atr"
  info "ASCII : $ascii"
  if grep -q "THSM1" <<< "$ascii"; then
    warn "This looks like a REAL SmartCard-HSM (ATR carries 'THSM1')."
    warn "The drill INITIALISES the device, ERASING everything on it, and spends PIN attempts."
    warn "Run it on a Pico HSM first. Only use a Nitrokey here if it is a scratch unit."
    warn "NOTE: a Pico HSM ALSO carries 'THSM1' in its ATR (measured 2026-07-29) — this check"
    warn "CANNOT tell the two apart. Confirm the exact device by its PKCS#11 token serial:"
    show "pkcs11-tool --list-slots"
    printf '%s' "nitrokey" > "$DRILL_DIR/.device-kind" 2>/dev/null || true
  else
    ok "Not a SmartCard-HSM ATR — consistent with a Pico HSM or another test board."
    printf '%s' "test" > "$DRILL_DIR/.device-kind" 2>/dev/null || true
  fi
  return 0
}

cmd_check() {
  b "What is attached (read-only — nothing is written)"
  mkdir -p "$DRILL_DIR"; chmod 700 "$DRILL_DIR"
  identify || return 1
  b "Toolchain"
  local missing=0
  for t in opensc-tool sc-hsm-tool pkcs11-tool openssl python3; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t"; else err "$t MISSING"; missing=1; fi
  done
  if command -v scsh3gui >/dev/null 2>&1 || command -v scsh3 >/dev/null 2>&1; then
    ok "Smart Card Shell (scsh3)"
  else
    warn "Smart Card Shell not on PATH — it performs the import itself."
    warn "Download from openscdp.org; it is Java, so a JRE is needed too."
    missing=1
  fi
  [ "$missing" = 0 ] && ok "toolchain complete" || warn "install what is missing before --prepare"
  b "PIN retry counters (read-only; consumes no attempt)"
  sc-hsm-tool 2>/dev/null | grep -iE "tries left" | sed 's/^/   /' || warn "could not read counters (card may need initialising)"
}

cmd_prepare() {
  b "Build the THROWAWAY PKCS#12 container"
  need openssl || return 1; need python3 || return 1
  mkdir -p "$DRILL_DIR"; chmod 700 "$DRILL_DIR"
  printf '%s' "$DRILL_MNEMONIC" > "$MNF"; chmod 600 "$MNF"
  head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$PWF"; chmod 600 "$PWF"
  local out
  out="$(python3 "$HERE/seed-to-pkcs12.py" --mnemonic-file "$MNF" --password-file "$PWF" --out "$P12" 2>&1)" || {
    err "container build failed:"; printf '%s\n' "$out" | sed 's/^/     /'; return 1; }
  printf '%s\n' "$out" | sed 's/^/   /'
  printf '%s' "$out" | grep -oE 'akash1[a-z0-9]+' | head -1 > "$ADDRF"
  [ -s "$ADDRF" ] || { err "could not record the expected address"; return 1; }
  ok "container: $P12"
  ok "expected address: $(cat "$ADDRF")"
  b "Now import it — this is the step no CLI can drive"
  info "The device must hold a DKEK domain first; the SmartCard-HSM supports ONLY encrypted"
  info "import. On a scratch device:"
  show "sc-hsm-tool --create-dkek-share '$DRILL_DIR/dkek.pbe' --pwd-shares-threshold 2 --pwd-shares-total 3"
  show "sc-hsm-tool --initialize --dkek-shares 1 --label 'drill'"
  show "sc-hsm-tool --import-dkek-share '$DRILL_DIR/dkek.pbe' --pwd-shares-total 2"
  info "  (enter the prime and any 2 of the 3 shares it printed — without --pwd-shares-total it asks"
  info "   for a password instead, and the generated password is never shown)"
  info "Then, in Smart Card Shell: Key Manager -> right-click SmartCard-HSM -> Import from PKCS#12"
  info "  container : $P12"
  info "  password  : cat '$PWF'"
  info "  label     : akash-funding   (the verify step looks for this label)"
  warn "--initialize ERASES the device. Only run it on the scratch board."
  info "When the import finishes:"
  show "$0 --verify"
}

cmd_verify() {
  b "Verify the card holds the seed's key AND can sign with it"
  need pkcs11-tool || return 1; need python3 || return 1
  [ -s "$ADDRF" ] || { err "no expected address recorded — run --prepare first."; return 1; }
  # Re-identify the card HERE rather than trusting what --check saw. Devices get swapped between
  # steps, and a pass on a Pico means something different from a pass on a Nitrokey: the first
  # proves the Smart Card Shell toolchain can encode secp256k1, the second proves the NXP
  # firmware accepts it too. Reporting the wrong one would open the gate on half the evidence.
  identify >/dev/null 2>&1 || warn "could not re-identify the card at verify time"
  local expected; expected="$(cat "$ADDRF")"
  info "expected (from the seed): $expected"

  local pub="$DRILL_DIR/imported-pub.der"
  rm -f "$pub"
  if ! pkcs11-tool --read-object --type pubkey --label akash-funding -o "$pub" >/dev/null 2>&1; then
    err "could not read a public key labelled 'akash-funding' from the card."
    err "Either the import did not complete, or it used a different label."
    show "pkcs11-tool --list-objects --type pubkey"
    return 1
  fi
  [ -s "$pub" ] || { err "empty public key read from the card."; return 1; }

  local oncard
  oncard="$(python3 "$HERE/derive-akash-address.py" --der "$pub" 2>/dev/null || true)"
  if [ -z "$oncard" ]; then
    err "the card's public key did not parse as secp256k1."
    err "THIS IS THE ANSWER TO THE DRILL: the import path mangled the curve. Do not open the gate."
    return 1
  fi
  info "on card                 : $oncard"
  if [ "$oncard" != "$expected" ]; then
    err "ADDRESS MISMATCH — the card holds a DIFFERENT key than the seed derives."
    err "The import did not preserve the key. Do NOT open the gate."
    return 1
  fi
  ok "ADDRESS MATCH — the imported key is exactly the seed's key."

  info "Proving the card can SIGN with it (a read-back only proves the PUBLIC half arrived)…"
  local dig="$DRILL_DIR/d.bin" sig="$DRILL_DIR/s.bin"
  head -c 32 /dev/urandom > "$dig"
  if ! pkcs11-tool --login --sign --label akash-funding -m ECDSA -i "$dig" -o "$sig" >/dev/null 2>&1; then
    err "the card refused to sign with the imported key."
    err "The object exists but is unusable. Do NOT open the gate."
    rm -f "$dig" "$sig"; return 1
  fi
  if ! python3 "$HERE/verify-hsm-control.py" --der "$pub" --digest "$dig" --sig "$sig" >/dev/null 2>&1; then
    err "the signature did NOT verify against the card's own public key."
    err "Do NOT open the gate."
    rm -f "$dig" "$sig"; return 1
  fi
  rm -f "$dig" "$sig"
  ok "SIGN PROOF PASSED — the card controls the imported private key."

  b "DRILL PASSED"
  info "A seed-derived secp256k1 key imports into this device and signs correctly."
  local kind; kind="$(cat "$DRILL_DIR/.device-kind" 2>/dev/null || echo unknown)"
  if [ "$kind" = "test" ]; then
    warn "This was a TEST device (non-SmartCard-HSM ATR). It proves the Smart Card Shell"
    warn "toolchain can encode secp256k1 through PKCS#12 — the software half of the question."
    warn "The Nitrokey's NXP firmware is a separate implementation: repeat on a scratch"
    warn "Nitrokey before opening the gate for real custody."
  else
    info "Run on a real SmartCard-HSM, so both the toolchain and the firmware are proven."
    info "Open the gate with:  CEREMONY_ALLOW_HSM_IMPORT=1"
  fi
  info "Clean up the drill material (it is throwaway, but it is still key material):"
  show "rm -rf '$DRILL_DIR'"
}

case "${1:---check}" in
  --check)   cmd_check;;
  --prepare) cmd_prepare;;
  --verify)  cmd_verify;;
  -h|--help) sed -n '2,25p' "$0";;
  *) err "unknown argument: $1"; sed -n '2,25p' "$0"; exit 2;;
esac
