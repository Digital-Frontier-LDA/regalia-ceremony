#!/usr/bin/env bash
# route-coverage.sh — drive EVERY hardware route the ceremony can take against the live
# emulators and assert real behaviour. Run inside the emulator image (the entrypoint boots
# the emulators first):
#
#   docker run --rm ceremony-emu run-route-tests
#
# Each route is exercised with the SAME tools the real ceremony calls, but pointed at the
# emulators, so a green run means the wizard's control flow + tool invocations are sound.
set -uo pipefail
RUN="${EMU_RUN:-/run/vault-emu}"
[ -f "$RUN/env.sh" ] && . "$RUN/env.sh"
SCRIPTS="${CEREMONY_SCRIPTS:-/opt/vault-ceremony/scripts}"
EMU_BIN="${EMU_BIN:-/opt/vault-emu/bin}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# =====================================================================================
hdr "ROUTE 1 — Nitrokey HSM 2 / pkcs11 (SoftHSM2): secp256k1 keygen + pubkey + sign"
export EMU_HSM_PIN="648219"
softhsm2-util --init-token --free --label akash-funding \
  --so-pin 3537363231383830 --pin "$EMU_HSM_PIN" >/dev/null 2>&1 \
  && P "SoftHSM2 token initialised" || F "token init failed"

if pkcs11-tool --login --keypairgen --key-type EC:secp256k1 --label akash-funding --id 01 \
      >"$WORK/keygen.log" 2>&1; then
  P "secp256k1 keypair generated on the (emulated) HSM"
else
  F "keypairgen failed"; sed 's/^/      /' "$WORK/keygen.log"
fi

if pkcs11-tool --read-object --type pubkey --id 01 -o "$WORK/funding-pub.der" >/dev/null 2>&1 \
   && [ -s "$WORK/funding-pub.der" ]; then
  P "public key exported as DER"
else
  F "pubkey export failed"
fi

ADDR="$(python3 "$SCRIPTS/derive-akash-address.py" --der "$WORK/funding-pub.der" 2>/dev/null || true)"
if [ -z "$ADDR" ]; then
  # SoftHSM2/OpenSC may export the raw CKA_EC_POINT (DER OCTET STRING of 04||X||Y) rather
  # than a full SubjectPublicKeyInfo — normalise to a hex point and use the --hex path.
  POINT_HEX="$(python3 - "$WORK/funding-pub.der" <<'PY'
import sys
der = open(sys.argv[1], "rb").read()
def tlv(b, i):
    t = b[i]; l = b[i+1]; i += 2
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[i:i+n], "big"); i += n
    return t, b[i:i+l]
pt = der
try:
    t, v = tlv(der, 0)
    if t == 0x04:           # OCTET STRING wrapper around the point
        pt = v
except Exception:
    pass
if len(pt) >= 65 and pt[0] == 0x04:
    pt = pt[:65]
sys.stdout.write(pt.hex())
PY
)"
  ADDR="$(python3 "$SCRIPTS/derive-akash-address.py" --hex "$POINT_HEX" 2>/dev/null || true)"
fi
case "$ADDR" in
  akash1*) P "derived a valid akash funding address: $ADDR" ;;
  *) F "address derivation produced '$ADDR'" ;;
esac

# real ECDSA sign through the token. SoftHSM2 exposes raw CKM_ECDSA for secp256k1 (not
# CKM_ECDSA_SHA256), so hash the message to 32 bytes first, exactly like a real signer.
python3 -c "import hashlib;open('$WORK/msg.hash','wb').write(hashlib.sha256(b'ceremony-test-message').digest())"
if pkcs11-tool --sign --login --id 01 --mechanism ECDSA --input-file "$WORK/msg.hash" \
      -o "$WORK/sig.bin" >"$WORK/sign.log" 2>&1 && [ -s "$WORK/sig.bin" ]; then
  P "HSM produced a real ECDSA signature ($(wc -c <"$WORK/sig.bin") bytes)"
else
  F "ECDSA signing failed"; sed 's/^/      /' "$WORK/sign.log"
fi

# =====================================================================================
hdr "ROUTE 2 — SmartCard-HSM DKEK 4-of-6 (sc-hsm-tool model): OpenSC password shares + wrap round-trip"
export EMU_SCHSM_STATE="$WORK/schsm"
sc-hsm-tool --create-dkek-share "$WORK/dkek.pbe" --pwd-shares-threshold 4 --pwd-shares-total 6 \
  > "$WORK/dkek-shares.txt" 2>&1
[ "$(grep -cE '^Share ID +: [0-9]+$' "$WORK/dkek-shares.txt")" = 6 ] && [ -s "$WORK/dkek.pbe" ] \
  && P "DKEK share created + password split into 6 shares" || F "create-dkek-share failed"

# The threshold, proven through the import a recovery uses (#464) and fed by the ceremony's own
# feed_dkek_shares: 3 shares are refused, a missing --pwd-shares-total is refused, 4 activate.
feeds="$(grep -c '^feed_dkek_shares() {$' "$SCRIPTS/ceremony.sh")"
if [ "$feeds" = 1 ]; then
  eval "$(sed -n '/^feed_dkek_shares() {$/,/^}$/p' "$SCRIPTS/ceremony.sh")"
else
  F "expected one feed_dkek_shares definition in ceremony.sh, found $feeds"
fi
feed_dkek_shares "$WORK/dkek-shares.txt" 1 7 >/dev/null 2>&1 \
  && F "feed_dkek_shares fed a share the capture does not contain" \
  || P "feed_dkek_shares refuses a share the capture does not contain"
grep -v '^Prime' "$WORK/dkek-shares.txt" > "$WORK/dkek-shares-noprime.txt"
[ -z "$(feed_dkek_shares "$WORK/dkek-shares-noprime.txt" 1 2 3 4 2>/dev/null)" ] \
  && P "feed_dkek_shares feeds nothing from a capture with no prime" \
  || F "feed_dkek_shares fed shares with no prime"
rm -f "$WORK/dkek-shares-noprime.txt"
sc-hsm-tool --initialize --dkek-shares 1 --label akash-funding >/dev/null 2>&1 \
  && P "card initialised (DKEK shares required = 1)" || F "initialize failed"
out="$(feed_dkek_shares "$WORK/dkek-shares.txt" 1 3 4 | sc-hsm-tool --import-dkek-share "$WORK/dkek.pbe" --pwd-shares-total 3 2>&1)" \
  && F "3 of 6 shares imported the DKEK share (threshold broken)" \
  || { grep -q "Error decrypting DKEK share" <<< "$out" \
         && P "3 shares do NOT open the DKEK share (threshold holds)" \
         || F "3-share import failed for the wrong reason: $(tail -1 <<< "$out")"; }
out="$(feed_dkek_shares "$WORK/dkek-shares.txt" 1 3 4 6 | sc-hsm-tool --import-dkek-share "$WORK/dkek.pbe" 2>&1)" \
  && F "a share import without --pwd-shares-total succeeded" \
  || { grep -q "Error decrypting DKEK share" <<< "$out" \
         && P "without --pwd-shares-total the import asks for a password and fails" \
         || F "flagless import failed for the wrong reason: $(tail -1 <<< "$out")"; }
grep -q "active" <<< "$(feed_dkek_shares "$WORK/dkek-shares.txt" 1 3 4 6 | sc-hsm-tool --import-dkek-share "$WORK/dkek.pbe" --pwd-shares-total 4 2>&1)" \
  && P "4 of 6 shares import and activate the DKEK" || F "import-dkek-share did not activate DKEK"
sc-hsm-tool --wrap-key "$WORK/wrapped.bin" --key-reference 1 >/dev/null 2>&1 \
  && [ -s "$WORK/wrapped.bin" ] && P "private key wrapped under the DKEK" || F "wrap-key failed"
grep -q "KEYREF-1" <<< "$(sc-hsm-tool --unwrap-key "$WORK/wrapped.bin" --key-reference 1 2>&1)" \
  && P "wrap/unwrap round-trips (disaster-recovery drill works)" || F "unwrap-key mismatch"

# =====================================================================================
hdr "ROUTE 3 — YubiKey 'ops' age identity (software-backed): real encrypt/decrypt round-trip"
export EMU_AGE_IDENTITY_DIR="$WORK/age"
RECIP="$(age-plugin-yubikey --generate 2>/dev/null | tail -1)"
case "$RECIP" in
  age1*) P "minted an age 'ops' recipient: ${RECIP:0:24}…" ;;
  *) F "no age recipient produced (got '$RECIP')" ;;
esac
printf 'breakglass-secret-XYZ' > "$WORK/plain.txt"
if age -r "$RECIP" -o "$WORK/cipher.age" "$WORK/plain.txt" 2>/dev/null \
   && grep -q "breakglass-secret-XYZ" <<< "$(age -d -i "$EMU_AGE_IDENTITY_DIR/ops-identity.txt" "$WORK/cipher.age" 2>/dev/null)"; then
  P "encrypt to the recipient + decrypt with the identity round-trips (touch simulated)"
else
  F "age round-trip failed"
fi
# ykman management surface (presence + PIV touch policy)
if grep -qi "touch policy: ALWAYS" <<< "$(ykman piv info 2>/dev/null)"; then
  P "ykman reports the PIV slot with touch-policy ALWAYS (management route)"
else
  F "ykman PIV info route failed"
fi

# =====================================================================================
hdr "ROUTE 4 — SLE-4442 memory card over real PC/SC (pcscd + vpcd + vpicc)"
if grep -qiE 'virtual|vpcd|reader' <<< "$(opensc-tool -l 2>/dev/null)"; then
  P "PC/SC stack reachable (virtual reader present)"
else
  F "no PC/SC virtual reader visible"; opensc-tool -l 2>&1 | sed 's/^/      /'
fi
if sle4442-manager info >"$WORK/sle.log" 2>&1; then
  P "card visible via PC/SC: $(grep -m1 'error counter' "$WORK/sle.log" | sed 's/^ *//')"
else
  F "sle4442-manager info failed"; sed 's/^/      /' "$WORK/sle.log"
fi
# store a Shamir share on the card and verify-read it back
if sle4442-manager store --psc FFFFFF --addr 32 --text "slip39-share-04-of-06" >/dev/null 2>&1; then
  P "stored a Shamir share on the SLE-4442 (write+verify-read)"
else
  F "store on SLE-4442 failed"
fi
RB="$(sle4442-manager read --addr 32 --len 21 2>/dev/null | xxd -r -p 2>/dev/null || true)"
[ "$RB" = "slip39-share-04-of-06" ] && P "independent read-back matches the stored share" || F "read-back mismatch ('$RB')"
# wrong PSC must be rejected (security memory works)
if sle4442-manager verify --psc 000000 >/dev/null 2>&1; then
  F "wrong PSC was accepted!"
else
  P "wrong PSC rejected (error counter enforced)"
fi

# =====================================================================================
hdr "ROUTE 5 — printing (CUPS + cups-pdf): real PDF produced"
echo "ceremony share page — QR + words" > "$WORK/page.txt"
if lp -d "${EMU_PRINTER:-vault-pdf}" "$WORK/page.txt" >/dev/null 2>&1; then
  P "lp accepted the job on queue ${EMU_PRINTER:-vault-pdf}"
else
  F "lp print failed"
fi
# Wait for cups-pdf to drop the PDF. The FIRST job after a cold cupsd compiles filters and can
# take >10s, so wait up to 30s. Only accept a file that is a VALID PDF (starts with %PDF) —
# breaking on mere existence races cups-pdf mid-write and the header check then reads a partial
# file. The per-run outdir is fresh, so any valid PDF in it is ours.
pdf=""
for _ in $(seq 1 60); do
  cand="$(find "${EMU_PDF_OUTDIR:-/var/spool/cups-pdf}" -name '*.pdf' 2>/dev/null | head -1)"
  if grep -q "%PDF" <<< "$([ -n "$cand" ] && head -c4 "$cand" 2>/dev/null)"; then pdf="$cand"; break; fi
  sleep 0.5
done
if [ -n "$pdf" ]; then
  P "cups-pdf produced a real PDF: $pdf ($(wc -c <"$pdf") bytes)"
else
  F "no PDF produced (cups-pdf)"; ls -la "${EMU_PDF_OUTDIR:-/var/spool/cups-pdf}" 2>/dev/null | sed 's/^/      /'
fi

# =====================================================================================
hdr "ROUTE 6 — M-DISC archive: burn on drive A, cross-drive verify on drive B"
export EMU_OPTICAL_DIR="$WORK/optical"
burn_src="$WORK/burn"; mkdir -p "$burn_src"
echo "recovery-kit" > "$burn_src/RECOVERY-START-HERE.txt"
echo "share data"   > "$burn_src/share1.txt"
( cd "$burn_src" && find . -type f ! -name manifest.sha256 -print0 | xargs -0 sha256sum > manifest.sha256 )
growisofs -Z /dev/sr0 -R -J "$burn_src" >/dev/null 2>&1 \
  && P "burned the kit to emulated drive A (/dev/sr0)" || F "growisofs burn failed"
if optical-verify --image "$EMU_OPTICAL_DIR/sr0.iso" --manifest manifest.sha256 >/dev/null 2>&1; then
  P "cross-drive verify PASSES on a good burn"
else
  F "cross-drive verify failed on a good burn"
fi
if optical-verify --image "$EMU_OPTICAL_DIR/sr0.iso" --manifest manifest.sha256 --fault >/dev/null 2>&1; then
  F "fault-injected burn was NOT caught (verify too weak)"
else
  P "fault-injected (marginal) burn is correctly REJECTED"
fi

# =====================================================================================
hdr "COVERAGE MATRIX — every ceremony hardware route has an emulator"
declare -A NEED=(
  [pkcs11-tool]="HSM keygen/sign/pubkey (SoftHSM2)"
  [sc-hsm-tool]="DKEK 4-of-6 + wrap (model)"
  [age-plugin-yubikey]="YubiKey ops identity (age)"
  [ykman]="YubiKey management/PIV info"
  [sle4442-manager]="SLE-4442 memory card (PC/SC)"
  [lp]="printing (cups-pdf)"
  [growisofs]="M-DISC burn (xorriso)"
)
for tool in "${!NEED[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    P "emulator wired for: $tool — ${NEED[$tool]}"
  else
    F "NO emulator for: $tool — ${NEED[$tool]}"
  fi
done

# =====================================================================================
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && { echo "  ALL HARDWARE ROUTES EMULATED + EXERCISED"; exit 0; } || { echo "  SOME ROUTES FAILED"; exit 1; }
