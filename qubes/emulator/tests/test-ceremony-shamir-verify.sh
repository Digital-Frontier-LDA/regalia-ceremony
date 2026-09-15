#!/usr/bin/env bash
# test-ceremony-shamir-verify.sh — adversarial tests for the ceremony's ssss (option a)
# REQUIREMENTS B5 — threshold recovery: below-threshold must fail, at-threshold must succeed.
# share-splitting path: it MUST reconstruct-verify before distributing, MUST abort if the
# split doesn't rebuild the secret, and MUST refuse multi-line / oversized secrets that
# ssss would silently truncate. Runs natively (ssss + bash); qrencode/lp are stubbed.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

command -v ssss-split >/dev/null 2>&1 || { echo "ssss not installed — skipping"; exit 0; }
REAL_SSSS_SPLIT="$(command -v ssss-split)"   # capture before we shadow PATH

# stub the print path so no qrencode/printer is needed
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
printf '#!/usr/bin/env bash\n[ "$1" = "-o" ] && : > "$2"; exit 0\n' > "$FAKE/qrencode"; chmod +x "$FAKE/qrencode"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE/lp"; chmod +x "$FAKE/lp"
trap 'rm -rf "$FAKE" "${WORK:-}"' EXIT

# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
ask(){ return 0; }; pause(){ :; }
PRINTER=""                      # print_share will only write files (which our stubs no-op)
init_work

# =====================================================================================
hdr "happy path: split is reconstruct-VERIFIED before printing"
printf 'AGE-SECRET-KEY-1EXAMPLE0test0only0do0not0use' > "$WORK/secret.in"
out="$(printf 'a\n' | step_shamir 2>&1)"
grep -qi "reconstruct-verify OK" <<< "$out" && P "wizard reconstruct-verified the split" || F "no reconstruct-verify on the happy path"
[ "$(grep -c . "$WORK/shares.txt" 2>/dev/null)" = 6 ] && P "6 shares produced" || F "expected 6 shares"

# =====================================================================================
hdr "adversarial: a split that does NOT rebuild the secret must ABORT (no distribution)"
rm -f "$WORK/shares.txt"
printf 'the-real-secret-A' > "$WORK/secret.in"
# stub ssss-split so it splits a DIFFERENT secret than secret.in -> the wizard's
# reconstruct-verify (which combines and compares to secret.in) must catch the mismatch.
cat > "$FAKE/ssss-split" <<S
#!/usr/bin/env bash
printf 'a-totally-different-secret' | "$REAL_SSSS_SPLIT" "\$@"
S
chmod +x "$FAKE/ssss-split"
out="$(printf 'a\n' | step_shamir 2>&1)"
if grep -qi "RECONSTRUCT-VERIFY FAILED" <<< "$out"; then P "aborts when 4 shares don't rebuild the secret"; else F "did NOT abort on a bad split"; fi
[ ! -f "$WORK/shares.txt" ] && P "bad shares.txt was removed (nothing to distribute)" || F "bad shares left on disk"
rm -f "$FAKE/ssss-split"   # restore real ssss-split (back on PATH)

# =====================================================================================
hdr "guard: a MULTI-LINE secret is refused (ssss would truncate it)"
printf 'line-one\nline-two\n' > "$WORK/secret.in"; rm -f "$WORK/shares.txt"
out="$(printf 'a\n' | step_shamir 2>&1)"
grep -qi "multi-line" <<< "$out" && [ ! -f "$WORK/shares.txt" ] && P "multi-line secret refused, no shares created" || F "multi-line secret was not refused"

# =====================================================================================
hdr "guard: an OVERSIZED (>128B) secret is refused"
head -c 200 /dev/zero | tr '\0' 'x' > "$WORK/secret.in"; rm -f "$WORK/shares.txt"
out="$(printf 'a\n' | step_shamir 2>&1)"
grep -qiE "128|ssss handles" <<< "$out" && [ ! -f "$WORK/shares.txt" ] && P "oversized secret refused" || F "oversized secret was not refused"

# =====================================================================================
hdr "option b (SLIP-39 mint): verified, and the master secret never lands in the shares file"
if python3 -c "import shamir_mnemonic" 2>/dev/null; then
  rm -f "$WORK/slip39.txt" "$WORK"/w*
  out="$(printf 'b\n' | step_shamir 2>&1)"
  grep -qi "reconstruct-verified" <<< "$out" && P "mint path reconstruct-verifies before distributing" || F "no reconstruct-verify on mint"
  n=$(grep -cE '^[a-z]+( [a-z]+){15,}$' "$WORK/slip39.txt" 2>/dev/null)
  [ "$n" = 6 ] && P "6 SLIP-39 shares minted" || F "expected 6 shares, got $n"
  # the file must NOT contain the `shamir create` leak signature (hex secret after the words)
  grep -qiE "master secret[ :=]+[0-9a-f]{16,}|using master secret" "$WORK/slip39.txt" \
    && F "master secret LEAKED into the shares file!" \
    || P "no master secret value in the shares file"
else
  P "shamir_mnemonic not installed — option b mint check skipped"
fi

hdr "option c (BIP39 -> SLIP-39): the funding ADDRESS is derived + shown to record as the recovery anchor"
if python3 -c "import shamir_mnemonic, mnemonic" 2>/dev/null; then
  rm -f "$WORK/slip39.txt" "$WORK"/w*
  # a known 12-word BIP39 test mnemonic (all-'abandon…about'); its akash address is deterministic.
  printf 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' > "$WORK/secret.in"
  want_addr="$(python3 "$SCRIPTS/derive-akash-address.py" --mnemonic-file "$WORK/secret.in" 2>/dev/null)"
  out="$(printf 'c\n' | step_shamir 2>&1)"
  n=$(grep -cE '^[a-z]+( [a-z]+){15,}$' "$WORK/slip39.txt" 2>/dev/null)
  [ "$n" = 6 ] && P "6 SLIP-39 word-shares produced from the BIP39 mnemonic" || F "expected 6 shares, got $n"
  # THE FIX UNDER TEST: without the recorded funding address, RECOVERY-TECHNICAL.md Step 4 /
  # recovery-card step 6 ("recovered addr == funding addr on sealed sheet, else STOP") has no
  # anchor. The wizard MUST derive + display the funding address and tell the operator to record it.
  grep -qF "$want_addr" <<< "$out" && P "funding address ($want_addr) is displayed" || F "funding address NOT displayed — recovery has no anchor to compare against"
  grep -qiE "record.*(sealed|custodian|seal registry)" <<< "$out" && P "operator told to record the address on the sealed sheet / registry" || F "no instruction to record the funding address"
  # the mnemonic itself must NEVER be printed
  grep -qF "abandon abandon abandon" <<< "$out" && F "BIP39 mnemonic LEAKED to the terminal!" || P "mnemonic not leaked to the terminal"
else
  P "shamir_mnemonic/mnemonic not installed — option c address-anchor check skipped"
fi

hdr "option c under an AMBIENT SLIP39_PASSPHRASE: shares must still recover with the EMPTY default"
# QUORUM-CONFIRMED defect: if SLIP39_PASSPHRASE is set in the operator's shell (dry-run leftover
# or vault-qube profile), option c silently minted the funding-seed SLIP-39 shares BOUND to it,
# while the recovery anchor (line 431) is derived from the raw mnemonic with NO passphrase. At
# disaster recovery in a clean shell the shares combine with the EMPTY passphrase -> different
# seed -> address != anchor -> the sole Option-B recovery path is permanently unrecoverable.
# The ceremony MUST neutralize the ambient passphrase so a set-once custodial backup is
# deterministic: shares minted here must recover with the empty default.
if python3 -c "import shamir_mnemonic, mnemonic" 2>/dev/null; then
  rm -f "$WORK/slip39.txt" "$WORK"/w* "$WORK/collected" "$WORK/recovered.mnemonic"
  printf 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' > "$WORK/secret.in"
  anchor_addr="$(env -u SLIP39_PASSPHRASE python3 "$SCRIPTS/derive-akash-address.py" --mnemonic-file "$WORK/secret.in" 2>/dev/null)"
  # simulate the ambient leak: an unrecorded SLIP-39 passphrase in the operator's env
  export SLIP39_PASSPHRASE="dry-run-leftover-do-not-use"
  out="$(printf 'c\n' | step_shamir 2>&1)"
  # collect any 4 of the minted word-shares (as a recoverer would) and recover in a CLEAN shell
  grep -E '^[a-z]+( [a-z]+){15,}$' "$WORK/slip39.txt" 2>/dev/null | head -4 > "$WORK/collected"
  env -u SLIP39_PASSPHRASE python3 "$SCRIPTS/bip39-slip39-backup.py" --recover --in "$WORK/collected" --out "$WORK/recovered.mnemonic" 2>/dev/null
  rec_addr="$(env -u SLIP39_PASSPHRASE python3 "$SCRIPTS/derive-akash-address.py" --mnemonic-file "$WORK/recovered.mnemonic" 2>/dev/null)"
  unset SLIP39_PASSPHRASE
  if [ -n "$anchor_addr" ] && [ "$rec_addr" = "$anchor_addr" ]; then
    P "shares minted under an ambient passphrase still recover to the funding anchor in a clean shell"
  else
    F "ambient SLIP39_PASSPHRASE bound the shares (recovered $rec_addr != anchor $anchor_addr) — DR would STOP, funds unrecoverable"
  fi
else
  P "shamir_mnemonic/mnemonic not installed — ambient-passphrase determinism check skipped"
fi

hdr "option c under an AMBIENT BIP39_PASSPHRASE: the recorded funding anchor must be the EMPTY-passphrase address"
# QUORUM-CONFIRMED defect: step_shamir neutralizes an ambient SLIP39_PASSPHRASE but NOT the
# symmetric BIP39_PASSPHRASE (25th-word) env var. bip39-slip39-backup.py splits the raw
# mnemonic (m.to_entropy ignores BIP39 passphrases), so the shares back up the TRUE seed. But
# the recovery anchor at line 443 runs derive-akash-address.py, which reads BIP39_PASSPHRASE
# with highest priority and applies it silently -> the anchor recorded on the sealed sheet is
# the seed+passphrase address, NOT the real empty-passphrase funding wallet. At clean-shell
# disaster recovery the correct shares rebuild the correct seed and derive the TRUE address,
# which != the wrongly-recorded anchor -> the operator STOPs and distrusts a perfectly good
# backup, stranding a set-once custodial seed. step_shamir MUST unset BIP39_PASSPHRASE so the
# anchor it displays/records equals the empty-passphrase address the shares actually recover to.
if python3 -c "import shamir_mnemonic, mnemonic" 2>/dev/null; then
  rm -f "$WORK/slip39.txt" "$WORK"/w* "$WORK/collected" "$WORK/recovered.mnemonic"
  printf 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' > "$WORK/secret.in"
  # the TRUE funding anchor: derived with NO BIP39 passphrase (what the shares recover to in a clean shell)
  true_anchor="$(env -u BIP39_PASSPHRASE python3 "$SCRIPTS/derive-akash-address.py" --mnemonic-file "$WORK/secret.in" 2>/dev/null)"
  # simulate the ambient leak: a stray 25th-word passphrase in the operator's env
  export BIP39_PASSPHRASE="dry-run-leftover-do-not-use"
  out="$(printf 'c\n' | step_shamir 2>&1)"
  unset BIP39_PASSPHRASE
  if [ -n "$true_anchor" ] && grep -qF "$true_anchor" <<< "$out"; then
    P "anchor displayed under an ambient BIP39_PASSPHRASE is the TRUE empty-passphrase funding address"
  else
    F "ambient BIP39_PASSPHRASE altered the recorded anchor (expected $true_anchor) — DR would STOP on a good backup"
  fi
else
  P "shamir_mnemonic/mnemonic not installed — ambient BIP39 passphrase anchor check skipped"
fi

hdr "step 6 recovery card under the HSM funding path: DKEK-unwrap restore, not phantom funding shares"
# QUORUM-CONFIRMED defect: step_recovery_card always called make-recovery-card.py WITHOUT
# --hsm-funding. When the OPTIONAL Nitrokey-HSM funding-signer path (step_hsm_funding) was
# performed, the funding key is born-in-HSM and backed up ONLY as the DKEK-wrapped blob
# ($WORK/funding-wrapped.bin) + dkek.pbe — there are NO SLIP-39 funding shares. Yet the printed
# break-glass card told the recoverer to rebuild the funding seed from a nonexistent
# funding-shares.txt and never mentioned the DKEK-import / sc-hsm-tool --unwrap-key restore the
# HSM path actually requires. step_recovery_card MUST detect the HSM artifact and pass
# --hsm-funding so the card carries the correct DKEK-restore procedure.
card_ps="$WORK/recovery-card.ps"
printf 'wrapped-blob' > "$WORK/funding-wrapped.bin"   # simulate: HSM funding path was performed
rm -f "$card_ps"
printf 'DF-BG-01\nHOLO-123\n' | step_recovery_card >/dev/null 2>&1
if [ -s "$card_ps" ] && grep -q "unwrap-key" "$card_ps"; then
  P "HSM-path card carries the sc-hsm-tool --unwrap-key / DKEK-restore procedure"
else
  F "HSM-path card OMITS the DKEK-unwrap restore (recoverer sent to nonexistent funding shares)"
fi

hdr "step 6 recovery card under the default (no-HSM) path: no phantom HSM restore block"
rm -f "$WORK/funding-wrapped.bin" "$card_ps"
printf 'DF-BG-01\nHOLO-123\nseed\n' | step_recovery_card >/dev/null 2>&1
if [ -s "$card_ps" ] && ! grep -q "unwrap-key" "$card_ps"; then
  P "default card omits the HSM block (funding recovered from its SLIP-39 shares)"
else
  F "default card wrongly includes the HSM restore block"
fi

hdr "step 6 recovery card in a SEPARATE session (HSM artifact already shredded): operator's answer drives the card"
# QUORUM-CONFIRMED defect: step_recovery_card inferred the funding model SOLELY from the
# transient $WORK/funding-wrapped.bin, which cleanup() shreds on exit. Printing the card in a
# LATER session than step_hsm_funding (or after a crash) leaves that file absent, so the card
# silently defaulted to the SEED-recovery procedure — sending a born-in-HSM recoverer to
# nonexistent SLIP-39 funding shares instead of the DKEK/sc-hsm-tool --unwrap-key restore,
# stranding real custodial funds. The wizard MUST let the operator declare the funding model
# explicitly and honour it even when no session artifact is present.
rm -f "$WORK/funding-wrapped.bin" "$card_ps"   # simulate: born-in-HSM step ran + was shredded in a PRIOR session
printf 'DF-BG-01\nHOLO-123\nhsm\n' | step_recovery_card >/dev/null 2>&1
if [ -s "$card_ps" ] && grep -q "unwrap-key" "$card_ps"; then
  P "operator-declared HSM model yields the DKEK-unwrap card even with the artifact shredded"
else
  F "separate-session HSM card fell back to phantom SLIP-39 funding shares (artifact-only inference)"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
